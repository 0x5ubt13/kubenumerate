#!/usr/bin/env python3
"""
Tests for OpenShift mode (--openshift): SCC admission of pods, SCC definitions, Routes, the oc CLI lookup and the
Kubernetes version parsed from `oc version`.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kubenumerate import Kubenumerate  # noqa: E402


def make_pod(scc=None, name="app-pod", namespace="team-a"):
    metadata = {"name": name, "namespace": namespace}
    if scc is not None:
        metadata["annotations"] = {"openshift.io/scc": scc}
    return {"kind": "Pod", "apiVersion": "v1", "metadata": metadata, "spec": {"containers": []}}


def make_scc(name, groups=(), users=(), **flags):
    item = {
        "kind": "SecurityContextConstraints",
        "apiVersion": "security.openshift.io/v1",
        "metadata": {"name": name},
        "groups": list(groups),
        "users": list(users),
        "runAsUser": {"type": "MustRunAsRange"},
    }
    item.update(flags)
    return item


def make_route(name="web", tls=None):
    spec = {"host": f"{name}.apps.example.com", "to": {"kind": "Service", "name": name}}
    if tls is not None:
        spec["tls"] = tls
    return {
        "kind": "Route",
        "apiVersion": "route.openshift.io/v1",
        "metadata": {"name": name, "namespace": "team-a"},
        "spec": spec,
    }


def audit_names(items, openshift, tmp_path):
    """Write items as a kubectl dump and return the AuditResultName values the parser produces for them."""
    out_dir = tmp_path / "kubectl_output"
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / "all.json", "w") as f:
        json.dump({"items": items}, f)
    kube = Kubenumerate(dry_run=False, kubectl_output_path=str(out_dir), verbosity=0, openshift=openshift)
    return list(kube.generate_kubeaudit_equivalent_df_from_kubectl()["AuditResultName"])


def test_pod_admitted_under_privileged_scc_is_flagged(tmp_path):
    assert "OpenShiftPodPermissiveSCC" in audit_names([make_pod(scc="privileged")], True, tmp_path)


def test_pod_admitted_under_restricted_v2_is_not_flagged(tmp_path):
    assert "OpenShiftPodPermissiveSCC" not in audit_names([make_pod(scc="restricted-v2")], True, tmp_path)


def test_openshift_checks_are_gated_by_the_flag(tmp_path):
    # Same input, plain Kubernetes mode: the SCC annotation means nothing to a non-OpenShift audit
    assert audit_names([make_pod(scc="privileged")], False, tmp_path) == []


def test_privileged_scc_granted_to_all_authenticated_users_is_flagged():
    names = [
        f["AuditResultName"]
        for f in Kubenumerate.openshift_findings(
            make_scc("rogue", groups=["system:authenticated"], allowPrivilegedContainer=True)
        )
    ]
    assert "OpenShiftSCCAllowsPrivileged" in names
    assert "OpenShiftSCCGrantedBroadly" in names


def test_restricted_scc_granted_to_all_authenticated_users_is_not_flagged():
    # restricted-v2 is granted to system:authenticated by default; that is expected, not a finding
    assert Kubenumerate.openshift_findings(make_scc("restricted-v2", groups=["system:authenticated"])) == []


def test_route_without_tls_is_flagged():
    names = [f["AuditResultName"] for f in Kubenumerate.openshift_findings(make_route(tls=None))]
    assert names == ["OpenShiftRouteWithoutTLS"]


def test_edge_route_redirecting_http_to_https_is_not_flagged():
    route = make_route(tls={"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"})
    assert Kubenumerate.openshift_findings(route) == []


def test_edge_route_allowing_plain_http_is_flagged():
    route = make_route(tls={"termination": "edge", "insecureEdgeTerminationPolicy": "Allow"})
    names = [f["AuditResultName"] for f in Kubenumerate.openshift_findings(route)]
    assert names == ["OpenShiftRouteAllowsInsecure"]


@pytest.mark.parametrize(
    "output, openshift, expected",
    [
        (
            b"Client Version: 4.16.0\nServer Version: 4.16.3\nKubernetes Version: v1.29.6+abc\n",
            True,
            "1.29.6",
        ),
        (b"Client Version: v1.36.0\nServer Version: v1.36.2\n", False, "1.36.2"),
    ],
)
def test_extract_version_reads_kubernetes_version_on_openshift(output, openshift, expected):
    # On OpenShift "Server Version" is the OCP release (4.x); the comparison needs the Kubernetes version
    assert Kubenumerate.extract_version(output, openshift=openshift) == expected


def test_missing_oc_exits_when_a_live_cluster_is_needed(monkeypatch):
    monkeypatch.setattr("kubenumerate.shutil.which", lambda name: None)
    kube = Kubenumerate(openshift=True)
    kube.args = type("Args", (), {"dry_run": False, "files": None})()
    with pytest.raises(SystemExit) as exc:
        kube.find_oc_bin()
    assert exc.value.code == 2


def test_missing_oc_is_tolerated_for_offline_runs(monkeypatch):
    monkeypatch.setattr("kubenumerate.shutil.which", lambda name: None)
    kube = Kubenumerate(openshift=True)
    kube.args = type("Args", (), {"dry_run": True, "files": None})()
    assert kube.find_oc_bin() == "oc"


@pytest.mark.parametrize(
    "scc", ["privileged", "anyuid", "hostnetwork", "hostnetwork-v2", "hostaccess", "hostmount-anyuid", "node-exporter"]
)
def test_every_permissive_scc_is_flagged(tmp_path, scc):
    assert "OpenShiftPodPermissiveSCC" in audit_names([make_pod(scc=scc)], True, tmp_path)


def test_pod_without_scc_annotation_is_not_flagged(tmp_path):
    assert "OpenShiftPodPermissiveSCC" not in audit_names([make_pod(scc=None)], True, tmp_path)


def test_version_check_skips_cleanly_when_oc_reports_no_kubernetes_version(capsys):
    # Older oc output with no "Kubernetes Version" line must not crash the comparison with a None/"None" version
    version = Kubenumerate.extract_version(b"Client Version: 4.16.0\nServer Version: 4.16.3\n", openshift=True)
    assert version is None
    kube = Kubenumerate(cluster_version=version, verbosity=0)
    kube.kubernetes_version_check()
    assert "could not fetch" in capsys.readouterr().out
