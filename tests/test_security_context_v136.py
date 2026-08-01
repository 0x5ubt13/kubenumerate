#!/usr/bin/env python3
"""
Tests for the Kubernetes v1.36 security context checks: procMount (KEP-4265)
and user namespaces / hostUsers (KEP-127), both of which went GA in v1.36.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kubenumerate import Kubenumerate  # noqa: E402
from summary_table import ISSUE_NAME_MAP, aggregate_issues_by_workload  # noqa: E402


def make_pod(containers, pod_spec_extra=None, name="test-pod", namespace="default"):
    """Build a minimal kubectl-style Pod list item."""
    spec = {"containers": containers}
    if pod_spec_extra:
        spec.update(pod_spec_extra)
    return {
        "kind": "Pod",
        "apiVersion": "v1",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


def make_deployment(containers, pod_spec_extra=None, name="test-deploy", namespace="default"):
    """Build a minimal kubectl-style Deployment list item (summary table ignores bare Pods)."""
    pod_spec = {"containers": containers}
    if pod_spec_extra:
        pod_spec.update(pod_spec_extra)
    return {
        "kind": "Deployment",
        "apiVersion": "apps/v1",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"template": {"spec": pod_spec}},
    }


def run_audit(tmp_path, items, cluster_version="1.36.0"):
    """Write items to a kubectl output dir and run the audit parser over them."""
    out_dir = tmp_path / "kubectl"
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / "pods.json", "w") as f:
        json.dump({"items": items}, f)
    kube = Kubenumerate(
        cluster_version=cluster_version,
        dry_run=False,
        kubectl_output_path=str(out_dir),
        verbosity=0,
    )
    return kube.generate_kubeaudit_equivalent_df_from_kubectl()


def names(df):
    return list(df["AuditResultName"])


class TestClusterAtLeast:
    """Version gate used to suppress v1.36-only recommendations on older clusters."""

    def test_returns_true_when_cluster_matches_minimum(self):
        assert Kubenumerate(cluster_version="1.36.0").cluster_at_least("1.36.0") is True

    def test_returns_true_when_cluster_is_newer(self):
        assert Kubenumerate(cluster_version="1.37.2").cluster_at_least("1.36.0") is True

    def test_returns_false_when_cluster_is_older(self):
        assert Kubenumerate(cluster_version="1.34.1").cluster_at_least("1.36.0") is False

    def test_returns_false_when_cluster_version_unknown(self):
        assert Kubenumerate(cluster_version=None).cluster_at_least("1.36.0") is False

    def test_returns_false_when_cluster_version_unparseable(self):
        assert Kubenumerate(cluster_version="not-a-version").cluster_at_least("1.36.0") is False


class TestProcMount:
    """procMount: Unmasked is dangerous on any cluster that accepted the field."""

    def test_unmasked_proc_mount_is_flagged(self, tmp_path):
        df = run_audit(
            tmp_path,
            [make_pod([{"name": "app", "securityContext": {"procMount": "Unmasked"}}])],
        )
        assert "ProcMountUnmasked" in names(df)

    def test_default_proc_mount_is_not_flagged(self, tmp_path):
        df = run_audit(
            tmp_path,
            [make_pod([{"name": "app", "securityContext": {"procMount": "Default"}}])],
        )
        assert "ProcMountUnmasked" not in names(df)

    def test_absent_proc_mount_is_not_flagged(self, tmp_path):
        df = run_audit(tmp_path, [make_pod([{"name": "app", "securityContext": {}}])])
        assert "ProcMountUnmasked" not in names(df)

    def test_unmasked_without_user_namespace_raises_anomaly(self, tmp_path):
        """procMount: Unmasked requires hostUsers: false; seeing it without one is an admission anomaly."""
        df = run_audit(
            tmp_path,
            [make_pod([{"name": "app", "securityContext": {"procMount": "Unmasked"}}])],
        )
        assert "ProcMountUnmaskedWithoutUserNamespace" in names(df)

    def test_unmasked_with_user_namespace_raises_no_anomaly(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                make_pod(
                    [{"name": "app", "securityContext": {"procMount": "Unmasked"}}],
                    pod_spec_extra={"hostUsers": False},
                )
            ],
        )
        result = names(df)
        assert "ProcMountUnmasked" in result
        assert "ProcMountUnmaskedWithoutUserNamespace" not in result

    def test_unmasked_is_flagged_even_on_older_clusters(self, tmp_path):
        """The version gate must not suppress a genuinely dangerous live setting."""
        df = run_audit(
            tmp_path,
            [make_pod([{"name": "app", "securityContext": {"procMount": "Unmasked"}}])],
            cluster_version="1.30.0",
        )
        assert "ProcMountUnmasked" in names(df)


class TestUserNamespaceRecommendation:
    """hostUsers: false is a mitigation, so its absence is only actionable from v1.36."""

    def test_flagged_when_host_users_absent_on_136(self, tmp_path):
        df = run_audit(tmp_path, [make_pod([{"name": "app"}])], cluster_version="1.36.0")
        assert "UserNamespaceNotEnabled" in names(df)

    def test_flagged_when_host_users_explicitly_true_on_136(self, tmp_path):
        df = run_audit(
            tmp_path,
            [make_pod([{"name": "app"}], pod_spec_extra={"hostUsers": True})],
            cluster_version="1.36.0",
        )
        assert "UserNamespaceNotEnabled" in names(df)

    def test_not_flagged_when_user_namespace_enabled(self, tmp_path):
        df = run_audit(
            tmp_path,
            [make_pod([{"name": "app"}], pod_spec_extra={"hostUsers": False})],
            cluster_version="1.36.0",
        )
        assert "UserNamespaceNotEnabled" not in names(df)

    def test_not_flagged_on_pre_136_cluster(self, tmp_path):
        """Gated: userns was not GA before 1.36, so recommending it would be a false positive."""
        df = run_audit(tmp_path, [make_pod([{"name": "app"}])], cluster_version="1.34.1")
        assert "UserNamespaceNotEnabled" not in names(df)

    def test_not_flagged_when_cluster_version_unknown(self, tmp_path):
        df = run_audit(tmp_path, [make_pod([{"name": "app"}])], cluster_version=None)
        assert "UserNamespaceNotEnabled" not in names(df)

    def test_raised_once_per_pod_not_per_container(self, tmp_path):
        df = run_audit(
            tmp_path,
            [make_pod([{"name": "a"}, {"name": "b"}, {"name": "c"}])],
            cluster_version="1.36.0",
        )
        assert names(df).count("UserNamespaceNotEnabled") == 1


class TestUserNamespacedColumn:
    """Root-class findings must record whether a user namespace mitigates them."""

    def test_root_container_marked_user_namespaced(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                make_pod(
                    [{"name": "app", "securityContext": {"runAsUser": 0}}],
                    pod_spec_extra={"hostUsers": False},
                )
            ],
        )
        row = df[df["AuditResultName"] == "RunAsUserCSCRoot"].iloc[0]
        assert bool(row["UserNamespaced"]) is True

    def test_root_container_not_marked_without_user_namespace(self, tmp_path):
        df = run_audit(tmp_path, [make_pod([{"name": "app", "securityContext": {"runAsUser": 0}}])])
        row = df[df["AuditResultName"] == "RunAsUserCSCRoot"].iloc[0]
        assert bool(row["UserNamespaced"]) is False

    def test_privileged_container_marked_user_namespaced(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                make_pod(
                    [{"name": "app", "securityContext": {"privileged": True}}],
                    pod_spec_extra={"hostUsers": False},
                )
            ],
        )
        row = df[df["AuditResultName"] == "PrivilegedTrue"].iloc[0]
        assert bool(row["UserNamespaced"]) is True

    def test_user_namespaced_column_always_present(self, tmp_path):
        df = run_audit(tmp_path, [])
        assert "UserNamespaced" in df.columns


class TestPrivilegedFlagSuppression:
    """A userns-isolated privileged container must not raise the host-level escalation finding."""

    def test_privileged_flag_set_when_not_user_namespaced(self, tmp_path):
        df = run_audit(tmp_path, [make_pod([{"name": "app", "securityContext": {"privileged": True}}])])
        kube = Kubenumerate(verbosity=0)
        kube.evaluate_privileged_severity(df)
        assert kube.privileged_flag is True

    def test_privileged_flag_not_set_when_user_namespaced(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                make_pod(
                    [{"name": "app", "securityContext": {"privileged": True}}],
                    pod_spec_extra={"hostUsers": False},
                )
            ],
        )
        kube = Kubenumerate(verbosity=0)
        kube.evaluate_privileged_severity(df)
        assert kube.privileged_flag is False

    def test_privileged_flag_set_when_any_container_not_user_namespaced(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                make_pod(
                    [{"name": "app", "securityContext": {"privileged": True}}],
                    pod_spec_extra={"hostUsers": False},
                    name="safe",
                ),
                make_pod([{"name": "app", "securityContext": {"privileged": True}}], name="unsafe"),
            ],
        )
        kube = Kubenumerate(verbosity=0)
        kube.evaluate_privileged_severity(df)
        assert kube.privileged_flag is True


class TestSummaryTableIntegration:
    """New findings must render as prose in the Word summary, not as raw result names."""

    @pytest.mark.parametrize(
        "result_name",
        ["ProcMountUnmasked", "ProcMountUnmaskedWithoutUserNamespace", "UserNamespaceNotEnabled"],
    )
    def test_new_findings_have_human_readable_names(self, result_name):
        assert result_name in ISSUE_NAME_MAP

    def test_user_namespaced_root_finding_is_annotated_in_summary(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                make_deployment(
                    [{"name": "app", "securityContext": {"runAsUser": 0}}],
                    pod_spec_extra={"hostUsers": False},
                )
            ],
        )
        summary = aggregate_issues_by_workload(df, [], verbosity=0)
        issues = summary[("default", "Deployment", "test-deploy")]["issues"]
        assert any("root (UID 0)" in issue and "user namespace" in issue for issue in issues)

    def test_unmitigated_root_finding_is_not_annotated_in_summary(self, tmp_path):
        df = run_audit(tmp_path, [make_deployment([{"name": "app", "securityContext": {"runAsUser": 0}}])])
        summary = aggregate_issues_by_workload(df, [], verbosity=0)
        issues = summary[("default", "Deployment", "test-deploy")]["issues"]
        assert "Container runs as root (UID 0)" in issues


class TestUserNamespacedAnnotationRobustness:
    """A missing UserNamespaced value must never be read as 'mitigated' (bool(nan) is True)."""

    def test_missing_user_namespaced_value_is_not_treated_as_mitigated(self):
        import numpy as np
        import pandas as pd

        df = pd.DataFrame(
            [
                {
                    "AuditResultName": "RunAsUserCSCRoot",
                    "ResourceNamespace": "default",
                    "ResourceKind": "Deployment",
                    "ResourceName": "legacy",
                    "Container": "app",
                    "UserNamespaced": np.nan,
                    "msg": "Container runs as UID 0.",
                }
            ]
        )
        summary = aggregate_issues_by_workload(df, [], verbosity=0)
        issues = summary[("default", "Deployment", "legacy")]["issues"]
        assert "Container runs as root (UID 0)" in issues
