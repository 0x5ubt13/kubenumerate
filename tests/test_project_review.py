#!/usr/bin/env python3
"""Offline tests for the project-scoped review: synthetic objects, a fake kubectl, no cluster access"""

import argparse
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kubenumerate import Kubenumerate  # noqa: E402
from project_review import (  # noqa: E402
    CLUSTER_SECTIONS,
    OPENSHIFT_CLUSTER_SECTIONS,
    OPENSHIFT_SECTIONS,
    RECOMMENDATIONS,
    REVIEW_SECTIONS,
    cross_object_findings,
    project_findings,
)


def names(findings):
    return {f["AuditResultName"] for f in findings}


def text(findings):
    return json.dumps(findings)


def assert_all_known(findings):
    # Every observation must have a recommendation and a report sheet, or it would be silently dropped
    assert names(findings) <= set(RECOMMENDATIONS)


def role(rules, name="reader", namespace="team-a"):
    return {"kind": "Role", "metadata": {"name": name, "namespace": namespace}, "rules": rules}


def rolebinding(ref_kind, ref_name, subjects, namespace="team-a"):
    return {
        "kind": "RoleBinding",
        "metadata": {"name": "b", "namespace": namespace},
        "roleRef": {"kind": ref_kind, "name": ref_name},
        "subjects": subjects,
    }


def test_namespace_without_enforce_label_is_an_observation_not_a_pass():
    ns = {
        "kind": "Namespace",
        "metadata": {"name": "team-a", "labels": {"pod-security.kubernetes.io/audit": "restricted"}},
    }
    findings = project_findings(ns)
    assert "PSAEnforceNotSet" in names(findings)
    assert "PSAEnforcePrivileged" not in names(findings)
    assert all(f["ResourceNamespace"] == "team-a" for f in findings)
    assert_all_known(findings)


def test_privileged_enforce_label_is_flagged():
    ns = {
        "kind": "Namespace",
        "metadata": {"name": "team-a", "labels": {"pod-security.kubernetes.io/enforce": "privileged"}},
    }
    assert "PSAEnforcePrivileged" in names(project_findings(ns))


def test_wildcard_role_is_flagged_and_wildcard_read_covers_secrets():
    findings = project_findings(role([{"apiGroups": [""], "resources": ["*"], "verbs": ["get"]}]))
    assert {"RoleWildcardPermission", "RoleSecretRead"} <= names(findings)
    assert_all_known(findings)


def test_read_only_role_produces_no_risk_findings():
    assert project_findings(role([{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}])) == []


def test_exec_and_escalation_are_flagged():
    rules = [
        {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]},
        {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles"], "verbs": ["escalate"]},
    ]
    assert {"RolePodsExec", "RoleEscalateBind"} <= names(project_findings(role(rules)))


def test_clusterrole_binding_reports_the_reference_without_claiming_inspection():
    binding = rolebinding("ClusterRole", "view", [{"kind": "User", "name": "alice@example.com"}])
    findings = project_findings(binding)
    assert "BindingReferencesClusterRole" in names(findings)
    assert "not assessed" in text(findings)
    assert "alice" not in text(findings), "subject names must be minimised out of the report"


def test_binding_to_a_local_role_with_risky_rules_is_flagged():
    risky = role([{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}], name="reader")
    binding = rolebinding("Role", "reader", [{"kind": "ServiceAccount", "name": "ci", "namespace": "team-a"}])
    findings = cross_object_findings([risky, binding], ["team-a"], lambda ns, res: False)
    assert "BindingToRiskyRole" in names(findings)


@pytest.mark.parametrize(
    "service_type, expected",
    [("LoadBalancer", "ServiceLoadBalancer"), ("NodePort", "ServiceNodePort"), ("ClusterIP", "ServiceConfigured")],
)
def test_service_type_is_reported(service_type, expected):
    svc = {
        "kind": "Service",
        "metadata": {"name": "web", "namespace": "team-a"},
        "spec": {"type": service_type, "ports": [{"port": 443}], "selector": {"app": "web"}},
    }
    assert names(project_findings(svc)) == {expected}


def test_ingress_tls_coverage_is_checked_per_host():
    ingress = {"kind": "Ingress", "metadata": {"name": "i", "namespace": "team-a"}}
    no_tls = dict(ingress, spec={"rules": [{"host": "a.example.com"}]})
    assert "IngressWithoutTLS" in names(project_findings(no_tls))

    covered = dict(ingress, spec={"rules": [{"host": "a.example.com"}], "tls": [{"hosts": ["a.example.com"]}]})
    assert names(project_findings(covered)) == {"IngressConfigured"}

    partial = dict(
        ingress,
        spec={"rules": [{"host": "a.example.com"}, {"host": "b.example.com"}], "tls": [{"hosts": ["a.example.com"]}]},
    )
    assert "IngressHostWithoutTLS" in names(project_findings(partial))


def test_service_account_with_token_automount_unset_is_flagged_but_explicit_false_is_not():
    unset = {"kind": "ServiceAccount", "metadata": {"name": "ci", "namespace": "team-a"}}
    disabled = dict(unset, automountServiceAccountToken=False)
    assert "ServiceAccountTokenAutomounted" in names(project_findings(unset))
    assert project_findings(disabled) == []


def test_pod_overriding_to_automount_for_a_named_account_is_flagged_but_not_for_default():
    named = {
        "kind": "Pod",
        "metadata": {"name": "p", "namespace": "team-a"},
        "spec": {"serviceAccountName": "ci-runner", "automountServiceAccountToken": True, "containers": []},
    }
    default = {
        "kind": "Pod",
        "metadata": {"name": "p", "namespace": "team-a"},
        "spec": {"automountServiceAccountToken": True, "containers": []},
    }
    assert "PodTokenAutomountExplicit" in names(project_findings(named))
    assert "PodTokenAutomountExplicit" not in names(project_findings(default))


def _workload_chain(pod_app_context, pod_init_context):
    """Deployment -> ReplicaSet -> Pod, with a template that sets allowPrivilegeEscalation: false and an init container"""
    deployment = {
        "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "team-a"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": "app", "securityContext": {"allowPrivilegeEscalation": False}}],
                    "initContainers": [{"name": "init", "securityContext": {"privileged": False}}],
                }
            }
        },
    }
    replicaset = {
        "kind": "ReplicaSet",
        "metadata": {
            "name": "web-abc",
            "namespace": "team-a",
            "ownerReferences": [{"kind": "Deployment", "name": "web", "controller": True}],
        },
    }
    pod = {
        "kind": "Pod",
        "metadata": {
            "name": "web-abc-1",
            "namespace": "team-a",
            "ownerReferences": [{"kind": "ReplicaSet", "name": "web-abc", "controller": True}],
        },
        "spec": {
            "containers": [{"name": "app", **pod_app_context}],
            "initContainers": [{"name": "init", **pod_init_context}],
        },
    }
    return [deployment, replicaset, pod]


def test_pod_drift_from_template_reports_unset_versus_false_and_init_containers():
    items = _workload_chain(pod_app_context={}, pod_init_context={"securityContext": {"privileged": False}})
    findings = cross_object_findings(items, ["team-a"], lambda ns, res: False)
    drift = [f for f in findings if f["AuditResultName"] == "PodDiffersFromTemplate"]
    assert len(drift) == 1
    assert "app.securityContext" in drift[0]["msg"]  # unset in the Pod, explicit in the template
    assert "init.securityContext" not in drift[0]["msg"]  # identical on both sides
    assert "False" not in drift[0]["msg"], "drift reports setting names, not values"


def test_matching_pod_produces_no_drift():
    items = _workload_chain(
        pod_app_context={"securityContext": {"allowPrivilegeEscalation": False}},
        pod_init_context={"securityContext": {"privileged": False}},
    )
    findings = cross_object_findings(items, ["team-a"], lambda ns, res: False)
    assert "PodDiffersFromTemplate" not in names(findings)


def test_absent_quota_is_reported_only_when_the_listing_succeeded():
    pod = {"kind": "Pod", "metadata": {"name": "p", "namespace": "team-a"}, "spec": {"containers": []}}

    unknown = cross_object_findings([pod], ["team-a"], lambda ns, res: False)
    assert names(unknown) == set(), "forbidden or unlisted resources must not be reported as absent"

    listed = cross_object_findings([pod], ["team-a"], lambda ns, res: res == "resourcequotas")
    assert names(listed) == {"NamespaceWithoutResourceQuota"}


def test_missing_pdb_is_reported_only_for_replicated_workloads():
    def deployment(replicas):
        return {
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "team-a"},
            "spec": {"replicas": replicas, "template": {"spec": {"containers": []}}},
        }

    listed = lambda ns, res: res == "poddisruptionbudgets"  # noqa: E731
    assert "NamespaceWithoutPDB" in names(cross_object_findings([deployment(3)], ["team-a"], listed))
    assert "NamespaceWithoutPDB" not in names(cross_object_findings([deployment(1)], ["team-a"], listed))


def test_confluent_listener_gaps_are_reported_and_secret_references_never_appear():
    kafka = {
        "apiVersion": "platform.confluent.io/v1beta1",
        "kind": "Kafka",
        "metadata": {"name": "k", "namespace": "team-a"},
        "spec": {
            "replicas": 3,
            "listeners": {
                "internal": {"port": 9092, "tls": {"enabled": True}},
                "external": {
                    "port": 9094,
                    "externalAccess": {"type": "loadBalancer"},
                    "authentication": {"type": "plain", "jaasConfigPassThrough": {"secretRef": "super-secret-name"}},
                },
            },
        },
    }
    findings = project_findings(kafka)
    assert {"ConfluentListenerAuthNotDeclared", "ConfluentListenerTLSNotDeclared"} <= names(findings)
    assert "super-secret-name" not in text(findings)
    assert_all_known(findings)


def test_confluent_rolebinding_omits_principal_name_and_flags_admin_roles():
    binding = {
        "apiVersion": "platform.confluent.io/v1beta1",
        "kind": "ConfluentRolebinding",
        "metadata": {"name": "rb", "namespace": "team-a"},
        "spec": {
            "principal": {"type": "User", "name": "svc-admin-jane"},
            "role": "SystemAdmin",
            "resourcePatterns": [],
        },
    }
    findings = project_findings(binding)
    assert "ConfluentPrivilegedRoleBinding" in names(findings)
    assert "jane" not in text(findings)


def test_every_review_audit_has_one_sheet_and_one_recommendation():
    all_sections = REVIEW_SECTIONS + CLUSTER_SECTIONS + OPENSHIFT_SECTIONS + OPENSHIFT_CLUSTER_SECTIONS
    sheet_audits = [audit for _, _, _, audits in all_sections for audit in audits]
    assert len(sheet_audits) == len(set(sheet_audits)), "an audit appears in two sheets"
    assert set(sheet_audits) == set(RECOMMENDATIONS)


@pytest.mark.parametrize(
    "stderr, expected",
    [
        ('Error from server (Forbidden): configmaps is forbidden: User "x" cannot list', "forbidden"),
        ('error: the server doesn\'t have a resource type "kafkas"', "unsupported"),
        ('Error from server (NotFound): namespaces "gone" not found', "not found"),
        ("Unable to connect to the server: dial tcp: connection refused", "failed"),
    ],
)
def test_kubectl_failures_are_classified_for_coverage(stderr, expected):
    assert Kubenumerate.classify_kubectl_error(stderr) == expected


def test_namespace_mode_never_falls_back_to_cluster_wide_requests(tmp_path, monkeypatch):
    import kubenumerate

    calls = []

    def fake_check_output(command, shell=False):
        return b"pods\nconfigmaps\n" if "--namespaced=true" in command else b"nodes\n"

    class FakeCompleted:
        def __init__(self, returncode, stdout=b"", stderr=b""):
            self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    def fake_run(command, *args, **kwargs):
        calls.append(command)
        resource, scope = command[2], command[3:-2]
        if resource == "configmaps" and scope == ["-n", "xyz"]:
            return FakeCompleted(1, stderr=b"Error from server (Forbidden): configmaps is forbidden")
        if resource == "namespace":
            payload = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": scope[0]}}
        else:
            payload = {"kind": "List", "items": [{"kind": resource, "metadata": {"name": "x"}}]}
        return FakeCompleted(0, stdout=json.dumps(payload).encode())

    class FakePopen:
        def __init__(self, command, stdout=None, stderr=None):
            pass

        def communicate(self):
            return b"Server Version: v1.36.3\n", b""

    monkeypatch.setattr(kubenumerate.subprocess, "check_output", fake_check_output)
    monkeypatch.setattr(kubenumerate.subprocess, "run", fake_run)
    monkeypatch.setattr(kubenumerate.subprocess, "Popen", FakePopen)

    kube = Kubenumerate(
        version="0.0.0-test",
        args=argparse.Namespace(kubeconfig=None),
        kubectl_bin="kubectl",
        kubectl_output_path=str(tmp_path) + "/",
        namespaces=["abc", "xyz"],
        verbosity=0,
    )
    kube.kubectl_get_all_yaml_and_json()

    assert not any("-A" in call for call in calls), "no cluster-wide request may be issued"
    assert not any(call[2] == "nodes" for call in calls), "cluster-scoped kinds are not requested in namespace mode"
    namespaced_scopes = [call[3:-2] for call in calls if call[2] not in ("namespace", "nodes")]
    assert all(scope in (["-n", "abc"], ["-n", "xyz"]) for scope in namespaced_scopes)
    # Namespace objects are read one by name, never listed: this is what supplies the PSA labels
    assert [call[3:-2] for call in calls if call[2] == "namespace"] == [["abc"], ["xyz"]]
    assert sum(1 for call in calls if call[2] == "configmaps" and call[3:-2] == ["-n", "xyz"]) == 1, "no retry"

    status = {(row["Scope"], row["Resource"]): row["Status"] for row in kube.coverage}
    assert status[("xyz", "configmaps")] == "forbidden"
    assert status[("abc", "configmaps")] in ("collected", "empty")
    assert status[("cluster-wide", "nodes")] == "not assessed"
