#!/usr/bin/env python3
"""Offline tests for cluster-scoped checks, which sections each mode produces, and what reaches the workbook and Word
report. Synthetic objects only; no cluster access."""

import os
import re
import sys
import zipfile

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kubenumerate import Kubenumerate  # noqa: E402
from project_review import cross_object_findings, project_findings, selected_sections  # noqa: E402
from summary_table import generate_summary_table  # noqa: E402

FINDING_COLUMNS = ["AuditResultName", "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]


def names(findings):
    return {f["AuditResultName"] for f in findings}


def node(name, kubelet):
    return {"kind": "Node", "metadata": {"name": name}, "status": {"nodeInfo": {"kubeletVersion": kubelet}}}


def sheet_names(workbook_path):
    with zipfile.ZipFile(workbook_path) as archive:
        return re.findall(r'<sheet name="([^"]+)"', archive.read("xl/workbook.xml").decode())


def test_cluster_role_wildcard_is_flagged_with_cluster_prefix():
    role = {
        "kind": "ClusterRole",
        "metadata": {"name": "ops"},
        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
    }
    assert {"ClusterRoleWildcardPermission", "ClusterRoleSecretRead"} <= names(project_findings(role))


def test_kubernetes_default_roles_are_not_reviewed():
    role = {
        "kind": "ClusterRole",
        "metadata": {"name": "system:controller:x"},
        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
    }
    assert project_findings(role) == []


def test_cluster_admin_and_broad_group_bindings_are_flagged():
    binding = {
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "open"},
        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
        "subjects": [{"kind": "Group", "name": "system:authenticated"}],
    }
    assert {"ClusterBindingToClusterAdmin", "ClusterBindingToBroadGroup"} <= names(project_findings(binding))


def test_webhook_ignore_policy_and_external_url_are_reported_per_webhook():
    config = {
        "kind": "ValidatingWebhookConfiguration",
        "metadata": {"name": "policy"},
        "webhooks": [
            {"name": "a.example.com", "failurePolicy": "Ignore", "clientConfig": {"url": "https://ext.example.com"}},
            {"name": "b.example.com", "clientConfig": {"service": {"name": "svc"}}},
        ],
    }
    findings = project_findings(config)
    ignored = [f for f in findings if f["AuditResultName"] == "WebhookFailurePolicyIgnore"]
    external = [f for f in findings if f["AuditResultName"] == "WebhookExternalURL"]
    assert [f["msg"].split()[1] for f in ignored] == ["a.example.com"]
    assert [f["msg"].split()[1] for f in external] == ["a.example.com"]


def test_nodes_on_different_kubelet_minors_are_each_flagged():
    findings = cross_object_findings(
        [node("n1", "v1.36.3"), node("n2", "v1.35.1"), node("n3", "v1.36.0")], [], lambda ns, res: False
    )
    skew = {f["ResourceName"] for f in findings if f["AuditResultName"] == "NodeKubeletVersionSkew"}
    assert skew == {"n1", "n2", "n3"}


def test_nodes_on_one_minor_version_are_not_flagged():
    findings = cross_object_findings([node("n1", "v1.36.3"), node("n2", "v1.36.0")], [], lambda ns, res: False)
    assert "NodeKubeletVersionSkew" not in names(findings)


def test_cluster_binding_to_a_risky_cluster_role_is_flagged():
    role = {
        "kind": "ClusterRole",
        "metadata": {"name": "reader"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}],
    }
    binding = {
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "b"},
        "roleRef": {"kind": "ClusterRole", "name": "reader"},
        "subjects": [{"kind": "User", "name": "x"}],
    }
    assert "ClusterBindingToRiskyRole" in names(cross_object_findings([role, binding], [], lambda ns, res: False))


def test_cluster_sections_only_exist_in_cluster_wide_runs():
    namespace_run = {s[2] for s in selected_sections(review=True, cluster=False, openshift=False)}
    cluster_run = {s[2] for s in selected_sections(review=True, cluster=True, openshift=False)}
    assert not {"Admission webhooks", "Nodes", "Cluster RBAC - Roles"} & namespace_run
    assert {"Admission webhooks", "Nodes", "Cluster RBAC - Roles"} <= cluster_run


def test_openshift_scc_definitions_need_a_cluster_wide_run():
    assert "OpenShift - SCC definitions" not in {s[2] for s in selected_sections(True, False, True)}
    assert "OpenShift - SCC definitions" in {s[2] for s in selected_sections(True, True, True)}


def test_review_switched_off_keeps_openshift_sections_only():
    sheets = {s[2] for s in selected_sections(review=False, cluster=True, openshift=True)}
    assert sheets == {"OpenShift - Pod SCC", "OpenShift - Routes", "OpenShift - SCC definitions"}


def test_only_populated_sheets_are_written_and_the_flag_keeps_the_run_sheets(tmp_path):
    def finding(audit):
        return {
            "AuditResultName": audit,
            "ResourceNamespace": "team-a",
            "ResourceKind": "Namespace",
            "ResourceName": "team-a",
            "Container": "",
            "msg": "observation",
        }

    psa_only = pd.DataFrame([finding("PSAEnforcePrivileged")], columns=FINDING_COLUMNS)
    empty = pd.DataFrame(columns=FINDING_COLUMNS)

    def workbook(kube, df, name):
        path = tmp_path / name
        with pd.ExcelWriter(path, engine="xlsxwriter") as writer:
            kube.project_checks(df, writer)
        return sheet_names(path)

    populated = workbook(Kubenumerate(namespaces=["team-a"]), psa_only, "populated.xlsx")
    assert "PSA labels" in populated
    assert "RBAC - Roles" not in populated  # no findings, so no sheet

    no_findings = workbook(Kubenumerate(namespaces=["team-a"]), empty, "none.xlsx")
    assert "PSA labels" not in no_findings

    flagged = Kubenumerate(namespaces=["team-a"])
    flagged.generate_empty_sheets = True
    with_flag = workbook(flagged, empty, "flag.xlsx")
    assert "PSA labels" in with_flag
    assert "Admission webhooks" not in with_flag  # cluster checks never ran in a namespace run


def test_word_report_includes_review_findings_and_only_the_sections_that_ran(tmp_path):
    findings = pd.DataFrame(
        [
            {
                "AuditResultName": "PSAEnforcePrivileged",
                "ResourceNamespace": "team-a",
                "ResourceKind": "Namespace",
                "ResourceName": "team-a",
                "Container": "",
                "msg": "enforce is privileged marker-one",
            },
            {
                "AuditResultName": "WebhookFailurePolicyIgnore",
                "ResourceNamespace": "",
                "ResourceKind": "ValidatingWebhookConfiguration",
                "ResourceName": "policy",
                "Container": "",
                "msg": "Webhook a.example.com ignores its own failures. marker-two",
            },
        ],
        columns=FINDING_COLUMNS,
    )

    def report(sections, notes, name):
        path = tmp_path / name
        generate_summary_table(findings, [], str(path), 0, review_sections=sections, notes=notes)
        with zipfile.ZipFile(path) as archive:
            return re.sub(r"<[^>]+>", " ", archive.read("word/document.xml").decode())

    namespace_text = report(
        selected_sections(True, False, False), ["Cluster-scoped checks were not run."], "namespace.docx"
    )
    assert "marker-one" in namespace_text
    assert "marker-two" not in namespace_text, "cluster findings cannot appear in a namespace run"
    assert "Cluster-scoped checks were not run." in namespace_text

    cluster_text = report(selected_sections(True, True, False), [], "cluster.docx")
    assert "marker-two" in cluster_text
    assert "Admission webhooks" in cluster_text
