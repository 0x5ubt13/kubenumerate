#!/usr/bin/env python3
"""Offline tests: bindings to identities that cover everyone, including system:anonymous (bound as a User)"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from project_review import project_findings  # noqa: E402


def names(findings):
    return {f["AuditResultName"] for f in findings}


def test_rolebinding_to_anonymous_user_is_flagged():
    binding = {
        "kind": "RoleBinding",
        "metadata": {"name": "b", "namespace": "team-a"},
        "roleRef": {"kind": "Role", "name": "reader"},
        "subjects": [{"kind": "User", "name": "system:anonymous"}],
    }
    assert "BindingToBroadGroup" in names(project_findings(binding))


def test_clusterrolebinding_to_anonymous_user_is_flagged():
    binding = {
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "open"},
        "roleRef": {"kind": "ClusterRole", "name": "view"},
        "subjects": [{"kind": "User", "name": "system:anonymous"}],
    }
    assert "ClusterBindingToBroadGroup" in names(project_findings(binding))


def test_group_subjects_still_flagged_and_ordinary_users_are_not():
    binding = {
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "x"},
        "roleRef": {"kind": "ClusterRole", "name": "view"},
        "subjects": [{"kind": "Group", "name": "system:authenticated"}, {"kind": "User", "name": "alice"}],
    }
    text = str(project_findings(binding))
    assert "ClusterBindingToBroadGroup" in names(project_findings(binding))
    assert "alice" not in text
