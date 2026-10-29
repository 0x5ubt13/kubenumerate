#!/usr/bin/env python3
"""Offline tests: RBAC risks match on API group as well as resource and verb"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from project_review import rbac_rule_risks  # noqa: E402


def test_same_resource_name_in_a_custom_group_is_not_a_secret_read():
    # A custom resource called "secrets" in example.com is not the core Secret resource
    rules = [{"apiGroups": ["example.com"], "resources": ["secrets"], "verbs": ["get"]}]
    assert "RoleSecretRead" not in rbac_rule_risks(rules)


def test_core_secret_read_is_flagged():
    rules = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
    assert "RoleSecretRead" in rbac_rule_risks(rules)


def test_workload_creation_needs_the_apps_or_batch_group():
    assert "RoleWorkloadCreate" in rbac_rule_risks(
        [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["create"]}]
    )
    assert "RoleWorkloadCreate" not in rbac_rule_risks(
        [{"apiGroups": ["example.com"], "resources": ["deployments"], "verbs": ["create"]}]
    )


def test_wildcard_group_matches_every_group():
    rules = [{"apiGroups": ["*"], "resources": ["secrets"], "verbs": ["list"]}]
    assert "RoleSecretRead" in rbac_rule_risks(rules)


def test_rule_without_api_groups_grants_nothing():
    rules = [{"resources": ["secrets"], "verbs": ["get"]}]
    assert rbac_rule_risks(rules) == {}
