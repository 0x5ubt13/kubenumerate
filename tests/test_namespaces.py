#!/usr/bin/env python3
"""Tests for scoping a run to one or more namespaces (OpenShift projects are the same)"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kubenumerate import Kubenumerate  # noqa: E402


def test_no_namespace_flag_fetches_cluster_wide():
    assert Kubenumerate(namespaces=None).scopes_for("pods", {"pods"}) == [["-A"]]


def test_namespace_scope_fetches_once_per_namespace_without_duplicates():
    assert Kubenumerate(namespaces=["abc", "xyz", "abc"]).scopes_for("pods", {"pods"}) == [["-n", "abc"], ["-n", "xyz"]]


def test_namespace_scoped_run_fetches_only_namespaced_kinds():
    kube = Kubenumerate(namespaces=["abc"])
    assert kube.resources_to_fetch({"pods"}, {"nodes", "clusterroles"}) == ["pods"]


def test_unscoped_run_fetches_cluster_scoped_kinds_too():
    kube = Kubenumerate(namespaces=None)
    assert kube.resources_to_fetch({"pods"}, {"nodes"}) == ["nodes", "pods"]


def test_kubiscan_is_skipped_for_namespace_scoped_runs(monkeypatch):
    # KubiScan -a audits cluster-wide RBAC and pods, so it must not run when the scope is restricted
    calls = []
    kube = Kubenumerate(namespaces=["abc"])
    monkeypatch.setattr(kube, "run_kubiscan", lambda: calls.append("kubiscan"))
    kube.check_roles()
    assert calls == []


def test_kubiscan_runs_for_unscoped_runs(monkeypatch):
    calls = []
    kube = Kubenumerate(namespaces=None)
    monkeypatch.setattr(kube, "run_kubiscan", lambda: calls.append("kubiscan"))
    kube.check_roles()
    assert calls == ["kubiscan"]


def test_project_flag_is_an_alias_for_namespace(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["kubenumerate", "--namespace", "abc", "--project", "xyz", "-n", "def"])
    kube = Kubenumerate()
    kube.parse_args()
    assert kube.args.namespaces == ["abc", "xyz", "def"]
