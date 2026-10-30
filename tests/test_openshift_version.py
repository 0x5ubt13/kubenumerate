#!/usr/bin/env python3
"""Offline tests: the cluster's Kubernetes version is compared against the version OpenShift bundles, and failed lookups
fall back cleanly"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import kubenumerate  # noqa: E402
from kubenumerate import Kubenumerate  # noqa: E402

RELEASE_TXT = """Client tools for OpenShift

Name:           4.22.18
Component Versions:
  kubectl          1.35.2
  kubernetes       1.35.8
  kubernetes-tests 1.35.1
  machine-os       10.2.20261006-0 Red Hat Enterprise Linux CoreOS 10.2
"""


class FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def kube(openshift, cluster_version="1.34.2"):
    return Kubenumerate(
        version="test", args=argparse.Namespace(kubeconfig=None), openshift=openshift, cluster_version=cluster_version
    )


def test_bundled_kubernetes_version_is_read_from_the_release_file(monkeypatch):
    monkeypatch.setattr(kubenumerate.requests, "get", lambda url, timeout: FakeResponse(RELEASE_TXT))
    # kubernetes-tests and kubectl must not be mistaken for the bundled version
    assert kube(openshift=True).fetch_openshift_kubernetes_version() == "1.35.8"


def test_openshift_cluster_is_compared_with_the_bundled_version_not_upstream(monkeypatch):
    monkeypatch.setattr(Kubenumerate, "fetch_openshift_kubernetes_version", lambda self: "1.35.8")

    def upstream_must_not_be_called(self):
        raise AssertionError("upstream Kubernetes must not be the reference on OpenShift")

    monkeypatch.setattr(Kubenumerate, "fetch_latest_kubernetes_version", upstream_must_not_be_called)
    k = kube(openshift=True, cluster_version="1.34.2")
    k.kubernetes_version_check()
    assert k.kube_version == "1.35.8"
    assert k.version_diff == 1


def test_failed_openshift_lookup_keeps_the_hard_coded_version(monkeypatch):
    monkeypatch.setattr(Kubenumerate, "fetch_openshift_kubernetes_version", lambda self: None)
    k = kube(openshift=True)
    before = k.kube_version
    k.kubernetes_version_check()
    assert k.kube_version == before


def test_upstream_lookup_error_string_does_not_crash_the_check(monkeypatch):
    # fetch_latest_kubernetes_version returns "error" on failure; this used to reach Version("error") and raise
    monkeypatch.setattr(Kubenumerate, "fetch_latest_kubernetes_version", lambda self: "error")
    k = kube(openshift=False)
    before = k.kube_version
    k.kubernetes_version_check()
    assert k.kube_version == before


def test_missing_bundled_version_in_release_file_returns_none(monkeypatch):
    monkeypatch.setattr(kubenumerate.requests, "get", lambda url, timeout: FakeResponse("no versions here"))
    assert kube(openshift=True).fetch_openshift_kubernetes_version() is None
