#!/usr/bin/env python3
"""Offline tests for namespace selection, the review skip, and the output and sheet flags"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse  # noqa: E402

from kubenumerate import Kubenumerate  # noqa: E402


@pytest.mark.parametrize(
    "values, expected",
    [
        (None, None),
        ([], None),
        (["abc", "xyz", "abc"], ["abc", "xyz"]),
    ],
)
def test_namespace_selection_is_unique_names_or_cluster_wide(values, expected):
    assert Kubenumerate.normalise_namespaces(values) == expected


def test_control_plane_review_can_be_skipped(tmp_path):
    namespace = {
        "kind": "Namespace",
        "metadata": {"name": "team-a", "labels": {"pod-security.kubernetes.io/enforce": "privileged"}},
    }
    (tmp_path / "namespaces.json").write_text(json.dumps({"kind": "List", "items": [namespace]}))

    def audits(skip):
        kube = Kubenumerate(namespaces=["team-a"], kubectl_output_path=str(tmp_path) + "/")
        kube.skip_review = skip
        return {row["AuditResultName"] for _, row in kube.generate_kubeaudit_equivalent_df_from_kubectl().iterrows()}

    assert "PSAEnforcePrivileged" in audits(skip=False)
    assert "PSAEnforcePrivileged" not in audits(skip=True)


def test_flags_parse_and_default_off(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["kubenumerate"])
    kube = Kubenumerate()
    kube.parse_args()
    assert kube.args.skip_control_plane_review is False
    assert kube.args.skip_trivy is False
    assert kube.args.generate_empty_sheets is False

    monkeypatch.setattr(
        sys,
        "argv",
        ["kubenumerate", "--skip-control-plane-review", "--skip-trivy", "--generate-empty-sheets"],
    )
    kube = Kubenumerate(args=argparse.Namespace())
    kube.parse_args()
    assert kube.args.skip_control_plane_review is True
    assert kube.args.skip_trivy is True
    assert kube.args.generate_empty_sheets is True
