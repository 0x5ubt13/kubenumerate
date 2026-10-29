#!/usr/bin/env python3
"""Offline tests for the scope marker: reuse only within the same scope"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kubenumerate import SCOPE_MARKER, Kubenumerate  # noqa: E402


def make(tmp_path, namespaces):
    return Kubenumerate(namespaces=namespaces, kubectl_output_path=str(tmp_path) + "/")


def test_first_run_writes_the_marker(tmp_path):
    make(tmp_path, ["team-a"]).check_scope_marker()
    recorded = json.loads((tmp_path / SCOPE_MARKER).read_text())
    assert recorded == {"platform": "kubernetes", "mode": "namespace", "namespaces": ["team-a"]}


def test_same_scope_may_resume_over_existing_files(tmp_path):
    make(tmp_path, ["team-a", "team-b"]).check_scope_marker()
    (tmp_path / "pods.json").write_text("{}")
    make(tmp_path, ["team-b", "team-a"]).check_scope_marker()  # same set, different order: resumes


def test_different_scope_is_refused(tmp_path):
    make(tmp_path, None).check_scope_marker()  # cluster-wide run
    (tmp_path / "pods.json").write_text("{}")
    with pytest.raises(SystemExit) as exc:
        make(tmp_path, ["team-a"]).check_scope_marker()
    assert exc.value.code == 2


def test_files_without_a_marker_are_refused(tmp_path):
    (tmp_path / "pods.json").write_text("{}")
    with pytest.raises(SystemExit) as exc:
        make(tmp_path, ["team-a"]).check_scope_marker()
    assert exc.value.code == 2
    assert not (tmp_path / SCOPE_MARKER).exists()


def test_marker_is_not_mistaken_for_collected_data(tmp_path):
    make(tmp_path, ["team-a"]).check_scope_marker()
    make(tmp_path, ["team-a"]).check_scope_marker()  # the marker alone must not count as data
