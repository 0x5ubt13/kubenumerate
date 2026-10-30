#!/usr/bin/env python3
"""Offline tests for Confluent fields confirmed with `oc explain`: principal type, and Kafka custom listeners"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from project_review import project_findings  # noqa: E402

API = "platform.confluent.io/v1beta1"


def test_rolebinding_reports_principal_type_but_never_the_name():
    binding = {
        "apiVersion": API,
        "kind": "ConfluentRolebinding",
        "metadata": {"name": "rb", "namespace": "team-a"},
        "spec": {"principal": {"type": "group", "name": "svc-ops-jane"}, "role": "Operator", "resourcePatterns": []},
    }
    text = str(project_findings(binding))
    assert "principal type group" in text
    assert "svc-ops-jane" not in text


def test_kafka_custom_listener_is_assessed_like_the_built_in_listeners():
    kafka = {
        "apiVersion": API,
        "kind": "Kafka",
        "metadata": {"name": "k", "namespace": "team-a"},
        "spec": {"listeners": {"custom": [{"name": "partner", "port": 9095, "authentication": {"type": "plain"}}]}},
    }
    findings = project_findings(kafka)
    text = str(findings)
    assert "custom partner, port 9095" in text
    assert "ConfluentListenerTLSNotDeclared" in {f["AuditResultName"] for f in findings}
    assert "not assessed" not in text
