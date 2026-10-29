#!/usr/bin/env python3
"""Offline tests for Confluent configuration reads, using the shapes confirmed with `oc explain` on the served CRDs"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from project_review import project_findings  # noqa: E402

API = "platform.confluent.io/v1beta1"


def names(findings):
    return {f["AuditResultName"] for f in findings}


def obj(kind, spec):
    return {"apiVersion": API, "kind": kind, "metadata": {"name": "x", "namespace": "team-a"}, "spec": spec}


def test_kafka_custom_listener_list_does_not_drop_the_other_findings():
    # `custom` is a list in the served schema; reading it as a listener object used to raise and lose the whole file
    kafka = obj("Kafka", {"listeners": {"internal": {"authentication": {"type": "plain"}}, "custom": [{"name": "c"}]}})
    findings = project_findings(kafka)
    assert {"ConfluentKafkaListeners", "ConfluentListenerTLSNotDeclared"} <= names(findings)
    assert "custom c" in str(findings)


def test_kafka_listeners_with_auth_and_tls_have_no_gap_findings():
    kafka = obj(
        "Kafka",
        {
            "listeners": {
                "internal": {"authentication": {"type": "mtls"}, "tls": {"enabled": True}},
                "external": {"authentication": {"type": "oauth"}, "tls": {"enabled": True}},
            }
        },
    )
    assert names(project_findings(kafka)) == {"ConfluentKafkaListeners"}


def test_control_center_with_live_shape_reports_missing_tls_block_only():
    # Shape from the cluster: REST auth basic, Kafka client auth mtls, no spec.tls block
    control_center = obj(
        "ControlCenter",
        {"authentication": {"type": "basic"}, "dependencies": {"kafka": {"authentication": {"type": "mtls"}}}},
    )
    found = names(project_findings(control_center))
    assert "ConfluentComponentTLSNotDeclared" in found
    assert "ConfluentComponentAuthNotDeclared" not in found
    assert "ConfluentComponentKafkaAuthNotDeclared" not in found


def test_connect_without_kafka_client_auth_is_reported():
    connect = obj("Connect", {"authentication": {"type": "basic"}, "tls": {"secretRef": "x"}})
    found = names(project_findings(connect))
    assert "ConfluentComponentKafkaAuthNotDeclared" in found
    assert "ConfluentComponentAuthNotDeclared" not in found


def test_connect_without_rest_authentication_is_reported():
    connect = obj(
        "Connect", {"dependencies": {"kafka": {"authentication": {"type": "mtls"}}}, "tls": {"secretRef": "x"}}
    )
    found = names(project_findings(connect))
    assert "ConfluentComponentAuthNotDeclared" in found
    assert "ConfluentComponentKafkaAuthNotDeclared" not in found


def test_kafka_rest_proxy_with_rest_auth_and_tls_block_has_no_gap_findings():
    proxy = obj("KafkaRestProxy", {"authentication": {"type": "mtls"}, "tls": {"secretRef": "x"}})
    assert names(project_findings(proxy)) == {"ConfluentComponentConfigured"}
