#!/usr/bin/env python3
"""
Simple test to verify summary_table module logic without requiring python-docx.
Tests the aggregation and formatting functions.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pandas as pd
from typing import List, Any

# Import only the non-docx dependent functions
import summary_table

def test_human_readable_issue_names():
    """Test that technical issue names are correctly mapped to human-readable versions."""
    print("Testing human-readable issue name mapping...")
    
    test_cases = {
        "PrivilegedTrue": "Running as privileged",
        "AppArmorNotSet": "AppArmor profile not set",
        "UnknownIssue": "UnknownIssue",  # Should return original if not mapped
    }
    
    for technical, expected in test_cases.items():
        result = summary_table._get_human_readable_issue_name(technical)
        assert result == expected, f"Expected '{expected}', got '{result}'"
        print(f"  ✓ {technical} -> {result}")
    
    print("✓ All issue name mappings passed!\n")


def test_aggregate_issues():
    """Test issue aggregation by workload."""
    print("Testing issue aggregation...")
    
    # Create sample findings DataFrame
    findings_data = [
        {
            "AuditResultName": "PrivilegedTrue",
            "ResourceNamespace": "default",
            "ResourceKind": "Deployment",
            "ResourceName": "nginx",
            "Container": "nginx-container",
        },
        {
            "AuditResultName": "AppArmorNotSet",
            "ResourceNamespace": "default",
            "ResourceKind": "Deployment",
            "ResourceName": "nginx",
            "Container": "nginx-container",
        },
        {
            "AuditResultName": "PrivilegedTrue",
            "ResourceNamespace": "kube-system",
            "ResourceKind": "DaemonSet",
            "ResourceName": "kube-proxy",
            "Container": "kube-proxy",
        },
        {
            "AuditResultName": "RunAsUserCSCRoot",
            "ResourceNamespace": "default",
            "ResourceKind": "Pod",  # Should be filtered out
            "ResourceName": "standalone-pod",
            "Container": "container",
        },
    ]
    
    # Add all required columns for the DataFrame
    columns = [
        "AuditResultName", "ResourceNamespace", "ResourceKind", "ResourceName",
        "Container", "AnnotationValue", "MissingAnnotation", "Metadata",
        "IntroducedMajor", "IntroducedMinor", "DeprecatedMajor", "DeprecatedMinor",
        "RemovedMajor", "RemovedMinor", "ResourceApiVersion",
        "MountName", "MountPath", "MountReadOnly", "MountVolume", "MountVolumeHostPath", "msg"
    ]
    
    findings_df = pd.DataFrame(findings_data, columns=columns)
    
    # Create sample trivy results
    trivy_results: List[List[Any]] = [
        ["default", "nginx:latest", "nginx-12345-abcde", "nginx-container", 2, ["CVE-1", "CVE-2"], 5, ["CVE-3", "CVE-4", "CVE-5", "CVE-6", "CVE-7"]],
    ]
    
    # Run aggregation
    result = summary_table.aggregate_issues_by_workload(findings_df, trivy_results, verbosity=2)
    
    # Verify results
    print(f"  Found {len(result)} workloads with issues")
    
    # Should have 2 workloads (Deployment and DaemonSet, Pod excluded)
    assert len(result) == 2, f"Expected 2 workloads, got {len(result)}"
    print("  ✓ Correct number of workloads (Pods filtered out)")
    
    # Check nginx deployment
    nginx_key = ("default", "Deployment", "nginx")
    assert nginx_key in result, "nginx Deployment not found in results"
    nginx_issues = result[nginx_key]
    assert nginx_issues["issue_count"] >= 2, f"Expected at least 2 issues for nginx, got {nginx_issues['issue_count']}"
    print(f"  ✓ nginx Deployment has {nginx_issues['issue_count']} issues")
    print(f"    Issues: {nginx_issues['issues']}")
    
    # Check kube-proxy daemonset
    proxy_key = ("kube-system", "DaemonSet", "kube-proxy")
    assert proxy_key in result, "kube-proxy DaemonSet not found in results"
    proxy_issues = result[proxy_key]
    assert proxy_issues["issue_count"] >= 1, f"Expected at least 1 issue for kube-proxy"
    print(f"  ✓ kube-proxy DaemonSet has {proxy_issues['issue_count']} issues")
    print(f"    Issues: {proxy_issues['issues']}")
    
    # Verify Pod was filtered out
    pod_key = ("default", "Pod", "standalone-pod")
    assert pod_key not in result, "Pod should have been filtered out but wasn't"
    print("  ✓ Standalone Pod correctly filtered out")
    
    print("✓ Issue aggregation test passed!\n")


def test_format_issues_list():
    """Test issue list formatting."""
    print("Testing issue list formatting...")
    
    # Test with few issues
    issues = ["Issue 1", "Issue 2", "Issue 3"]
    formatted = summary_table.format_issues_list(issues)
    assert "Issue 1" in formatted
    assert "Issue 2" in formatted
    assert "Issue 3" in formatted
    print(f"  ✓ Short list formatted correctly:\n{formatted}\n")
    
    # Test with many issues (should truncate)
    many_issues = [f"Issue {i}" for i in range(1, 16)]
    formatted_many = summary_table.format_issues_list(many_issues, max_items=10)
    assert "and 5 more issues" in formatted_many or "and 5 more" in formatted_many.lower()
    print(f"  ✓ Long list truncated correctly")
    
    # Test with empty list
    empty_formatted = summary_table.format_issues_list([])
    assert "No issues" in empty_formatted
    print(f"  ✓ Empty list handled correctly: {empty_formatted}")
    
    print("✓ Issue formatting test passed!\n")


if __name__ == "__main__":
    print("=" * 60)
    print("Running summary_table module tests")
    print("=" * 60 + "\n")
    
    try:
        test_human_readable_issue_names()
        test_aggregate_issues()
        test_format_issues_list()
        
        print("=" * 60)
        print("✓ All tests passed successfully!")
        print("=" * 60)
        print("\nNote: To test Word document generation, install python-docx:")
        print("  pip install python-docx")
        print("Then run kubenumerate with --summary-word flag")
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
