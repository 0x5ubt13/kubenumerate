#!/usr/bin/env python3
"""
Demonstration script for Kubenumerate version management
"""

import os
import subprocess
from pathlib import Path

def print_separator(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def demo_version_management():
    """Demonstrate all version management options"""
    
    print_separator("KUBENUMERATE VERSION MANAGEMENT DEMO")
    
    # Import version functions
    try:
        from version import (
            get_version,
            get_version_from_env,
            get_version_from_file,
            get_version_from_git,
            get_version_from_git_commit,
            get_version_from_setup
        )
        from kubenumerate import Kubenumerate
    except ImportError as e:
        print(f"Error importing modules: {e}")
        return
    
    print("\n1. CURRENT VERSION DETECTION")
    print("-" * 40)
    
    # Show current version from each source
    print(f"Environment variable: {get_version_from_env() or 'Not set'}")
    print(f"Git tag: {get_version_from_git() or 'Not available'}")
    print(f"Git commit: {get_version_from_git_commit() or 'Not available'}")
    print(f"VERSION file: {get_version_from_file() or 'Not found'}")
    print(f"setup.py/pyproject.toml: {get_version_from_setup() or 'Not found'}")
    print(f"Final version (priority): {get_version()}")
    print(f"Kubenumerate instance: {Kubenumerate().version}")
    
    print("\n2. ENVIRONMENT VARIABLE OVERRIDE")
    print("-" * 40)
    
    # Test environment variable override
    test_version = "2.0.0-demo"
    os.environ['KUBENUMERATE_VERSION'] = test_version
    
    print(f"Setting KUBENUMERATE_VERSION={test_version}")
    print(f"Environment version: {get_version_from_env()}")
    print(f"Final version: {get_version()}")
    print(f"Kubenumerate instance: {Kubenumerate().version}")
    
    # Clean up
    if 'KUBENUMERATE_VERSION' in os.environ:
        del os.environ['KUBENUMERATE_VERSION']
    
    print("\n3. VERSION FILE DEMO")
    print("-" * 40)
    
    # Test VERSION file
    version_file = Path("VERSION")
    if version_file.exists():
        current_version = version_file.read_text().strip()
        print(f"Current VERSION file content: {current_version}")
        
        # Test updating VERSION file
        try:
            from version import update_version_file
            test_version = "1.5.0-demo"
            print(f"Updating VERSION file to: {test_version}")
            update_version_file(test_version)
            print(f"Updated VERSION file content: {version_file.read_text().strip()}")
            
            # Restore original version
            update_version_file(current_version)
            print(f"Restored VERSION file to: {current_version}")
        except Exception as e:
            print(f"Error updating VERSION file: {e}")
    
    print("\n4. GIT VERSIONING DEMO")
    print("-" * 40)
    
    # Show git information
    try:
        # Get current branch
        branch = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
        print(f"Current branch: {branch}")
        
        # Get latest tag
        try:
            latest_tag = subprocess.run(
                ["git", "describe", "--tags", "--abbrev=0"],
                capture_output=True, text=True, check=True
            ).stdout.strip()
            print(f"Latest tag: {latest_tag}")
        except subprocess.CalledProcessError:
            print("No tags found")
        
        # Get commit count since tag
        try:
            commit_count = subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                capture_output=True, text=True, check=True
            ).stdout.strip()
            print(f"Total commits: {commit_count}")
        except subprocess.CalledProcessError:
            print("Could not get commit count")
        
        # Get short commit hash
        try:
            commit_hash = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, check=True
            ).stdout.strip()
            print(f"Current commit: {commit_hash}")
        except subprocess.CalledProcessError:
            print("Could not get commit hash")
            
    except FileNotFoundError:
        print("Git not available")
    except Exception as e:
        print(f"Error getting git info: {e}")
    
    print("\n5. CI/CD INTEGRATION EXAMPLES")
    print("-" * 40)
    
    print("GitHub Actions environment variable:")
    print("  env:")
    print("    KUBENUMERATE_VERSION: ${{ github.ref_name }}")
    
    print("\nDocker build with version:")
    print("  ARG KUBENUMERATE_VERSION")
    print("  ENV KUBENUMERATE_VERSION=$KUBENUMERATE_VERSION")
    
    print("\nManual version setting:")
    print("  export KUBENUMERATE_VERSION='2.0.0'")
    print("  python3 kubenumerate.py")
    
    print("\n6. VERSION PRIORITY ORDER")
    print("-" * 40)
    print("1. Environment variable (KUBENUMERATE_VERSION)")
    print("2. Git tags with commit info")
    print("3. VERSION file")
    print("4. setup.py/pyproject.toml")
    print("5. Default fallback (1.3.0-dev)")
    
    print("\n7. USAGE RECOMMENDATIONS")
    print("-" * 40)
    print("• Development: Use git tags (automatic)")
    print("• CI/CD: Use environment variables")
    print("• Releases: Use VERSION file + git tags")
    print("• Docker: Use build args + environment variables")
    print("• Testing: Use environment variables for specific versions")

if __name__ == "__main__":
    demo_version_management() 