#!/usr/bin/env python3
"""
Version management for Kubenumerate.
Provides multiple ways to handle versioning dynamically.
"""

import os
import subprocess
import re
from pathlib import Path
from typing import Optional


def get_version_from_git() -> Optional[str]:
    """Get version from git tags."""
    try:
        # Get the latest tag
        result = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True,
            text=True,
            check=True
        )
        version = result.stdout.strip()
        # Remove 'v' prefix if present
        if version.startswith('v'):
            version = version[1:]
        return version
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def get_version_from_git_commit() -> Optional[str]:
    """Get version from git commit hash and tag."""
    try:
        # Get the latest tag
        tag_result = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True,
            text=True,
            check=True
        )
        tag = tag_result.stdout.strip()
        
        # Get commit count since tag
        count_result = subprocess.run(
            ["git", "rev-list", "--count", f"{tag}..HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
        count = count_result.stdout.strip()
        
        # Get short commit hash
        hash_result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
        commit_hash = hash_result.stdout.strip()
        
        # Remove 'v' prefix from tag
        if tag.startswith('v'):
            tag = tag[1:]
        
        if count == "0":
            return tag
        else:
            return f"{tag}-dev.{count}+{commit_hash}"
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def get_version_from_env() -> Optional[str]:
    """Get version from environment variable."""
    return os.environ.get('KUBENUMERATE_VERSION')


def get_version_from_file() -> Optional[str]:
    """Get version from VERSION file."""
    version_file = Path(__file__).parent / "VERSION"
    if version_file.exists():
        return version_file.read_text().strip()
    return None


def get_version_from_setup() -> Optional[str]:
    """Get version from setup.py or pyproject.toml."""
    # Check for setup.py
    setup_file = Path(__file__).parent / "setup.py"
    if setup_file.exists():
        try:
            with open(setup_file, 'r') as f:
                content = f.read()
                match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                if match:
                    return match.group(1)
        except Exception:
            pass
    
    # Check for pyproject.toml
    pyproject_file = Path(__file__).parent / "pyproject.toml"
    if pyproject_file.exists():
        try:
            with open(pyproject_file, 'r') as f:
                content = f.read()
                match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                if match:
                    return match.group(1)
        except Exception:
            pass
    
    return None


def get_version() -> str:
    """
    Get version using the following priority:
    1. Environment variable KUBENUMERATE_VERSION
    2. Git tag with commit info
    3. VERSION file
    4. setup.py/pyproject.toml
    5. Default fallback
    """
    # Try environment variable first
    version = get_version_from_env()
    if version:
        return version
    
    # Try git-based versioning
    version = get_version_from_git_commit()
    if version:
        return version
    
    # Try VERSION file
    version = get_version_from_file()
    if version:
        return version
    
    # Try setup.py/pyproject.toml
    version = get_version_from_setup()
    if version:
        return version
    
    # Default fallback
    return "1.3.0-dev"


def update_version_file(version: str) -> None:
    """Update the VERSION file with the given version."""
    version_file = Path(__file__).parent / "VERSION"
    version_file.write_text(version + "\n")


def create_git_tag(version: str, message: str = None) -> None:
    """Create a git tag for the given version."""
    if not message:
        message = f"Release version {version}"
    
    try:
        subprocess.run(["git", "tag", "-a", f"v{version}", "-m", message], check=True)
        print(f"Created git tag: v{version}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to create git tag: {e}")


if __name__ == "__main__":
    print(get_version()) 