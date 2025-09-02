#!/usr/bin/env python3
"""
Tests for version management functionality
"""

import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

# Import the version module
try:
    from version import (
        get_version,
        get_version_from_env,
        get_version_from_file,
        get_version_from_git,
        get_version_from_git_commit,
        update_version_file,
        create_git_tag
    )
except ImportError:
    # If version module is not available, skip tests
    pytest.skip("version module not available", allow_module_level=True)


class TestVersionManagement:
    """Test cases for version management functions"""

    def test_get_version_from_env(self):
        """Test getting version from environment variable"""
        with patch.dict(os.environ, {'KUBENUMERATE_VERSION': '2.0.0'}):
            assert get_version_from_env() == '2.0.0'
        
        with patch.dict(os.environ, {}, clear=True):
            assert get_version_from_env() is None

    def test_get_version_from_file(self):
        """Test getting version from VERSION file"""
        with tempfile.TemporaryDirectory() as temp_dir:
            version_file = Path(temp_dir) / "VERSION"
            version_file.write_text("1.2.3\n")
            
            with patch('version.Path') as mock_path:
                mock_path.return_value.parent = Path(temp_dir)
                assert get_version_from_file() == "1.2.3"

    def test_get_version_from_file_not_exists(self):
        """Test getting version when VERSION file doesn't exist"""
        with patch('version.Path') as mock_path:
            mock_path.return_value.parent = Path("/nonexistent")
            assert get_version_from_file() is None

    @patch('subprocess.run')
    def test_get_version_from_git_success(self, mock_run):
        """Test getting version from git tags successfully"""
        mock_result = MagicMock()
        mock_result.stdout = "v1.2.3\n"
        mock_run.return_value = mock_result
        
        assert get_version_from_git() == "1.2.3"

    @patch('subprocess.run')
    def test_get_version_from_git_failure(self, mock_run):
        """Test getting version from git when it fails"""
        mock_run.side_effect = FileNotFoundError()
        assert get_version_from_git() is None

    @patch('subprocess.run')
    def test_get_version_from_git_commit_success(self, mock_run):
        """Test getting version from git commit successfully"""
        # Mock the three git commands
        mock_run.side_effect = [
            MagicMock(stdout="v1.2.3\n"),  # git describe --tags --abbrev=0
            MagicMock(stdout="0\n"),       # git rev-list --count
            MagicMock(stdout="abc123\n")   # git rev-parse --short HEAD
        ]
        
        assert get_version_from_git_commit() == "1.2.3"

    @patch('subprocess.run')
    def test_get_version_from_git_commit_with_dev(self, mock_run):
        """Test getting version from git commit with dev suffix"""
        # Mock the three git commands
        mock_run.side_effect = [
            MagicMock(stdout="v1.2.3\n"),  # git describe --tags --abbrev=0
            MagicMock(stdout="5\n"),       # git rev-list --count
            MagicMock(stdout="abc123\n")   # git rev-parse --short HEAD
        ]
        
        assert get_version_from_git_commit() == "1.2.4"

    def test_get_version_priority(self):
        """Test version priority order"""
        with patch('version.get_version_from_env', return_value='2.0.0'), \
             patch('version.get_version_from_git_commit', return_value='1.2.3'), \
             patch('version.get_version_from_file', return_value='1.1.0'), \
             patch('version.get_version_from_setup', return_value='1.0.0'):
            
            assert get_version() == '2.0.0'  # Environment should take priority

    def test_get_version_fallback(self):
        """Test version fallback to default"""
        with patch('version.get_version_from_env', return_value=None), \
             patch('version.get_version_from_git_commit', return_value=None), \
             patch('version.get_version_from_file', return_value=None), \
             patch('version.get_version_from_setup', return_value=None):
            
            assert get_version() == '2.0.0'  # Default fallback

    def test_update_version_file(self):
        """Test updating VERSION file"""
        with tempfile.TemporaryDirectory() as temp_dir:
            version_file = Path(temp_dir) / "VERSION"
            
            with patch('version.Path') as mock_path:
                mock_path.return_value.parent = Path(temp_dir)
                update_version_file("2.0.0")
                
                assert version_file.read_text().strip() == "2.0.0"

    @patch('subprocess.run')
    def test_create_git_tag_success(self, mock_run):
        """Test creating git tag successfully"""
        create_git_tag("2.0.0", "Test release")
        
        mock_run.assert_called_once_with(
            ["git", "tag", "-a", "v2.0.0", "-m", "Test release"],
            check=True
        )

    @patch('subprocess.run')
    def test_create_git_tag_failure(self, mock_run):
        """Test creating git tag when it fails"""
        mock_run.side_effect = subprocess.CalledProcessError(1, "git tag")
        
        # Should not raise an exception, just print error
        create_git_tag("2.0.0")


class TestVersionIntegration:
    """Integration tests for version management"""

    def test_version_import_in_kubenumerate(self):
        """Test that Kubenumerate can import and use version management"""
        try:
            from kubenumerate import Kubenumerate
            k = Kubenumerate()
            assert hasattr(k, 'version')
            assert isinstance(k.version, str)
            assert len(k.version) > 0
        except ImportError:
            pytest.skip("kubenumerate module not available")

    def test_version_file_exists(self):
        """Test that VERSION file exists and is readable"""
        version_file = Path("VERSION")
        assert version_file.exists()
        version = version_file.read_text().strip()
        assert len(version) > 0
        assert "." in version  # Should contain version numbers 