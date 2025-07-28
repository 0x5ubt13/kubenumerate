# CI/CD Pipeline and Version Management for Kubenumerate

## Overview

This document summarizes the complete CI/CD pipeline and version management solution implemented for Kubenumerate, providing alternatives to hardcoding versions and automating the release process.

## What Was Implemented

### 1. Dynamic Version Management System

**Files Created/Modified:**
- `version.py` - Core version management module
- `VERSION` - Version file for manual version tracking
- `kubenumerate.py` - Updated to use dynamic versioning
- `setup.py` - Package configuration with dynamic versioning
- `pyproject.toml` - Modern Python packaging configuration

**Key Features:**
- Priority-based version detection (Environment → Git → File → Package → Default)
- Git tag integration with commit information
- Environment variable override capability
- Automatic fallback to default version
- Comprehensive error handling

### 2. GitHub Actions CI/CD Pipeline

**Files Created:**
- `.github/workflows/ci.yml` - Main CI/CD pipeline
- `.github/workflows/version-bump.yml` - Automated version bumping
- `.github/workflows/release.yml` - Release automation

**Pipeline Features:**
- **Testing**: Linting, type checking, security scanning, unit tests
- **Building**: Docker image building and publishing
- **Releasing**: Automatic GitHub releases from tags
- **Security**: Trivy vulnerability scanning
- **Version Management**: Automated version bumping and tagging

### 3. Testing Infrastructure

**Files Created:**
- `tests/__init__.py` - Test package initialization
- `tests/test_version.py` - Comprehensive version management tests
- `demo_version.py` - Interactive version management demonstration

**Test Coverage:**
- All version management functions
- Priority order verification
- Environment variable handling
- Git integration testing
- Error handling scenarios

### 4. Documentation

**Files Created:**
- `VERSION_MANAGEMENT.md` - Comprehensive version management guide
- `CI_CD_SUMMARY.md` - This summary document

## Version Management Alternatives

### 1. Environment Variables (Recommended for CI/CD)
```bash
export KUBENUMERATE_VERSION="2.0.0"
python3 kubenumerate.py
```

### 2. Git Tags (Recommended for Development)
```bash
git tag -a v1.2.3 -m "Release 1.2.3"
git push origin v1.2.3
# Version automatically detected: 1.2.3-dev.5+abc123
```

### 3. VERSION File (Recommended for Manual Releases)
```bash
echo "1.2.3" > VERSION
python3 kubenumerate.py
```

### 4. Package Configuration (setup.py/pyproject.toml)
```python
# Automatically uses version.py for version detection
from version import get_version
setup(version=get_version())
```

### 5. Default Fallback
If no other source is available, defaults to `"1.3.0-dev"`

## CI/CD Workflow

### Main Pipeline (ci.yml)
**Triggers:** Push to main/develop, pull requests, tags
**Jobs:**
1. **Test**: Linting, type checking, security scanning, unit tests
2. **Build**: Docker image building (only on main/tags)
3. **Release**: GitHub release creation (only on tags)
4. **Security**: Trivy vulnerability scanning

### Version Bump Workflow (version-bump.yml)
**Triggers:** Push to main (excluding VERSION file changes)
**Actions:**
- Automatically bumps patch version
- Updates VERSION file
- Commits changes back to repository

### Release Workflow (release.yml)
**Triggers:** Push of version tags (v*)
**Actions:**
- Creates GitHub release
- Generates changelog from commits
- Uploads release assets
- Updates VERSION file

## Usage Examples

### For Development
```bash
# Version automatically detected from git
git checkout feature-branch
python3 kubenumerate.py
```

### For CI/CD
```yaml
# GitHub Actions automatically sets version
- name: Run Kubenumerate
  env:
    KUBENUMERATE_VERSION: ${{ github.ref_name }}
  run: python3 kubenumerate.py
```

### For Docker
```dockerfile
# Version can be set at build time
ARG KUBENUMERATE_VERSION
ENV KUBENUMERATE_VERSION=$KUBENUMERATE_VERSION
```

### For Manual Releases
```bash
# Update VERSION file
echo "2.0.0" > VERSION

# Create git tag
git add VERSION
git commit -m "Release version 2.0.0"
git tag -a v2.0.0 -m "Release 2.0.0"
git push origin v2.0.0
```

## Benefits

### 1. Eliminates Hardcoded Versions
- No more manual version updates in code
- Automatic version detection from multiple sources
- Consistent versioning across all environments

### 2. Automated CI/CD
- Automated testing on every change
- Automated building and publishing
- Automated release creation
- Security scanning integration

### 3. Flexible Version Management
- Multiple version sources supported
- Environment-specific versioning
- Git integration for development
- Manual override capability

### 4. Improved Developer Experience
- Clear version priority system
- Comprehensive documentation
- Interactive demonstration tools
- Extensive test coverage

## Setup Instructions

### 1. Enable GitHub Actions
- Push the workflow files to your repository
- Configure required secrets (DOCKER_USERNAME, DOCKER_PASSWORD)
- Enable GitHub Actions in repository settings

### 2. Configure Version Management
- Choose your preferred version management strategy
- Set up git tags for releases
- Configure environment variables in CI/CD

### 3. Test the System
```bash
# Run the demonstration
python3 demo_version.py

# Test version detection
python3 version.py

# Test Kubenumerate integration
python3 -c "from kubenumerate import Kubenumerate; print(Kubenumerate().version)"
```

### 4. Run Tests
```bash
# Install test dependencies
pip install pytest pytest-cov

# Run version tests
pytest tests/test_version.py -v
```

## Migration from Hardcoded Version

### Before
```python
def __init__(self, ..., version="1.3.0-dev", ...):
    self.version = version
```

### After
```python
def __init__(self, ..., version=None, ...):
    self.version = version if version is not None else get_version()
```

## Next Steps

1. **Configure GitHub Secrets**: Set up DOCKER_USERNAME and DOCKER_PASSWORD
2. **Choose Version Strategy**: Decide on your preferred version management approach
3. **Test Pipeline**: Push changes to trigger the CI/CD pipeline
4. **Create First Release**: Tag a release to test the release workflow
5. **Customize**: Modify workflows and version management as needed

## Troubleshooting

### Version Not Updating
- Check priority order in version.py
- Verify environment variable is set correctly
- Ensure git repository is available
- Check VERSION file exists and is readable

### CI/CD Issues
- Verify GitHub Actions are enabled
- Check secret configuration
- Review workflow permissions
- Check for syntax errors in YAML files

### Git Integration Issues
- Ensure git is installed and accessible
- Verify repository has tags
- Check git command permissions

## Conclusion

This implementation provides a comprehensive solution for version management and CI/CD automation for Kubenumerate. The system is flexible, well-tested, and follows best practices for modern Python projects. The priority-based version detection ensures compatibility with various deployment scenarios while maintaining simplicity and reliability. 