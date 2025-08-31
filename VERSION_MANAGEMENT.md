# Version Management for Kubenumerate

This document explains the various alternatives to hardcoding the version in Kubenumerate and how to use them.

## Overview

Kubenumerate now supports multiple version management strategies, eliminating the need to hardcode versions in the source code. The version is determined using a priority-based system:

1. **Environment Variable** (highest priority)
2. **Git Tags with Commit Info**
3. **VERSION File**
4. **setup.py/pyproject.toml**
5. **Default Fallback** (lowest priority)

## Version Management Alternatives

### 1. Environment Variable

**Priority**: Highest
**Use Case**: CI/CD pipelines, container deployments, development environments

Set the `KUBENUMERATE_VERSION` environment variable:

```bash
export KUBENUMERATE_VERSION="2.0.0"
python kubenumerate.py
```

**In CI/CD (GitHub Actions)**:
```yaml
env:
  KUBENUMERATE_VERSION: ${{ github.ref_name }}
```

**In Docker**:
```dockerfile
ENV KUBENUMERATE_VERSION="2.0.0"
```

**Advantages**:
- Override version without code changes
- Perfect for CI/CD pipelines
- Environment-specific versioning
- No git repository required

### 2. Git Tags with Commit Info

**Priority**: High
**Use Case**: Development builds, release candidates

The system automatically detects git tags and creates version strings like:
- `1.2.3` (exact tag match)
- `1.2.3-dev.5+abc123` (tag + commit count + hash)

**Setup**:
```bash
# Create a tag
git tag -a v1.2.3 -m "Release 1.2.3"
git push origin v1.2.3

# The version will automatically be detected
python kubenumerate.py
```

**Advantages**:
- Automatic version tracking
- Includes commit information
- Works with git workflows
- No manual version file updates

### 3. VERSION File

**Priority**: Medium
**Use Case**: Simple version tracking, manual releases

Create a `VERSION` file in the project root:

```bash
echo "1.2.3" > VERSION
```

**Update programmatically**:
```python
from version import update_version_file
update_version_file("2.0.0")
```

**Advantages**:
- Simple and explicit
- Version visible in repository
- Easy to update
- Works without git

### 4. setup.py/pyproject.toml

**Priority**: Low
**Use Case**: Package distribution, PyPI releases

**setup.py**:
```python
from version import get_version

setup(
    name="kubenumerate",
    version=get_version(),
    # ... other configuration
)
```

**pyproject.toml**:
```toml
[project]
name = "kubenumerate"
dynamic = ["version"]

[tool.setuptools.dynamic]
version = {attr = "version.get_version"}
```

**Advantages**:
- Standard Python packaging
- PyPI integration
- Build system integration

### 5. Default Fallback

**Priority**: Lowest
**Use Case**: Emergency fallback

If no other version source is available, the system falls back to `"2.0.0"`.

## CI/CD Integration

### GitHub Actions Workflow

The provided CI/CD pipeline automatically handles version management:

1. **Version Bump Workflow** (`.github/workflows/version-bump.yml`):
   - Automatically bumps patch version on main branch commits
   - Updates VERSION file
   - Commits changes back to repository

2. **Release Workflow** (`.github/workflows/release.yml`):
   - Creates GitHub releases from tags
   - Generates changelog automatically
   - Uploads release assets

3. **Main CI Pipeline** (`.github/workflows/ci.yml`):
   - Tests version management
   - Builds Docker images with correct versions
   - Runs security scans

### Usage Examples

**For Development**:
```bash
# Version will be automatically detected from git
git checkout feature-branch
python kubenumerate.py  # Uses git-based versioning
```

**For CI/CD**:
```yaml
# GitHub Actions automatically sets version
- name: Run Kubenumerate
  env:
    KUBENUMERATE_VERSION: ${{ github.ref_name }}
  run: python kubenumerate.py
```

**For Docker**:
```dockerfile
# Version can be set at build time
ARG KUBENUMERATE_VERSION
ENV KUBENUMERATE_VERSION=$KUBENUMERATE_VERSION
```

**For Manual Releases**:
```bash
# Update VERSION file
echo "2.0.0" > VERSION

# Create git tag
git add VERSION
git commit -m "Release version 2.0.0"
git tag -a v2.0.0 -m "Release 2.0.0"
git push origin v2.0.0
```

## Version Format

The system supports semantic versioning (SemVer) format:
- `MAJOR.MINOR.PATCH` (e.g., `1.2.3`)
- `MAJOR.MINOR.PATCH-dev.COUNT+HASH` (e.g., `1.2.3-dev.5+abc123`)
- `MAJOR.MINOR.PATCH-rc.1` (e.g., `1.2.3-rc.1`)

## Migration from Hardcoded Version

To migrate from hardcoded version:

1. **Remove hardcoded version**:
   ```python
   # Before
   version="1.3.0-dev"
   
   # After
   version=None  # Will use dynamic versioning
   ```

2. **Choose your preferred method**:
   - For CI/CD: Use environment variables
   - For development: Use git tags
   - For releases: Use VERSION file

3. **Update your workflow**:
   - Set up git tags for releases
   - Configure CI/CD environment variables
   - Update documentation

## Testing Version Management

Run the provided tests to verify version management:

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run version tests
pytest tests/test_version.py -v

# Test version detection
python version.py
python -c "from kubenumerate import Kubenumerate; print(Kubenumerate().version)"
```

## Troubleshooting

**Version not updating**:
1. Check priority order
2. Verify environment variable is set correctly
3. Ensure git repository is available
4. Check VERSION file exists and is readable

**Git-based versioning not working**:
1. Ensure git is installed
2. Check repository has tags
3. Verify git commands work manually

**CI/CD version issues**:
1. Check environment variable syntax
2. Verify workflow permissions
3. Check secret configuration

## Best Practices

1. **Use git tags for releases**: Always tag releases with semantic versions
2. **Environment variables for CI/CD**: Set version explicitly in pipelines
3. **VERSION file for manual releases**: Keep it updated for manual releases
4. **Test version detection**: Include version tests in your test suite
5. **Document version strategy**: Choose and document your preferred approach

## Configuration

The version management system can be configured by modifying `version.py`:

- Change priority order
- Add new version sources
- Modify version format
- Add custom version logic

For example, to add a new version source:

```python
def get_version_from_custom_source():
    # Your custom logic here
    return "custom-version"

def get_version():
    # Add your source to the priority list
    version = get_version_from_custom_source()
    if version:
        return version
    # ... rest of priority chain
``` 