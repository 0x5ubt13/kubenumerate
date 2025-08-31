#!/usr/bin/env python3
"""
Setup script for Kubenumerate
"""

from setuptools import setup, find_packages
import os

# Import version management
try:
    from version import get_version
except ImportError:
    def get_version():
        return "2.0.0"

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="kubenumerate",
    version=get_version(),
    author="Subtle",
    author_email="5ubt13@protonmail.com",
    description="A comprehensive Kubernetes security auditing tool",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/0x5ubt13/kubenumerate",
    py_modules=["kubenumerate", "ExtensiveRoleCheck", "formatter", "version"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.12",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "flake8>=5.0.0",
            "black>=22.0.0",
            "mypy>=1.0.0",
            "bandit>=1.7.0",
            "safety>=2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "kubenumerate=kubenumerate:main",
        ],
    },
    keywords="kubernetes security audit compliance cis",
    project_urls={
        "Bug Reports": "https://github.com/0x5ubt13/kubenumerate/issues",
        "Source": "https://github.com/0x5ubt13/kubenumerate",
        "Documentation": "https://github.com/0x5ubt13/kubenumerate#readme",
    },
) 