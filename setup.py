#!/usr/bin/env python3
"""
Setup script for Automated Compliance Scanner
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="compliance-scanner",
    version="1.0.0",
    author="Rayshaun Smith",
    author_email="RaySmith414@users.noreply.github.com",
    description="Automated security compliance scanner for CIS Benchmarks with NIST 800-53 mapping",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/RaySmith414/Automated-Compliance-Scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "compliance-scanner=scanner.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["config/*.yaml", "reports/templates/*.html"],
    },
)
