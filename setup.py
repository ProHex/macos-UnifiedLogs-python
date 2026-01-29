#!/usr/bin/env python3
# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0

"""Setup script for macos-unifiedlogs."""

from setuptools import setup, find_packages

setup(
    name="macos-unifiedlogs",
    version="0.1.0",
    description="Parse macOS Unified Log format (tracev3 files)",
    author="Aria Akhavan",
    license="Apache-2.0",
    packages=find_packages(include=["macos_unifiedlogs", "macos_unifiedlogs.*"]),
    python_requires=">=3.9",
    install_requires=[
        "lz4>=4.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
    },
)
