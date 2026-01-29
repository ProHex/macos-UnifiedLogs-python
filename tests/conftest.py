# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Pytest fixtures for macOS Unified Logs tests."""

import os
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from macos_unifiedlogs import (
    LogarchiveProvider,
    LogData,
    UnifiedLogData,
    collect_strings,
    collect_shared_strings,
    collect_timesync,
    parse_log,
    build_log,
)
from macos_unifiedlogs.timesync import TimesyncBoot


def get_test_data_path() -> Path:
    """Get the path to the test_data directory."""
    # Try relative to this file first
    tests_dir = Path(__file__).parent

    # Go up to the repository root and into tests/test_data
    repo_root = tests_dir.parent.parent
    test_data = repo_root / "tests" / "test_data"

    if test_data.exists():
        return test_data

    # Also check if there's a test_data in the python tests directory
    python_test_data = tests_dir / "test_data"
    if python_test_data.exists():
        return python_test_data

    return test_data  # Return expected path even if it doesn't exist


@pytest.fixture
def test_data_path() -> Path:
    """Fixture providing the path to test data."""
    return get_test_data_path()


@pytest.fixture
def big_sur_logarchive_path(test_data_path: Path) -> Optional[Path]:
    """Fixture providing the path to Big Sur logarchive."""
    path = test_data_path / "system_logs_big_sur.logarchive"
    if path.exists():
        return path
    return None


@pytest.fixture
def big_sur_private_logarchive_path(test_data_path: Path) -> Optional[Path]:
    """Fixture providing the path to Big Sur private-enabled logarchive."""
    path = test_data_path / "system_logs_big_sur_private_enabled.logarchive"
    if path.exists():
        return path
    return None


@pytest.fixture
def big_sur_public_private_mix_path(test_data_path: Path) -> Optional[Path]:
    """Fixture providing the path to Big Sur public/private mix logarchive."""
    path = test_data_path / "system_logs_big_sur_public_private_data_mix.logarchive"
    if path.exists():
        return path
    return None


@pytest.fixture
def high_sierra_logarchive_path(test_data_path: Path) -> Optional[Path]:
    """Fixture providing the path to High Sierra logarchive."""
    path = test_data_path / "system_logs_high_sierra.logarchive"
    if path.exists():
        return path
    return None


@pytest.fixture
def monterey_logarchive_path(test_data_path: Path) -> Optional[Path]:
    """Fixture providing the path to Monterey logarchive."""
    path = test_data_path / "system_logs_monterey.logarchive"
    if path.exists():
        return path
    return None


def collect_logs(provider: LogarchiveProvider) -> List[UnifiedLogData]:
    """Collect all logs from a provider."""
    logs = []
    for source_file in provider.tracev3_files():
        with source_file.reader() as reader:
            _, log_data = parse_log(reader)
            logs.append(log_data)
    return logs


def is_signpost(log_type) -> bool:
    """Check if a log type is a signpost type."""
    from macos_unifiedlogs import LogType

    signpost_types = {
        LogType.ProcessSignpostEvent,
        LogType.ProcessSignpostStart,
        LogType.ProcessSignpostEnd,
        LogType.SystemSignpostEvent,
        LogType.SystemSignpostStart,
        LogType.SystemSignpostEnd,
        LogType.ThreadSignpostEvent,
        LogType.ThreadSignpostStart,
        LogType.ThreadSignpostEnd,
    }
    return log_type in signpost_types


def skip_if_no_test_data(path: Optional[Path], test_name: str):
    """Skip test if test data is not available."""
    if path is None or not path.exists():
        pytest.skip(f"Test data not available for {test_name}")
