# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Integration tests for Monterey logs."""

import re
from pathlib import Path
from typing import Optional

import pytest

from macos_unifiedlogs import (
    EventType,
    LogarchiveProvider,
    LogData,
    LogType,
    build_log,
    collect_timesync,
    parse_log,
)

from .conftest import collect_logs, skip_if_no_test_data


class TestMonterey:
    """Test parsing Monterey log archives."""

    def test_parse_log_monterey(self, monterey_logarchive_path: Optional[Path]):
        """Test parsing a single tracev3 file from Monterey."""
        skip_if_no_test_data(monterey_logarchive_path, "Monterey")

        test_path = monterey_logarchive_path / "Persist" / "000000000000000a.tracev3"

        with open(test_path, "rb") as handle:
            _, log_data = parse_log(handle)

        assert len(log_data.catalog_data[0].firehose) == 17
        assert len(log_data.catalog_data[0].simpledump) == 383
        assert len(log_data.header) == 1
        assert len(log_data.catalog_data[0].catalog.catalog_process_info_entries) == 17
        assert len(log_data.catalog_data[0].statedump) == 0

    def test_build_log_monterey(self, monterey_logarchive_path: Optional[Path]):
        """Test building logs from Monterey tracev3 file."""
        skip_if_no_test_data(monterey_logarchive_path, "Monterey")

        provider = LogarchiveProvider(str(monterey_logarchive_path))
        timesync_data = collect_timesync(provider)

        test_path = monterey_logarchive_path / "Persist" / "000000000000000a.tracev3"

        with open(test_path, "rb") as handle:
            _, log_data = parse_log(handle)

        exclude_missing = False
        results, _ = build_log(log_data, provider, timesync_data, exclude_missing)

        assert len(results) == 322859
        assert results[0].process == "/kernel"
        assert results[0].subsystem == ""
        assert results[0].time == 1651345928766719209.0
        assert results[0].activity_id == 0
        assert results[0].library == "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox"
        assert results[0].message == "2 duplicate reports for Sandbox: MTLCompilerServi(187) deny(1) file-read-metadata /private"
        assert results[0].pid == 0
        assert results[0].thread_id == 2241
        assert results[0].category == ""
        assert results[0].log_type == LogType.Error
        assert results[0].event_type == EventType.Log
        assert results[0].euid == 0
        assert results[0].boot_uuid == "17AB576950394796B7F3CD2C157F4A2F"
        assert results[0].timezone_name == "New_York"
        assert results[0].library_uuid == "7EFAFB8B6CA63090957FC68A6230BC38"
        assert results[0].process_uuid == "C342869FFFB93CCEA5A3EA711C1E87F6"
        assert results[0].raw_message == "%s"

    def test_parse_all_logs_monterey(self, monterey_logarchive_path: Optional[Path]):
        """Test parsing all logs from Monterey logarchive."""
        skip_if_no_test_data(monterey_logarchive_path, "Monterey")

        provider = LogarchiveProvider(str(monterey_logarchive_path))
        timesync_data = collect_timesync(provider)
        log_data = collect_logs(provider)

        log_data_vec = []
        exclude_missing = False
        message_re = re.compile(r"^[\s]*%s\s*$")

        for logs in log_data:
            data, _ = build_log(logs, provider, timesync_data, exclude_missing)
            log_data_vec.extend(data)

        assert len(log_data_vec) == 2397109

        unknown_strings = 0
        invalid_offsets = 0
        invalid_shared_string_offsets = 0
        statedump_custom_objects = 0
        statedump_protocol_buffer = 0
        string_count = 0

        mutilities_worldclock = 0
        mutilities_return = 0
        location_tracker = 0
        pauses_tracker = 0
        dns_counts = 0

        for logs in log_data_vec:
            if ("Failed to get string message from " in logs.message or
                    "Unknown shared string message" in logs.message):
                unknown_strings += 1

            if "Error: Invalid offset " in logs.message:
                invalid_offsets += 1

            if "Error: Invalid shared string offset" in logs.message:
                invalid_shared_string_offsets += 1

            if "Unsupported Statedump object" in logs.message:
                statedump_custom_objects += 1

            if ("Failed to parse StateDump protobuf" in logs.message or
                    "Failed to serialize Protobuf HashMap" in logs.message):
                statedump_protocol_buffer += 1

            if message_re.match(logs.raw_message):
                string_count += 1

            if ("MTUtilities: WorldClockWidget:" in logs.message and
                    logs.log_type == LogType.Default):
                mutilities_worldclock += 1

            if "MTUtilities: Returning widget" in logs.message:
                mutilities_return += 1

            if "allowsMapCorrection" in logs.message:
                location_tracker += 1

            if '"pausesLocationUpdatesAutomatically":1,' in logs.message:
                pauses_tracker += 1

            if "Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0" in logs.message:
                dns_counts += 1

        assert unknown_strings == 531
        assert invalid_offsets == 60
        assert invalid_shared_string_offsets == 309
        assert statedump_custom_objects == 0
        assert statedump_protocol_buffer == 0

        # Accurate count based on log raw-dump -a <monterey.logarchive> | grep "format:\s*%s$" | sort | uniq -c | sort -n
        assert string_count == 28196
        assert mutilities_worldclock == 57
        assert mutilities_return == 71
        assert dns_counts == 3196

        assert location_tracker == 298
        # Accurate count based on log raw-dump -A tests/test_data/system_logs_monterey.logarchive | grep -c pausesLocationUpdatesAutomatically
        assert pauses_tracker == 180
