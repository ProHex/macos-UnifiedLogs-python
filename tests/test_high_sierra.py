# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Integration tests for High Sierra logs."""

import re
from pathlib import Path
from typing import Optional

import pytest

from macos_unifiedlogs import (
    EventType,
    LogarchiveProvider,
    LogType,
    build_log,
    collect_timesync,
    parse_log,
)

from .conftest import collect_logs, skip_if_no_test_data


class TestHighSierra:
    """Test parsing High Sierra log archives."""

    def test_parse_log_high_sierra(self, high_sierra_logarchive_path: Optional[Path]):
        """Test parsing a single tracev3 file from High Sierra."""
        skip_if_no_test_data(high_sierra_logarchive_path, "High Sierra")

        test_path = high_sierra_logarchive_path / "Persist" / "0000000000000001.tracev3"

        with open(test_path, "rb") as handle:
            _, log_data = parse_log(handle)

        assert len(log_data.catalog_data[0].firehose) == 172
        assert len(log_data.catalog_data[0].simpledump) == 0
        assert len(log_data.header) == 1
        assert len(log_data.catalog_data[0].catalog.catalog_process_info_entries) == 30
        assert len(log_data.catalog_data[0].statedump) == 0

    def test_build_log_high_sierra(self, high_sierra_logarchive_path: Optional[Path]):
        """Test building logs from High Sierra tracev3 file."""
        skip_if_no_test_data(high_sierra_logarchive_path, "High Sierra")

        provider = LogarchiveProvider(str(high_sierra_logarchive_path))
        timesync_data = collect_timesync(provider)

        test_path = high_sierra_logarchive_path / "Persist" / "0000000000000001.tracev3"

        with open(test_path, "rb") as handle:
            _, log_data = parse_log(handle)

        exclude_missing = False
        results, _ = build_log(log_data, provider, timesync_data, exclude_missing)

        assert len(results) == 162402
        assert results[0].process == "/usr/libexec/opendirectoryd"
        assert results[0].subsystem == "com.apple.opendirectoryd"
        assert results[0].time == 1624134811546060433.0
        assert results[0].activity_id == 0
        assert results[0].library == "/usr/libexec/opendirectoryd"
        assert results[0].message == "opendirectoryd (build 483.700) launched..."
        assert results[0].pid == 59
        assert results[0].thread_id == 622
        assert results[0].category == "default"
        assert results[0].log_type == LogType.Default
        assert results[0].event_type == EventType.Log
        assert results[0].euid == 0
        assert results[0].boot_uuid == "30774817CF1549B0920E1A8E17D47AB5"
        assert results[0].timezone_name == "Pacific"
        assert results[0].process_uuid == "AD43C574A9F73311A4E995237667082A"
        assert results[0].library_uuid == "AD43C574A9F73311A4E995237667082A"
        assert results[0].raw_message == "opendirectoryd (build %{public}s) launched..."

    def test_build_log_complex_format_high_sierra(
        self, high_sierra_logarchive_path: Optional[Path]
    ):
        """Test building logs with complex format strings from High Sierra."""
        skip_if_no_test_data(high_sierra_logarchive_path, "High Sierra")

        provider = LogarchiveProvider(str(high_sierra_logarchive_path))
        timesync_data = collect_timesync(provider)

        test_path = high_sierra_logarchive_path / "Persist" / "0000000000000001.tracev3"

        with open(test_path, "rb") as handle:
            _, log_data = parse_log(handle)

        exclude_missing = False
        results, _ = build_log(log_data, provider, timesync_data, exclude_missing)
        assert len(results) == 162402

        expected_message = (
            "<PCPersistentTimer: 0x7f8b72c722f0> Calculated minimum fire date "
            "[2021-06-19 19:47:59 -0700] (75%) with fire date [2021-06-19 21:51:14 -0700], "
            "start date [2021-06-19 13:38:14 -0700], minimum early fire proportion 0.75, "
            "power state detection supported: no, in high power state: no, early fire constant interval 0"
        )

        for result in results:
            if result.message == expected_message:
                assert result.process == "/System/Library/PrivateFrameworks/CalendarNotification.framework/Versions/A/XPCServices/CalNCService.xpc/Contents/MacOS/CalNCService"
                assert result.subsystem == "com.apple.PersistentConnection"
                assert result.time == 1624135094694359040.0
                assert result.activity_id == 0
                assert result.library == "/System/Library/PrivateFrameworks/PersistentConnection.framework/Versions/A/PersistentConnection"
                assert result.message == expected_message
                assert result.pid == 580
                assert result.thread_id == 8759
                assert result.category == "persistentTimer.com.apple.CalendarNotification.EKTravelEngine.periodicRefreshTimer"
                assert result.log_type == LogType.Default
                assert result.event_type == EventType.Log
                assert result.euid == 501
                assert result.boot_uuid == "30774817CF1549B0920E1A8E17D47AB5"
                assert result.timezone_name == "Pacific"
                assert result.process_uuid == "3E78A65047873F8AAFB10EA606B84B5D"
                assert result.library_uuid == "761AF71A7FBE3374A4A48A38E0D59B6B"
                assert result.raw_message == (
                    "%{public}@ Calculated minimum fire date [%{public}@] (%g%%) with fire date "
                    "[%{public}@], start date [%{public}@], minimum early fire proportion %g, "
                    "power state detection supported: %{public}s, in high power state: %{public}s, "
                    "early fire constant interval %f"
                )
                return

        pytest.fail("Did not find message match")

    def test_build_log_negative_number_high_sierra(
        self, high_sierra_logarchive_path: Optional[Path]
    ):
        """Test building logs with negative numbers from High Sierra."""
        skip_if_no_test_data(high_sierra_logarchive_path, "High Sierra")

        provider = LogarchiveProvider(str(high_sierra_logarchive_path))
        timesync_data = collect_timesync(provider)

        test_path = high_sierra_logarchive_path / "Special" / "0000000000000003.tracev3"

        with open(test_path, "rb") as handle:
            _, log_data = parse_log(handle)

        exclude_missing = False
        results, _ = build_log(log_data, provider, timesync_data, exclude_missing)
        assert len(results) == 12058

        for result in results:
            if result.message == "[BTUserEventAgentController messageTracerEventDriven] PowerSource -2 -2\n":
                assert result.raw_message == "[BTUserEventAgentController messageTracerEventDriven] PowerSource %f %f\n"
                return

        pytest.fail("Did not find negative message match")

    def test_parse_all_logs_high_sierra(
        self, high_sierra_logarchive_path: Optional[Path]
    ):
        """Test parsing all logs from High Sierra logarchive."""
        skip_if_no_test_data(high_sierra_logarchive_path, "High Sierra")

        provider = LogarchiveProvider(str(high_sierra_logarchive_path))
        timesync_data = collect_timesync(provider)
        log_data = collect_logs(provider)

        log_data_vec = []
        exclude_missing = False

        for logs in log_data:
            data, _ = build_log(logs, provider, timesync_data, exclude_missing)
            log_data_vec.extend(data)

        assert len(log_data_vec) == 569796

        empty_counter = 0
        empty_identityservicesd = 0
        empty_callservicesd = 0
        empty_configd = 0
        empty_coreduetd = 0
        private_entries = 0
        kernel_entries = 0
        string_count = 0

        message_re = re.compile(r"^[\s]*%s\s*$")

        for logs in log_data_vec:
            if not logs.message:
                empty_counter += 1

                if logs.process == "/System/Library/PrivateFrameworks/TelephonyUtilities.framework/callservicesd":
                    empty_callservicesd += 1
                elif logs.process == "/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd":
                    empty_identityservicesd += 1
                elif logs.process == "/usr/libexec/configd":
                    empty_configd += 1
                elif logs.process == "/usr/libexec/coreduetd":
                    empty_coreduetd += 1
            elif "<private>" in logs.message:
                private_entries += logs.message.count("<private>")

            if "bytes in/out: 818/542, packets in/out: 2/2, rtt: 0.020s, retransmitted packets: 1, out-of-order packets: 2" in logs.message:
                assert logs.message == "[11 <private> stream, pid: 344] cancelled\n\t[11.1 334B42D96E654481B31C3A452BFB96B7 <private>.49154<-><private>]\n\tConnected Path: satisfied (Path is satisfied), interface: en0, ipv4, dns\n\tDuration: 0.115s, DNS @0.000s took 0.002s, TCP @0.002s took 0.014s\n\tbytes in/out: 818/542, packets in/out: 2/2, rtt: 0.020s, retransmitted packets: 1, out-of-order packets: 2"
                assert logs.raw_message == "[%{public}s %{private}@ %{public}@] cancelled\n\t[%s %{uuid_t}.16P %{private,network:in_addr}d.%d<->%{private,network:sockaddr}.*P]\n\tConnected Path: %@\n\tDuration: %u.%03us, DNS @%u.%03us took %u.%03us, %{public}s @%u.%03us took %u.%03us\n\tbytes in/out: %llu/%llu, packets in/out: %llu/%llu, rtt: %u.%03us, retransmitted packets: %llu, out-of-order packets: %u"

            if logs.process == "/kernel" and logs.library == "/kernel":
                kernel_entries += 1

            if message_re.match(logs.raw_message):
                string_count += 1

        # Opening system_logs_high_sierra.logarchive in Console.app and searching for the
        # processes above should return the exact same number of empty entries as below
        assert empty_counter == 107
        assert empty_identityservicesd == 24
        assert empty_configd == 64
        assert empty_coreduetd == 1
        assert empty_callservicesd == 18
        assert private_entries == 88352
        assert kernel_entries == 389
        assert string_count == 23982

        unknown_strings = 0
        invalid_offsets = 0
        invalid_shared_string_offsets = 0
        statedump_custom_objects = 0
        statedump_protocol_buffer = 0

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

        assert unknown_strings == 0
        assert invalid_offsets == 3
        assert invalid_shared_string_offsets == 0
        assert statedump_custom_objects == 0
        assert statedump_protocol_buffer == 0
