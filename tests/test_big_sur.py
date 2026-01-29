# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Integration tests for Big Sur logs."""

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

from .conftest import collect_logs, is_signpost, skip_if_no_test_data


class TestBigSur:
    """Test parsing Big Sur log archives."""

    def test_parse_log_big_sur(self, big_sur_logarchive_path: Optional[Path]):
        """Test parsing a single tracev3 file from Big Sur."""
        skip_if_no_test_data(big_sur_logarchive_path, "Big Sur")

        test_path = big_sur_logarchive_path / "Persist" / "0000000000000004.tracev3"

        with open(test_path, "rb") as handle:
            _, log_data = parse_log(handle)

        assert len(log_data.catalog_data[0].firehose) == 82
        assert len(log_data.catalog_data[0].simpledump) == 0
        assert len(log_data.header) == 1
        assert len(log_data.catalog_data[0].catalog.catalog_process_info_entries) == 45
        assert len(log_data.catalog_data[0].statedump) == 0

    def test_big_sur_livedata(self, big_sur_logarchive_path: Optional[Path]):
        """Test parsing Big Sur livedata tracev3 file."""
        skip_if_no_test_data(big_sur_logarchive_path, "Big Sur")

        provider = LogarchiveProvider(str(big_sur_logarchive_path))
        timesync_data = collect_timesync(provider)

        test_path = big_sur_logarchive_path / "logdata.LiveData.tracev3"

        with open(test_path, "rb") as handle:
            _, results = parse_log(handle)

        exclude_missing = False
        data, _ = build_log(results, provider, timesync_data, exclude_missing)
        assert len(data) == 101566

        for result in data:
            # Test for a log message that uses a firehose_header_timestamp with a value of zero
            if result.message == "TimeSyncTime is mach_absolute_time nanoseconds\n":
                assert result.message == "TimeSyncTime is mach_absolute_time nanoseconds\n"
                assert result.activity_id == 0
                assert result.thread_id == 116
                assert result.euid == 0
                assert result.pid == 0
                assert result.library == "/System/Library/Extensions/IOTimeSyncFamily.kext/Contents/MacOS/IOTimeSyncFamily"
                assert result.subsystem == ""
                assert result.category == ""
                assert result.event_type == EventType.Log
                assert result.log_type == LogType.Info
                assert result.process == "/kernel"
                assert result.time == 1642304801596413351.0
                assert result.boot_uuid == "A2A9017676CF421C84DC9BBD6263FEE7"
                assert result.timezone_name == "Pacific"
                break

    def test_build_log_big_sur(self, big_sur_logarchive_path: Optional[Path]):
        """Test building logs from Big Sur tracev3 file."""
        skip_if_no_test_data(big_sur_logarchive_path, "Big Sur")

        provider = LogarchiveProvider(str(big_sur_logarchive_path))
        timesync_data = collect_timesync(provider)

        test_path = big_sur_logarchive_path / "Persist" / "0000000000000004.tracev3"

        with open(test_path, "rb") as handle:
            _, log_data = parse_log(handle)

        exclude_missing = False
        results, _ = build_log(log_data, provider, timesync_data, exclude_missing)

        assert len(results) == 110953
        assert results[0].process == "/usr/libexec/opendirectoryd"
        assert results[0].subsystem == "com.apple.opendirectoryd"
        assert results[0].time == 1642303933964503310.0
        assert results[0].activity_id == 0
        assert results[0].library == "/usr/libexec/opendirectoryd"
        assert results[0].message == "opendirectoryd (build 796.100) launched..."
        assert results[0].pid == 105
        assert results[0].thread_id == 670
        assert results[0].category == "default"
        assert results[0].log_type == LogType.Default
        assert results[0].event_type == EventType.Log
        assert results[0].euid == 0
        assert results[0].boot_uuid == "AACFB573E87545CE98B893D132766A46"
        assert results[0].timezone_name == "Pacific"
        assert results[0].library_uuid == "B736DF1625F538248E9527A8CEC4991E"
        assert results[0].process_uuid == "B736DF1625F538248E9527A8CEC4991E"
        assert results[0].raw_message == "opendirectoryd (build %{public}s) launched..."

    def test_parse_all_logs_big_sur(self, big_sur_logarchive_path: Optional[Path]):
        """Test parsing all logs from Big Sur logarchive."""
        skip_if_no_test_data(big_sur_logarchive_path, "Big Sur")

        provider = LogarchiveProvider(str(big_sur_logarchive_path))
        timesync_data = collect_timesync(provider)
        log_data = collect_logs(provider)

        log_data_vec = []
        exclude_missing = False

        for logs in log_data:
            data, _ = build_log(logs, provider, timesync_data, exclude_missing)
            log_data_vec.extend(data)

        # Run: "log raw-dump -a macos-unifiedlogs/tests/test_data/system_logs_big_sur.logarchive"
        # total log entries: 747,294
        # Add Statedump log entries: 322
        # Total log entries: 747,616
        assert len(log_data_vec) == 747616

        unknown_strings = 0
        invalid_offsets = 0
        invalid_shared_string_offsets = 0
        statedump_custom_objects = 0
        statedump_protocol_buffer = 0

        found_precision_string = False
        statedump_count = 0
        signpost_count = 0

        default_type = 0
        info_type = 0
        error_type = 0
        create_type = 0
        debug_type = 0
        useraction_type = 0
        fault_type = 0
        loss_type = 0

        string_count = 0
        message_re = re.compile(r"^[\s]*%s\s*$")
        empty_format_count = 0
        sock_count = 0
        location_harvest_count = 0

        for logs in log_data_vec:
            if ("Failed to get string message from " in logs.message or
                    "Unknown shared string message" in logs.message):
                unknown_strings += 1
            elif "Error: Invalid offset " in logs.message:
                invalid_offsets += 1
            elif "Error: Invalid shared string offset" in logs.message:
                invalid_shared_string_offsets += 1
            elif "Unsupported Statedump object" in logs.message:
                statedump_custom_objects += 1
            elif ("Failed to parse StateDump protobuf" in logs.message or
                  "Failed to serialize Protobuf HashMap" in logs.message):
                statedump_protocol_buffer += 1
            elif logs.message == r'#32EC4B64 [AssetCacheLocatorService.queue] sending POST [327]{"locator-tag":"#32ec4b64","local-addresses":["192.168.101.144"],"ranked-results":true,"locator-software":[{"build":"20G224","type":"system","name":"macOS","version":"11.6.1"},{"id":"com.apple.AssetCacheLocatorService","executable":"AssetCacheLocatorService","type":"bundle","name":"AssetCacheLocatorService","version":"118"}]} to https://lcdn-locator.apple.com/lcdn/locate':
                found_precision_string = True

            if logs.event_type == EventType.Statedump:
                statedump_count += 1
            elif logs.event_type == EventType.Signpost:
                signpost_count += 1
            elif logs.log_type == LogType.Default:
                default_type += 1
            elif logs.log_type == LogType.Info:
                info_type += 1
            elif logs.log_type == LogType.Error:
                error_type += 1
            elif logs.log_type == LogType.Create:
                create_type += 1
            elif logs.log_type == LogType.Debug:
                debug_type += 1
            elif logs.log_type == LogType.Useraction:
                useraction_type += 1
            elif logs.log_type == LogType.Fault:
                fault_type += 1
            elif logs.event_type == EventType.Loss:
                loss_type += 1

            if '"subHarvester":"Trace"' in logs.message:
                location_harvest_count += 1

            if message_re.match(logs.raw_message):
                string_count += 1

            if (not logs.raw_message and not logs.message and
                    logs.event_type != EventType.Loss):
                empty_format_count += 1

            if "nw_resolver_create_dns_getaddrinfo_locked_block_invoke [C1] Got DNS result type NoAddress ifindex=0 configuration.ls.apple.com configuration.ls.apple.com. ::" in logs.message:
                sock_count += 1

        assert unknown_strings == 0
        assert invalid_offsets == 54
        assert invalid_shared_string_offsets == 0
        assert statedump_custom_objects == 0
        assert statedump_protocol_buffer == 0
        assert found_precision_string

        assert statedump_count == 322
        assert signpost_count == 50665
        assert string_count == 11764
        assert empty_format_count == 56
        assert default_type == 462518
        assert info_type == 114540
        assert error_type == 29132
        assert create_type == 87831
        assert debug_type == 1908
        assert useraction_type == 15
        assert fault_type == 680
        assert loss_type == 5
        assert sock_count == 2
        assert location_harvest_count == 11

    def test_parse_all_persist_logs_with_network_big_sur(
        self, big_sur_logarchive_path: Optional[Path]
    ):
        """Test parsing all persist logs containing network from Big Sur."""
        skip_if_no_test_data(big_sur_logarchive_path, "Big Sur")

        provider = LogarchiveProvider(str(big_sur_logarchive_path))
        timesync_data = collect_timesync(provider)
        log_data = collect_logs(provider)

        log_data_vec = []
        exclude_missing = False

        for logs in log_data:
            data, _ = build_log(logs, provider, timesync_data, exclude_missing)
            log_data_vec.extend(data)

        messages_containing_network = 0
        default_type = 0
        info_type = 0
        error_type = 0
        create_type = 0
        state_simple_dump = 0
        signpost = 0

        network_message_uuid = False

        for logs in log_data_vec:
            if "network" in logs.message.lower():
                if logs.log_type == LogType.Default:
                    default_type += 1
                    if "7C10C1EF-1B86-494F-800D-C769A89172C1" in logs.message:
                        network_message_uuid = True
                elif logs.log_type == LogType.Info:
                    info_type += 1
                elif logs.log_type == LogType.Error:
                    error_type += 1
                elif logs.log_type == LogType.Create:
                    create_type += 1
                    continue
                elif logs.event_type in (EventType.Simpledump, EventType.Statedump):
                    state_simple_dump += 1
                    continue
                elif is_signpost(logs.log_type):
                    signpost += 1
                    continue
                messages_containing_network += 1

        assert messages_containing_network == 9173
        assert default_type == 8320
        assert network_message_uuid

        assert info_type == 638
        assert error_type == 215
        assert create_type == 687
        assert state_simple_dump == 34
        assert signpost == 62

    def test_parse_all_logs_private_big_sur(
        self, big_sur_private_logarchive_path: Optional[Path]
    ):
        """Test parsing Big Sur logs with private data enabled."""
        skip_if_no_test_data(big_sur_private_logarchive_path, "Big Sur Private")

        provider = LogarchiveProvider(str(big_sur_private_logarchive_path))
        timesync_data = collect_timesync(provider)
        log_data = collect_logs(provider)

        log_data_vec = []
        exclude_missing = False

        for logs in log_data:
            data, _ = build_log(logs, provider, timesync_data, exclude_missing)
            log_data_vec.extend(data)

        assert len(log_data_vec) == 887890

        empty_counter = 0
        not_found = 0
        staff_count = 0

        for logs in log_data_vec:
            if not logs.message:
                empty_counter += 1
            if "<not found>" in logs.message:
                not_found += 1
            if "group: staff@/Local/Default" in logs.message:
                staff_count += 1

        assert not_found == 0
        assert staff_count == 4
        assert empty_counter == 596

    def test_parse_all_logs_private_with_public_mix_big_sur(
        self, big_sur_public_private_mix_path: Optional[Path]
    ):
        """Test parsing Big Sur logs with public/private data mix."""
        skip_if_no_test_data(big_sur_public_private_mix_path, "Big Sur Public/Private Mix")

        provider = LogarchiveProvider(str(big_sur_public_private_mix_path))
        timesync_data = collect_timesync(provider)
        log_data = collect_logs(provider)

        log_data_vec = []
        exclude_missing = False

        for logs in log_data:
            data, _ = build_log(logs, provider, timesync_data, exclude_missing)
            log_data_vec.extend(data)

        assert len(log_data_vec) == 1287628

        not_found = 0
        user_not_found = 0
        mobile_not_found = 0
        bssid_count = 0
        dns_query_count = 0
        bofa_count = 0

        for logs in log_data_vec:
            if "<not found>" in logs.message:
                not_found += 1
            if "user: -1 <not found>" in logs.message:
                user_not_found += 1
            if "refreshing: details, reason: expired, user: mobile <not found>" in logs.message:
                mobile_not_found += 1
            if "BSSID 00:00:00:00:00:00" in logs.message:
                bssid_count += 1
            if "https://doh.dns.apple.com/dns-query" in logs.message:
                dns_query_count += 1
            if "bankofamerica" in logs.message:
                bofa_count += 1

        assert not_found == 5
        assert user_not_found == 2
        assert mobile_not_found == 1
        assert bssid_count == 39
        assert dns_query_count == 41
        assert bofa_count == 573

    def test_parse_all_logs_private_with_public_mix_big_sur_single_file(
        self, big_sur_public_private_mix_path: Optional[Path]
    ):
        """Test parsing a single tracev3 file with public/private data mix."""
        skip_if_no_test_data(big_sur_public_private_mix_path, "Big Sur Public/Private Mix")

        provider = LogarchiveProvider(str(big_sur_public_private_mix_path))
        timesync_data = collect_timesync(provider)

        test_path = big_sur_public_private_mix_path / "Persist" / "0000000000000009.tracev3"

        with open(test_path, "rb") as handle:
            _, log_data = parse_log(handle)

        exclude_missing = False
        results, _ = build_log(log_data, provider, timesync_data, exclude_missing)
        assert len(results) == 91567

        hex_count = 0
        dns = 0
        public_private_mixture = False

        for result in results:
            if "7FAE25804F50" in result.message:
                hex_count += 1
            if ".mdns" in result.subsystem:
                dns += 1
            if result.message == "os_transaction created: (7FAE25B0E420) CLLS:0x7fae23628160.LocationFine":
                public_private_mixture = True

        assert hex_count == 4
        assert dns == 801
        assert public_private_mixture

    def test_parse_all_logs_private_with_public_mix_big_sur_special_file(
        self, big_sur_public_private_mix_path: Optional[Path]
    ):
        """Test parsing Special tracev3 file with public/private data mix."""
        skip_if_no_test_data(big_sur_public_private_mix_path, "Big Sur Public/Private Mix")

        provider = LogarchiveProvider(str(big_sur_public_private_mix_path))
        timesync_data = collect_timesync(provider)

        test_path = big_sur_public_private_mix_path / "Special" / "0000000000000008.tracev3"

        with open(test_path, "rb") as handle:
            _, log_data = parse_log(handle)

        exclude_missing = False
        results, _ = build_log(log_data, provider, timesync_data, exclude_missing)
        assert len(results) == 2238

        statedump = 0
        default = 0
        fault = 0
        info = 0
        error = 0

        for result in results:
            if result.event_type == EventType.Statedump:
                statedump += 1
            elif result.log_type == LogType.Default:
                default += 1
            elif result.log_type == LogType.Fault:
                fault += 1
            elif result.log_type == LogType.Info:
                info += 1
            elif result.log_type == LogType.Error:
                error += 1

        assert statedump == 1
        assert default == 1972
        assert fault == 32
        assert info == 41
        assert error == 192

    def test_big_sur_missing_oversize_strings(
        self, big_sur_logarchive_path: Optional[Path]
    ):
        """Test handling of missing oversize strings in Big Sur."""
        skip_if_no_test_data(big_sur_logarchive_path, "Big Sur")

        provider = LogarchiveProvider(str(big_sur_logarchive_path))
        timesync_data = collect_timesync(provider)

        # livedata may have oversize string data in other tracev3 on disk
        test_path = big_sur_logarchive_path / "logdata.LiveData.tracev3"

        with open(test_path, "rb") as handle:
            _, log_data = parse_log(handle)

        exclude_missing = False
        data, _ = build_log(log_data, provider, timesync_data, exclude_missing)
        assert len(data) == 101566

        missing_strings = 0
        for result in data:
            if "<Missing message data>" in result.message:
                missing_strings += 1

        # There should be only 29 entries that have actual missing data
        # 23 strings are in other tracev3 files. 23 + 29 = 52
        assert missing_strings == 52

    def test_big_sur_oversize_strings_in_another_file(
        self, big_sur_logarchive_path: Optional[Path]
    ):
        """Test oversize strings from another file in Big Sur."""
        skip_if_no_test_data(big_sur_logarchive_path, "Big Sur")

        provider = LogarchiveProvider(str(big_sur_logarchive_path))
        timesync_data = collect_timesync(provider)

        # Get most recent Persist tracev3 file could contain oversize log entries
        persist_path = big_sur_logarchive_path / "Persist" / "0000000000000005.tracev3"
        with open(persist_path, "rb") as handle:
            _, log_data = parse_log(handle)

        # Get most recent Special tracev3 file that could contain oversize log entries
        special_path = big_sur_logarchive_path / "Special" / "0000000000000005.tracev3"
        with open(special_path, "rb") as handle:
            _, special_data = parse_log(handle)

        livedata_path = big_sur_logarchive_path / "logdata.LiveData.tracev3"
        with open(livedata_path, "rb") as handle:
            _, results = parse_log(handle)

        results.oversize.extend(log_data.oversize)
        results.oversize.extend(special_data.oversize)

        exclude_missing = False
        data, _ = build_log(results, provider, timesync_data, exclude_missing)
        assert len(data) == 101566

        missing_strings = 0
        for result in data:
            if "<Missing message data>" in result.message:
                missing_strings += 1

        # 29 log entries actually have missing data
        # Apple displays as: <decode: missing data>
        assert missing_strings == 29
