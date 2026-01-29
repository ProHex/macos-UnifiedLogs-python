# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for DSC (shared cache strings) parsing."""

import pytest

from macos_unifiedlogs.dsc import (
    RangeDescriptor,
    SharedCacheStrings,
    UUIDDescriptor,
)


class TestRangeDescriptor:
    """Test RangeDescriptor data structure."""

    def test_range_descriptor_creation(self):
        """Test creating RangeDescriptor."""
        descriptor = RangeDescriptor(
            range_offset=0x1000,
            data_offset=0x2000,
            range_size=500,
            unknown_uuid_index=0,
            strings=b'test strings',
        )

        assert descriptor.range_offset == 0x1000
        assert descriptor.data_offset == 0x2000
        assert descriptor.range_size == 500
        assert descriptor.unknown_uuid_index == 0

    def test_range_descriptor_defaults(self):
        """Test RangeDescriptor default values."""
        descriptor = RangeDescriptor()
        assert descriptor.range_offset == 0
        assert descriptor.data_offset == 0
        assert descriptor.range_size == 0
        assert descriptor.unknown_uuid_index == 0
        assert descriptor.strings == b''


class TestUUIDDescriptor:
    """Test UUIDDescriptor data structure."""

    def test_uuid_descriptor_creation(self):
        """Test creating UUIDDescriptor."""
        descriptor = UUIDDescriptor(
            text_offset=0x100,
            text_size=1000,
            uuid="ABCD1234ABCD1234ABCD1234ABCD1234",
            path_offset=0,
            path_string="/usr/lib/libSystem.B.dylib",
        )

        assert descriptor.text_offset == 0x100
        assert descriptor.text_size == 1000
        assert descriptor.uuid == "ABCD1234ABCD1234ABCD1234ABCD1234"
        assert descriptor.path_string == "/usr/lib/libSystem.B.dylib"

    def test_uuid_descriptor_defaults(self):
        """Test UUIDDescriptor default values."""
        descriptor = UUIDDescriptor()
        assert descriptor.text_offset == 0
        assert descriptor.text_size == 0
        assert descriptor.uuid == ""
        assert descriptor.path_offset == 0
        assert descriptor.path_string == ""


class TestSharedCacheStrings:
    """Test SharedCacheStrings data structure."""

    def test_shared_cache_strings_creation(self):
        """Test creating SharedCacheStrings."""
        uuid1 = UUIDDescriptor(
            text_offset=0x100,
            text_size=500,
            uuid="UUID1234567890ABCDEF1234567890AB",
            path_offset=0,
            path_string="/System/Library/Frameworks/Foundation.framework/Foundation",
        )

        range1 = RangeDescriptor(
            range_offset=0x100,
            data_offset=0x200,
            range_size=500,
            unknown_uuid_index=0,
        )

        dsc = SharedCacheStrings(
            signature=0x64736368,  # "hcsd" in little endian
            major_version=2,
            minor_version=0,
            number_ranges=1,
            number_uuids=1,
            ranges=[range1],
            uuids=[uuid1],
            dsc_uuid="DSCUUID12345678901234567890ABCD",
        )

        assert dsc.signature == 0x64736368
        assert dsc.major_version == 2
        assert dsc.number_uuids == 1
        assert len(dsc.uuids) == 1
        assert dsc.uuids[0].uuid == "UUID1234567890ABCDEF1234567890AB"

    def test_shared_cache_strings_defaults(self):
        """Test SharedCacheStrings default values."""
        dsc = SharedCacheStrings()
        assert dsc.signature == 0
        assert dsc.major_version == 0
        assert dsc.minor_version == 0
        assert dsc.number_ranges == 0
        assert dsc.number_uuids == 0
        assert dsc.ranges == []
        assert dsc.uuids == []

    def test_shared_cache_strings_v1(self):
        """Test SharedCacheStrings version 1 (Big Sur and earlier)."""
        dsc = SharedCacheStrings(
            signature=0x64736368,
            major_version=1,
            minor_version=0,
            number_ranges=2,
            number_uuids=2,
            ranges=[
                RangeDescriptor(range_offset=0x1000, data_offset=0x1100, range_size=100, unknown_uuid_index=0),
                RangeDescriptor(range_offset=0x2000, data_offset=0x2100, range_size=200, unknown_uuid_index=1),
            ],
            uuids=[
                UUIDDescriptor(
                    text_offset=0x1000,
                    text_size=100,
                    uuid="A" * 32,
                    path_offset=0,
                    path_string="/lib/a",
                ),
                UUIDDescriptor(
                    text_offset=0x2000,
                    text_size=200,
                    uuid="B" * 32,
                    path_offset=0,
                    path_string="/lib/b",
                ),
            ],
            dsc_uuid="",
        )

        assert dsc.major_version == 1
        assert len(dsc.uuids) == 2
        assert len(dsc.ranges) == 2

    def test_shared_cache_strings_v2(self):
        """Test SharedCacheStrings version 2 (Monterey and later)."""
        dsc = SharedCacheStrings(
            signature=0x64736368,
            major_version=2,
            minor_version=0,
            number_ranges=1,
            number_uuids=1,
            ranges=[
                RangeDescriptor(range_offset=0x5000, data_offset=0x5100, range_size=1000, unknown_uuid_index=0),
            ],
            uuids=[
                UUIDDescriptor(
                    text_offset=0x5000,
                    text_size=1000,
                    uuid="C" * 32,
                    path_offset=100,
                    path_string="/System/Library/Caches/com.apple.dyld/test.dsc",
                ),
            ],
            dsc_uuid="DSCUUID" + "0" * 25,
        )

        assert dsc.major_version == 2
        assert dsc.dsc_uuid.startswith("DSCUUID")
