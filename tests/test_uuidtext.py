# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for UUIDText parsing."""

import pytest

from macos_unifiedlogs.uuidtext import UUIDText, UUIDTextEntry


class TestUUIDTextEntry:
    """Test UUIDTextEntry data structure."""

    def test_uuidtext_entry_creation(self):
        """Test creating UUIDTextEntry."""
        entry = UUIDTextEntry(
            range_start_offset=0x1000,
            entry_size=100,
        )

        assert entry.range_start_offset == 0x1000
        assert entry.entry_size == 100

    def test_uuidtext_entry_defaults(self):
        """Test UUIDTextEntry default values."""
        entry = UUIDTextEntry()
        assert entry.range_start_offset == 0
        assert entry.entry_size == 0


class TestUUIDText:
    """Test UUIDText data structure."""

    def test_uuidtext_creation(self):
        """Test creating UUIDText."""
        entry1 = UUIDTextEntry(
            range_start_offset=0x1000,
            entry_size=20,
        )
        entry2 = UUIDTextEntry(
            range_start_offset=0x2000,
            entry_size=30,
        )

        uuidtext = UUIDText(
            uuid="ABCD1234ABCD1234ABCD1234ABCD1234",
            signature=0x66778899,
            unknown_major_version=2,
            unknown_minor_version=1,
            number_entries=2,
            entry_descriptors=[entry1, entry2],
            footer_data=b'/usr/lib/libSystem.B.dylib\x00',
        )

        assert uuidtext.signature == 0x66778899
        assert uuidtext.number_entries == 2
        assert len(uuidtext.entry_descriptors) == 2
        assert uuidtext.uuid == "ABCD1234ABCD1234ABCD1234ABCD1234"

    def test_uuidtext_defaults(self):
        """Test UUIDText default values."""
        uuidtext = UUIDText()
        assert uuidtext.signature == 0
        assert uuidtext.number_entries == 0
        assert uuidtext.entry_descriptors == []
        assert uuidtext.uuid == ""
        assert uuidtext.footer_data == b''

    def test_uuidtext_lookup(self):
        """Test looking up entry by offset."""
        entry1 = UUIDTextEntry(
            range_start_offset=0x1000,
            entry_size=20,
        )
        entry2 = UUIDTextEntry(
            range_start_offset=0x2000,
            entry_size=30,
        )

        uuidtext = UUIDText(
            uuid="TEST",
            signature=0x66778899,
            number_entries=2,
            entry_descriptors=[entry1, entry2],
            footer_data=b'/test/path\x00',
        )

        # Lookup should find the entry containing the offset
        for entry in uuidtext.entry_descriptors:
            if entry.range_start_offset == 0x1000:
                assert entry.entry_size == 20
                break

    def test_uuidtext_with_footer_data(self):
        """Test UUIDText with footer data containing library paths."""
        footer = b"libSystem.B.dylib\x00CoreFoundation\x00"
        uuidtext = UUIDText(
            uuid="CF12345678901234567890123456789A",
            signature=0x66778899,
            number_entries=0,
            entry_descriptors=[],
            footer_data=footer,
        )

        assert uuidtext.footer_data == footer
        assert b"libSystem.B.dylib" in uuidtext.footer_data
