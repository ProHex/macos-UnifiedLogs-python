# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Parse Firehose log entries - the core log data in tracev3 files."""

import logging
import struct
from dataclasses import dataclass, field
from typing import List, Tuple

from ...util import encode_standard, extract_string_size, padding_size_8, padding_size_four
from .activity import FirehoseActivity
from .loss import FirehoseLoss
from .nonactivity import FirehoseNonActivity
from .signpost import FirehoseSignpost
from .trace import FirehoseTrace

logger = logging.getLogger(__name__)


@dataclass
class FirehoseItemInfo:
    """Information about a single firehose item (message component)."""
    message_strings: str = ""
    item_type: int = 0
    item_size: int = 0


@dataclass
class FirehoseItemData:
    """Collection of firehose items for a log entry."""
    item_info: List[FirehoseItemInfo] = field(default_factory=list)
    backtrace_strings: List[str] = field(default_factory=list)


@dataclass
class FirehoseItemType:
    """Internal structure for parsing firehose items."""
    item_type: int = 0
    item_size: int = 0
    offset: int = 0
    message_string_size: int = 0
    message_strings: str = ""


@dataclass
class Firehose:
    """Individual firehose log entry."""
    unknown_log_activity_type: int = 0  # 0x2=Activity, 0x4=non-activity, 0x6=signpost, 0x3=trace
    unknown_log_type: int = 0  # Log type (Info, Debug, Error, Fault, etc.)
    flags: int = 0
    format_string_location: int = 0
    thread_id: int = 0
    continous_time_delta: int = 0
    continous_time_delta_upper: int = 0
    data_size: int = 0
    firehose_activity: FirehoseActivity = None
    firehose_non_activity: FirehoseNonActivity = None
    firehose_loss: FirehoseLoss = None
    firehose_signpost: FirehoseSignpost = None
    firehose_trace: FirehoseTrace = None
    unknown_item: int = 0
    number_items: int = 0
    message: FirehoseItemData = None

    def __post_init__(self):
        if self.firehose_activity is None:
            self.firehose_activity = FirehoseActivity()
        if self.firehose_non_activity is None:
            self.firehose_non_activity = FirehoseNonActivity()
        if self.firehose_loss is None:
            self.firehose_loss = FirehoseLoss()
        if self.firehose_signpost is None:
            self.firehose_signpost = FirehoseSignpost()
        if self.firehose_trace is None:
            self.firehose_trace = FirehoseTrace()
        if self.message is None:
            self.message = FirehoseItemData()


@dataclass
class FirehosePreamble:
    """Firehose preamble - header for a batch of firehose log entries."""
    chunk_tag: int = 0
    chunk_sub_tag: int = 0
    chunk_data_size: int = 0
    first_number_proc_id: int = 0
    second_number_proc_id: int = 0
    ttl: int = 0
    collapsed: int = 0
    unknown: bytes = b''
    public_data_size: int = 0
    private_data_virtual_offset: int = 0  # 0x1000 if NO private data
    unknown2: int = 0
    unknown3: int = 0
    base_continous_time: int = 0
    public_data: List[Firehose] = field(default_factory=list)

    # Item type constants
    STRING_ITEM = [0x20, 0x22, 0x40, 0x42, 0x30, 0x31, 0x32, 0xf2]
    PRIVATE_NUMBER = 0x1
    PRIVATE_STRINGS = [0x21, 0x25, 0x35, 0x31, 0x41, 0x81, 0xf1]
    LOG_TYPES = [0x2, 0x6, 0x4, 0x7, 0x3]
    REMNANT_DATA = 0x0

    @staticmethod
    def parse_firehose_preamble(data: bytes) -> Tuple[bytes, 'FirehosePreamble']:
        """Parse the start of the Firehose data.

        Args:
            data: Raw bytes starting at firehose preamble

        Returns:
            Tuple of (remaining data, FirehosePreamble)
        """
        firehose_data = FirehosePreamble()
        offset = 0

        firehose_data.chunk_tag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        firehose_data.chunk_sub_tag = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        firehose_data.chunk_data_size = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        firehose_data.first_number_proc_id = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        firehose_data.second_number_proc_id = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        firehose_data.ttl = struct.unpack_from('<B', data, offset)[0]
        offset += 1
        firehose_data.collapsed = struct.unpack_from('<B', data, offset)[0]
        offset += 1
        firehose_data.unknown = data[offset:offset + 2]
        offset += 2
        firehose_data.public_data_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        firehose_data.private_data_virtual_offset = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        firehose_data.unknown2 = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        firehose_data.unknown3 = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        firehose_data.base_continous_time = struct.unpack_from('<Q', data, offset)[0]
        offset += 8

        log_data_start = offset
        public_data_size_offset = 16
        public_data_end = offset + (firehose_data.public_data_size - public_data_size_offset)
        public_data = data[offset:public_data_end]

        # Go through all the public data associated with log Firehose entry
        pub_offset = 0
        while pub_offset < len(public_data):
            remaining, firehose_public_data = FirehosePreamble._parse_firehose(
                public_data[pub_offset:]
            )
            pub_offset = len(public_data) - len(remaining)

            if (firehose_public_data.unknown_log_activity_type not in FirehosePreamble.LOG_TYPES
                    or len(remaining) < 24):
                if firehose_public_data.unknown_log_activity_type == FirehosePreamble.REMNANT_DATA:
                    firehose_data.public_data.append(firehose_public_data)
                    break
                firehose_data.public_data.append(firehose_public_data)
                break

            firehose_data.public_data.append(firehose_public_data)

        # Calculate where input data should resume
        input_offset = log_data_start + (firehose_data.public_data_size - public_data_size_offset)

        # Handle private data
        if firehose_data.private_data_virtual_offset != 0x1000:
            logger.debug("[macos-unifiedlogs] Parsing Private Firehose Data")

            # Calculate start of private data
            private_offset = 0x1000 - firehose_data.private_data_virtual_offset
            if len(data) > input_offset + private_offset:
                private_input = data[input_offset + private_offset:]
            else:
                private_input = data[input_offset:]

            # Skip zero padding (unless collapsed)
            if firehose_data.collapsed != 1:
                while private_input and private_input[0] == 0:
                    private_input = private_input[1:]

            # Update items with private data
            for firehose_entry in firehose_data.public_data:
                if firehose_entry.firehose_non_activity.private_strings_size == 0:
                    continue

                string_offset = (firehose_entry.firehose_non_activity.private_strings_offset
                                 - firehose_data.private_data_virtual_offset)
                if string_offset < len(private_input):
                    private_string_start = private_input[string_offset:]
                    FirehosePreamble._parse_private_data(
                        private_string_start, firehose_entry.message
                    )

        return (data[input_offset:], firehose_data)

    @staticmethod
    def _parse_firehose(data: bytes) -> Tuple[bytes, Firehose]:
        """Parse all the different types of Firehose data.

        Args:
            data: Raw bytes starting at firehose entry

        Returns:
            Tuple of (remaining data, Firehose)
        """
        firehose_results = Firehose()
        offset = 0

        firehose_results.unknown_log_activity_type = struct.unpack_from('<B', data, offset)[0]
        offset += 1
        firehose_results.unknown_log_type = struct.unpack_from('<B', data, offset)[0]
        offset += 1
        firehose_results.flags = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        firehose_results.format_string_location = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        firehose_results.thread_id = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        firehose_results.continous_time_delta = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        firehose_results.continous_time_delta_upper = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        firehose_results.data_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2

        # Extract the data for this entry
        firehose_input = data[offset:offset + firehose_results.data_size]
        input_after_entry = data[offset + firehose_results.data_size:]

        # Log activity types
        ACTIVITY = 0x2
        SIGNPOST = 0x6
        NONACTIVITY = 0x4
        LOSS = 0x7
        TRACE = 0x3
        UNKNOWN_REMNANT = 0x0

        firehose_offset = 0
        if firehose_results.unknown_log_activity_type == ACTIVITY:
            remaining, activity = FirehoseActivity.parse_activity(
                firehose_input, firehose_results.flags, firehose_results.unknown_log_type
            )
            firehose_results.firehose_activity = activity
            firehose_offset = len(firehose_input) - len(remaining)
        elif firehose_results.unknown_log_activity_type == NONACTIVITY:
            remaining, non_activity = FirehoseNonActivity.parse_non_activity(
                firehose_input, firehose_results.flags
            )
            firehose_results.firehose_non_activity = non_activity
            firehose_offset = len(firehose_input) - len(remaining)
        elif firehose_results.unknown_log_activity_type == SIGNPOST:
            remaining, signpost = FirehoseSignpost.parse_signpost(
                firehose_input, firehose_results.flags
            )
            firehose_results.firehose_signpost = signpost
            firehose_offset = len(firehose_input) - len(remaining)
        elif firehose_results.unknown_log_activity_type == LOSS:
            remaining, loss = FirehoseLoss.parse_firehose_loss(firehose_input)
            firehose_results.firehose_loss = loss
            firehose_offset = len(firehose_input) - len(remaining)
        elif firehose_results.unknown_log_activity_type == TRACE:
            remaining, trace = FirehoseTrace.parse_firehose_trace(
                firehose_input, firehose_results.flags
            )
            firehose_results.firehose_trace = trace
            firehose_results.message = trace.message_data
            firehose_offset = len(firehose_input) - len(remaining)
        elif firehose_results.unknown_log_activity_type == UNKNOWN_REMNANT:
            return (input_after_entry, firehose_results)
        else:
            logger.warning(
                f"[macos-unifiedlogs] Unknown log activity type: "
                f"{firehose_results.unknown_log_activity_type}"
            )
            return (input_after_entry, firehose_results)

        # Parse items if we have enough data
        remaining_firehose = firehose_input[firehose_offset:]
        minimum_item_size = 6
        if len(remaining_firehose) < minimum_item_size:
            # Skip zero padding
            while input_after_entry and input_after_entry[0] == 0:
                input_after_entry = input_after_entry[1:]
            return (input_after_entry, firehose_results)

        firehose_results.unknown_item = struct.unpack_from('<B', remaining_firehose, 0)[0]
        firehose_results.number_items = struct.unpack_from('<B', remaining_firehose, 1)[0]

        _, firehose_item_data = FirehosePreamble.collect_items(
            remaining_firehose[2:], firehose_results.number_items, firehose_results.flags
        )
        firehose_results.message = firehose_item_data

        # Calculate padding and advance
        padding = padding_size_8(firehose_results.data_size)
        result_offset = offset + firehose_results.data_size + padding
        return (data[result_offset:], firehose_results)

    @staticmethod
    def collect_items(
        data: bytes, firehose_number_items: int, firehose_flags: int
    ) -> Tuple[bytes, FirehoseItemData]:
        """Collect all the Firehose items (log message entries) in the log entry.

        Args:
            data: Raw bytes at start of items
            firehose_number_items: Number of items to collect
            firehose_flags: Flags from firehose entry

        Returns:
            Tuple of (remaining data, FirehoseItemData)
        """
        items_data: List[FirehoseItemType] = []
        firehose_item_data = FirehoseItemData()

        # Item type categories
        NUMBER_ITEM_TYPE = [0x0, 0x2]
        PRECISION_ITEMS = [0x10, 0x12]
        SENSITIVE_ITEMS = [0x5, 0x45, 0x85]
        OBJECT_ITEMS = [0x40, 0x42]

        firehose_input = data
        item_count = 0

        # First pass: collect item metadata
        while item_count < firehose_number_items and firehose_input:
            remaining, item = FirehosePreamble._get_firehose_items(firehose_input)
            firehose_input = remaining

            # Precision items just contain the length for the actual item
            if item.item_type in PRECISION_ITEMS:
                items_data.append(item)
                item_count += 1
                continue

            # Number items have values immediately after type
            if item.item_type in NUMBER_ITEM_TYPE:
                remaining, message_number = FirehosePreamble._parse_item_number(
                    firehose_input, item.item_size
                )
                item.message_strings = str(message_number)
                firehose_input = remaining
                item_count += 1
                items_data.append(item)
                continue

            # A message size of 0 for object type is "(null)"
            if item.message_string_size == 0 and item.item_type in OBJECT_ITEMS:
                item.message_strings = "(null)"

            items_data.append(item)
            item_count += 1

        # Check for backtrace data
        HAS_CONTEXT_DATA = 0x1000
        BACKTRACE_SIGNATURE_SIZE = 3
        BACKTRACE_SIGNATURE = bytes([1, 0, 18])

        if (firehose_flags & HAS_CONTEXT_DATA) != 0:
            logger.debug("[macos-unifiedlogs] Identified Backtrace data in Firehose log chunk")
            remaining, backtrace_data = FirehosePreamble._get_backtrace_data(firehose_input)
            firehose_input = remaining
            firehose_item_data.backtrace_strings = backtrace_data
        elif len(firehose_input) > BACKTRACE_SIGNATURE_SIZE:
            if firehose_input[:BACKTRACE_SIGNATURE_SIZE] == BACKTRACE_SIGNATURE:
                remaining, backtrace_data = FirehosePreamble._get_backtrace_data(firehose_input)
                firehose_input = remaining
                firehose_item_data.backtrace_strings = backtrace_data

        # Second pass: get string values
        for item in items_data:
            # Skip number items (already handled)
            if item.item_type in NUMBER_ITEM_TYPE:
                continue

            # Private strings
            if item.item_type in FirehosePreamble.PRIVATE_STRINGS or item.item_type in SENSITIVE_ITEMS:
                item.message_strings = "<private>"
                continue

            if item.item_type == FirehosePreamble.PRIVATE_NUMBER:
                continue

            # Skip precision items
            if item.item_type in PRECISION_ITEMS:
                continue

            if item.message_string_size == 0 and item.message_strings:
                continue

            if not firehose_input:
                break

            if item.item_type in FirehosePreamble.STRING_ITEM:
                remaining, message_string = FirehosePreamble._parse_item_string(
                    firehose_input, item.item_type, item.message_string_size
                )
                firehose_input = remaining
                item.message_strings = message_string
            else:
                logger.error(f"[macos-unifiedlogs] Unknown Firehose item: {item.item_type}")

        # Convert to FirehoseItemInfo
        for item in items_data:
            item_info = FirehoseItemInfo(
                message_strings=item.message_strings,
                item_type=item.item_type,
                item_size=item.message_string_size,
            )
            firehose_item_data.item_info.append(item_info)

        return (firehose_input, firehose_item_data)

    @staticmethod
    def _parse_private_data(data: bytes, firehose_item_data: FirehoseItemData) -> Tuple[bytes, None]:
        """Parse any private firehose data and update firehose items.

        Args:
            data: Raw bytes at start of private data
            firehose_item_data: FirehoseItemData to update

        Returns:
            Tuple of (remaining data, None)
        """
        PRIVATE_STRINGS = [0x21, 0x25, 0x41, 0x35, 0x31, 0x81, 0xf1]
        PRIVATE_NUMBER = 0x1

        private_string_start = data

        for firehose_info in firehose_item_data.item_info:
            if firehose_info.item_type in PRIVATE_STRINGS:
                # Base64 encode arbitrary data
                if firehose_info.item_type in [PRIVATE_STRINGS[3], PRIVATE_STRINGS[4]]:
                    if len(private_string_start) < firehose_info.item_size:
                        firehose_info.message_strings = encode_standard(private_string_start)
                        private_string_start = b''
                        continue

                    pointer_object = private_string_start[:firehose_info.item_size]
                    private_string_start = private_string_start[firehose_info.item_size:]
                    firehose_info.message_strings = encode_standard(pointer_object)
                    continue

                # Even null values are marked private
                if firehose_info.item_size == 0:
                    firehose_info.message_strings = "<private>"
                else:
                    remaining, private_string = extract_string_size(
                        private_string_start, firehose_info.item_size
                    )
                    private_string_start = remaining
                    firehose_info.message_strings = private_string

            elif firehose_info.item_type == PRIVATE_NUMBER:
                PRIVATE_NUMBER_FLAG = 0x8000
                if firehose_info.item_size == PRIVATE_NUMBER_FLAG:
                    firehose_info.message_strings = "<private>"
                else:
                    remaining, private_number = FirehosePreamble._parse_item_number(
                        private_string_start, firehose_info.item_size
                    )
                    private_string_start = remaining
                    firehose_info.message_strings = str(private_number)

        return (private_string_start, None)

    @staticmethod
    def _get_backtrace_data(data: bytes) -> Tuple[bytes, List[str]]:
        """Parse Backtrace data for log entry.

        Args:
            data: Raw bytes at start of backtrace

        Returns:
            Tuple of (remaining data, list of backtrace strings)
        """
        offset = 3  # Skip unknown data

        uuid_count = struct.unpack_from('<B', data, offset)[0]
        offset += 1
        offset_count = struct.unpack_from('<H', data, offset)[0]
        offset += 2

        # Parse UUIDs
        uuid_vec = []
        for _ in range(uuid_count):
            uuid_high = struct.unpack_from('>Q', data, offset)[0]
            uuid_low = struct.unpack_from('>Q', data, offset + 8)[0]
            uuid_vec.append((uuid_high << 64) | uuid_low)
            offset += 16

        # Parse offsets
        offsets_vec = []
        for _ in range(offset_count):
            offsets_vec.append(struct.unpack_from('<I', data, offset)[0])
            offset += 4

        # Parse indexes
        indexes = []
        for _ in range(offset_count):
            indexes.append(struct.unpack_from('<B', data, offset)[0])
            offset += 1

        # Build backtrace strings
        backtrace_data = []
        for i, idx in enumerate(indexes):
            uuid = uuid_vec[idx] if idx < len(uuid_vec) else 0
            off = offsets_vec[i] if i < len(offsets_vec) else 0
            backtrace_data.append(f'"{uuid:032X}" +0x{off:x}')

        # Calculate padding
        padding = padding_size_four(offset_count)
        offset += padding

        return (data[offset:], backtrace_data)

    @staticmethod
    def _get_firehose_items(data: bytes) -> Tuple[bytes, FirehoseItemType]:
        """Get the strings, precision, and private firehose message items.

        Args:
            data: Raw bytes at start of item

        Returns:
            Tuple of (remaining data, FirehoseItemType)
        """
        offset = 0

        item_type = struct.unpack_from('<B', data, offset)[0]
        offset += 1
        item_size = struct.unpack_from('<B', data, offset)[0]
        offset += 1

        item = FirehoseItemType(item_type=item_type, item_size=item_size)

        # String and private number items metadata is 4 bytes
        STRING_ITEM = [0x20, 0x21, 0x22, 0x25, 0x40, 0x41, 0x42, 0x30, 0x31, 0x32, 0xf2, 0x35, 0x81, 0xf1]
        PRIVATE_NUMBER = 0x1

        if item_type in STRING_ITEM or item_type == PRIVATE_NUMBER:
            item.offset = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            item.message_string_size = struct.unpack_from('<H', data, offset)[0]
            offset += 2

        # Precision items
        PRECISION_ITEMS = [0x10, 0x12]
        if item_type in PRECISION_ITEMS:
            offset += item_size

        # Sensitive items
        SENSITIVE_ITEMS = [0x5, 0x45, 0x85]
        if item_type in SENSITIVE_ITEMS:
            item.offset = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            item.message_string_size = struct.unpack_from('<H', data, offset)[0]
            offset += 2

        return (data[offset:], item)

    @staticmethod
    def _parse_item_string(
        data: bytes, item_type: int, message_size: int
    ) -> Tuple[bytes, str]:
        """Parse the item string.

        Args:
            data: Raw bytes at start of string data
            item_type: Type of item
            message_size: Size of message

        Returns:
            Tuple of (remaining data, string value)
        """
        if message_size > len(data):
            remaining, result = extract_string_size(data, len(data))
            return (remaining, result)

        message_data = data[:message_size]
        remaining = data[message_size:]

        # Arbitrary data types need base64 encoding
        ARBITRARY = [0x30, 0x31, 0x32]
        if item_type in ARBITRARY:
            return (remaining, encode_standard(message_data))

        BASE64_RAW_BYTES = 0xf2
        if item_type == BASE64_RAW_BYTES:
            return (remaining, encode_standard(message_data))

        _, message_string = extract_string_size(message_data, message_size)
        return (remaining, message_string)

    @staticmethod
    def _parse_item_number(data: bytes, item_size: int) -> Tuple[bytes, int]:
        """Parse the Firehose item number.

        Args:
            data: Raw bytes at start of number
            item_size: Size of number in bytes

        Returns:
            Tuple of (remaining data, number value)
        """
        if item_size == 4:
            value = struct.unpack_from('<i', data, 0)[0]
            return (data[4:], value)
        elif item_size == 2:
            value = struct.unpack_from('<h', data, 0)[0]
            return (data[2:], value)
        elif item_size == 8:
            value = struct.unpack_from('<q', data, 0)[0]
            return (data[8:], value)
        elif item_size == 1:
            value = struct.unpack_from('<b', data, 0)[0]
            return (data[1:], value)
        else:
            logger.warning(f"[macos-unifiedlogs] Unknown number size support: {item_size}")
            return (data, -9999)
