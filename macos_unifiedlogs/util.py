# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Utility functions for parsing macOS Unified Logs."""

import base64
import logging
from datetime import datetime, timezone
from typing import Tuple

logger = logging.getLogger(__name__)


def anticipated_padding_size_8(items_count: int, items_size: int) -> int:
    """Returns the padding to consume in order to align to 8 bytes.

    Actual total size is computed as items_count * items_size.
    """
    return anticipated_padding_size(items_count, items_size, 8)


def anticipated_padding_size(items_count: int, items_size: int, alignment: int) -> int:
    """Returns the padding to consume in order to align to 'alignment' bytes.

    Actual total size is computed as items_count * items_size.
    """
    total_size = items_count * items_size
    return padding_size(total_size, alignment)


def padding_size_8(data_size: int) -> int:
    """Calculate 8 byte padding."""
    return padding_size(data_size, 8)


def padding_size_four(data_size: int) -> int:
    """Calculate 4 byte padding."""
    return padding_size(data_size, 4)


def padding_size(data_size: int, alignment: int) -> int:
    """Calculate padding based on provided alignment."""
    return (alignment - (data_size & (alignment - 1))) & (alignment - 1)


def extract_string_size(data: bytes, message_size: int) -> Tuple[bytes, str]:
    """Extract a size-based string from Firehose string item entries.

    Args:
        data: The byte data to extract from
        message_size: The size of the message to extract

    Returns:
        Tuple of (remaining data, extracted string)
    """
    if message_size == 0:
        return (data, "(null)")

    # If our remaining data is smaller than the message string size just go until the end
    if len(data) < message_size:
        try:
            result = data.decode('utf-8').rstrip('\x00')
            return (b'', result)
        except UnicodeDecodeError as err:
            logger.error(f"[macos-unifiedlogs] Failed to extract specific string size: {err}")
            return (b'', "Could not find path string")

    # Get whole string message except end of string (0s)
    path_bytes = data[:message_size]
    remaining = data[message_size:]

    try:
        result = path_bytes.decode('utf-8').rstrip('\x00')
        return (remaining, result)
    except UnicodeDecodeError as err:
        logger.error(f"[macos-unifiedlogs] Failed to get specific string: {err}")
        return (remaining, "Could not find path string")


def extract_string(data: bytes) -> Tuple[bytes, str]:
    """Extract strings that contain end of string characters.

    Args:
        data: The byte data to extract from

    Returns:
        Tuple of (remaining data, extracted string)
    """
    if not data:
        logger.error("[macos-unifiedlogs] Cannot extract string. Empty input.")
        return (data, "Cannot extract string. Empty input.")

    # If message data does not end with end of string character (0)
    # just grab everything and convert what we have to string
    if data[-1] != 0:
        try:
            result = data.decode('utf-8')
            return (b'', result)
        except UnicodeDecodeError as err:
            logger.warning(f"[macos-unifiedlogs] Failed to extract full string: {err}")
            return (b'', "Could not extract string")

    # Find the first null byte
    null_pos = data.find(b'\x00')
    if null_pos == -1:
        null_pos = len(data)

    path_bytes = data[:null_pos]
    remaining = data[null_pos:]

    try:
        result = path_bytes.decode('utf-8')
        return (remaining, result)
    except UnicodeDecodeError as err:
        logger.warning(f"[macos-unifiedlogs] Failed to get string: {err}")
        return (remaining, "Could not extract string")


def non_empty_cstring(data: bytes) -> Tuple[bytes, str]:
    """Extract a non-empty UTF8 string from a byte array.

    Stops at NULL_BYTE or end of string. Consumes the end byte.
    Raises ValueError if the string is empty.

    Args:
        data: The byte data to extract from

    Returns:
        Tuple of (remaining data, extracted string)

    Raises:
        ValueError: If the resulting string would be empty
    """
    if not data:
        return (data, "")

    # Find the first null byte
    null_pos = data.find(b'\x00')
    if null_pos == -1:
        # No null byte, take everything
        str_part = data
        remaining = b''
    else:
        str_part = data[:null_pos]
        remaining = data[null_pos + 1:]  # Skip the null byte

    try:
        result = str_part.decode('utf-8')
        if not result:
            raise ValueError("Empty string")
        return (remaining, result)
    except UnicodeDecodeError:
        raise ValueError("Failed to decode string")


def clean_uuid(uuid_format: str) -> str:
    """Clean and format UUIDs to be pretty."""
    return uuid_format.replace(',', '').replace('[', '').replace(']', '').replace(' ', '')


def encode_standard(data: bytes) -> str:
    """Base64 encode data using the STANDARD engine (alphabet along with "+" and "/")."""
    return base64.b64encode(data).decode('ascii')


def decode_standard(data: str) -> bytes:
    """Base64 decode data using the STANDARD engine (alphabet along with "+" and "/")."""
    return base64.b64decode(data)


def unixepoch_to_iso(timestamp: int) -> str:
    """Convert UnixEpoch time (nanoseconds) to ISO RFC 3339 format.

    Args:
        timestamp: Unix timestamp in nanoseconds

    Returns:
        ISO 8601 formatted timestamp string
    """
    # Convert nanoseconds to seconds
    seconds = timestamp / 1_000_000_000
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    # Format with nanosecond precision
    nanos = timestamp % 1_000_000_000
    return dt.strftime('%Y-%m-%dT%H:%M:%S') + f'.{nanos:09d}Z'
