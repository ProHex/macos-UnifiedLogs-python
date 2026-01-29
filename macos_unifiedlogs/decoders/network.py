# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Network address decoders for Unified Log format strings."""

import base64
import ipaddress
import logging
import struct
from typing import Union

from ..error import DecoderError

logger = logging.getLogger(__name__)


def ipv_six(input_str: str) -> ipaddress.IPv6Address:
    """Parse an IPv6 address from base64 encoded data.

    Args:
        input_str: Base64 encoded IPv6 address

    Returns:
        IPv6Address object

    Raises:
        DecoderError: If data cannot be decoded or parsed
    """
    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode ipv6 data: {input_str}") from e

    try:
        return get_ip_six(decoded_data)
    except Exception as e:
        raise DecoderError(f"Failed to get ipv6: {input_str}") from e


def ipv_four(input_str: str) -> ipaddress.IPv4Address:
    """Parse an IPv4 address from base64 encoded data.

    Args:
        input_str: Base64 encoded IPv4 address

    Returns:
        IPv4Address object

    Raises:
        DecoderError: If data cannot be decoded or parsed
    """
    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode ipv4 data: {input_str}") from e

    try:
        return get_ip_four(decoded_data)
    except Exception as e:
        raise DecoderError(f"Failed to get ipv4: {input_str}") from e


def sockaddr(input_str: str) -> str:
    """Parse a sockaddr structure from base64 encoded data.

    Args:
        input_str: Base64 encoded sockaddr data

    Returns:
        String representation of the socket address

    Raises:
        DecoderError: If data cannot be decoded or parsed
    """
    if not input_str:
        return "<NULL>"

    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode sockaddr data: {input_str}") from e

    try:
        return get_sockaddr_data(decoded_data)
    except Exception as e:
        raise DecoderError(f"Failed to get sockaddr structure: {input_str}") from e


def get_sockaddr_data(data: bytes) -> str:
    """Get the sockaddr data from raw bytes.

    Args:
        data: Raw sockaddr structure bytes

    Returns:
        String representation of the socket address
    """
    if len(data) < 2:
        raise ValueError("Data too short for sockaddr")

    _total_length = data[0]
    family = data[1]
    offset = 2

    # Family types seen so far (AF_INET should be used most often)
    if family == 2:  # AF_INET
        if len(data) < offset + 6:
            raise ValueError("Data too short for AF_INET sockaddr")

        port = struct.unpack_from('>H', data, offset)[0]
        offset += 2
        ip_addr = get_ip_four(data[offset:offset + 4])

        if port == 0:
            return str(ip_addr)
        return f"{ip_addr}:{port}"

    elif family == 30:  # AF_INET6
        if len(data) < offset + 24:
            raise ValueError("Data too short for AF_INET6 sockaddr")

        port = struct.unpack_from('>H', data, offset)[0]
        offset += 2
        flow = struct.unpack_from('>I', data, offset)[0]
        offset += 4
        ip_addr = get_ip_six(data[offset:offset + 16])
        offset += 16
        scope = struct.unpack_from('>I', data, offset)[0]

        if port == 0:
            return f"{ip_addr}, Flow ID: {flow}, Scope ID: {scope}"
        return f"{ip_addr}:{port}, Flow ID: {flow}, Scope ID: {scope}"

    else:
        logger.warning(f"[macos-unifiedlogs] Unknown sockaddr family: {family}. From: {data!r}")
        return f"Unknown sockaddr family: {family}"


def get_ip_four(data: bytes) -> ipaddress.IPv4Address:
    """Get the IPv4 data from raw bytes.

    Args:
        data: Raw IPv4 address bytes (4 bytes, big endian)

    Returns:
        IPv4Address object
    """
    if len(data) < 4:
        raise ValueError("Data too short for IPv4 address")

    ip_int = struct.unpack_from('>I', data, 0)[0]
    return ipaddress.IPv4Address(ip_int)


def get_ip_six(data: bytes) -> ipaddress.IPv6Address:
    """Get the IPv6 data from raw bytes.

    Args:
        data: Raw IPv6 address bytes (16 bytes, big endian)

    Returns:
        IPv6Address object
    """
    if len(data) < 16:
        raise ValueError("Data too short for IPv6 address")

    # Read as two big-endian 64-bit integers
    high = struct.unpack_from('>Q', data, 0)[0]
    low = struct.unpack_from('>Q', data, 8)[0]
    ip_int = (high << 64) | low
    return ipaddress.IPv6Address(ip_int)
