# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""DNS decoders for Unified Log format strings."""

import base64
import logging
import struct
from dataclasses import dataclass
from typing import Tuple

from ..error import DecoderError
from ..util import extract_string, extract_string_size
from .network import get_ip_four, get_ip_six

logger = logging.getLogger(__name__)

# DNS record types from https://en.wikipedia.org/wiki/List_of_DNS_record_types
DNS_RECORD_TYPES = {
    "1": "A",
    "2": "NS",
    "5": "CNAME",
    "6": "SOA",
    "10": "NULL",
    "12": "PTR",
    "13": "HINFO",
    "15": "MX",
    "16": "TXT",
    "17": "RP",
    "18": "AFSDB",
    "24": "SIG",
    "25": "KEY",
    "28": "AAAA",
    "29": "LOC",
    "33": "SRV",
    "35": "NAPTR",
    "36": "KX",
    "37": "CERT",
    "39": "DNAME",
    "42": "APL",
    "43": "DS",
    "44": "SSHFP",
    "45": "IPSECKEY",
    "46": "RRSIG",
    "47": "NSEC",
    "48": "DNSKEY",
    "49": "DHCID",
    "50": "NSEC3",
    "51": "NSEC3PARAM",
    "52": "TLSA",
    "53": "SMIMEA",
    "55": "HIP",
    "59": "CDS",
    "60": "CDNSKEY",
    "61": "OPENPGPKEY",
    "62": "CSYNC",
    "63": "ZONEMD",
    "64": "SVCB",
    "65": "HTTPS",
    "108": "EUI48",
    "109": "EUI64",
    "249": "TKEY",
    "250": "TSIG",
    "255": "ANY",
    "256": "URI",
    "257": "CAA",
    "32768": "TA",
    "32769": "DLV",
}


@dataclass
class DnsCounts:
    """DNS header counts structure."""
    question: int = 0
    answer: int = 0
    authority: int = 0
    additional: int = 0

    def __str__(self) -> str:
        return (
            f"Question Count: {self.question}, Answer Record Count: {self.answer}, "
            f"Authority Record Count: {self.authority}, Additional Record Count: {self.additional}"
        )


def parse_dns_header(data: str) -> str:
    """Parse the DNS header.

    Args:
        data: Base64 encoded DNS header data

    Returns:
        Human-readable DNS header string

    Raises:
        DecoderError: If data cannot be decoded or parsed
    """
    try:
        decoded_data = base64.b64decode(data)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode DNS header details: {data}") from e

    try:
        return _get_dns_header(decoded_data)
    except Exception as e:
        raise DecoderError(f"Failed to parse DNS header details: {data}") from e


def _get_dns_header(data: bytes) -> str:
    """Get the DNS header data from raw bytes.

    Args:
        data: Raw DNS header bytes

    Returns:
        Human-readable DNS header string
    """
    if len(data) < 12:
        raise ValueError("Data too short for DNS header")

    offset = 0
    id_val = struct.unpack_from('>H', data, offset)[0]
    offset += 2

    flags = struct.unpack_from('>H', data, offset)[0]
    flags_message = _get_dns_flags(flags)
    offset += 2

    counts = _parse_counts(data[offset:])

    return f"Query ID: {id_val:#X}, Flags: {flags:#X} {flags_message}, {counts}"


def _get_dns_flags(flags: int) -> str:
    """Parse the DNS bit flags.

    Args:
        flags: 16-bit flags value

    Returns:
        Human-readable flags string
    """
    # https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format
    query = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    authoritative_flag = (flags >> 10) & 0x1
    truncation_flag = (flags >> 9) & 0x1
    recursion_desired = (flags >> 8) & 0x1
    recursion_available = (flags >> 7) & 0x1
    response_code = flags & 0xF

    opcode_messages = {
        0: "QUERY",
        1: "IQUERY",
        2: "STATUS",
        3: "RESERVED",
        4: "NOTIFY",
        5: "UPDATE",
    }
    opcode_message = opcode_messages.get(opcode, "UNKNOWN OPCODE")

    response_messages = {
        0: "No Error",
        1: "Format Error",
        2: "Server Failure",
        3: "NX Domain",
        4: "Not Implemented",
        5: "Refused",
        6: "YX Domain",
        7: "YX RR Set",
        8: "NX RR Set",
        9: "Not Auth",
        10: "Not Zone",
    }
    response_message = response_messages.get(response_code, "Unknown Response Code")

    return (
        f"Opcode: {opcode_message}, \n"
        f"    Query Type: {query},\n"
        f"    Authoritative Answer Flag: {authoritative_flag}, \n"
        f"    Truncation Flag: {truncation_flag}, \n"
        f"    Recursion Desired: {recursion_desired}, \n"
        f"    Recursion Available: {recursion_available}, \n"
        f"    Response Code: {response_message}"
    )


def _parse_counts(data: bytes) -> DnsCounts:
    """Parse just the DNS count data.

    Args:
        data: Raw DNS counts bytes (8 bytes)

    Returns:
        DnsCounts object
    """
    if len(data) < 8:
        raise ValueError("Data too short for DNS counts")

    question = struct.unpack_from('>H', data, 0)[0]
    answer = struct.unpack_from('>H', data, 2)[0]
    authority = struct.unpack_from('>H', data, 4)[0]
    additional = struct.unpack_from('>H', data, 6)[0]

    return DnsCounts(
        question=question,
        answer=answer,
        authority=authority,
        additional=additional,
    )


def get_domain_name(input_str: str) -> str:
    """Base64 decode the domain name.

    Args:
        input_str: Base64 encoded domain name

    Returns:
        Cleaned domain name string

    Raises:
        DecoderError: If data cannot be decoded
    """
    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode DNS name details: {input_str}") from e

    try:
        _, results = extract_string(decoded_data)
    except Exception as e:
        raise DecoderError(f"Failed to extract domain name from logs: {input_str}") from e

    # Clean domain name - replace non-printable characters with '.'
    clean_domain = ""
    non_domain_chars = ['\n', '\t', '\r']
    for char in results:
        if char in non_domain_chars or not char.isprintable() or ord(char) < 32:
            clean_domain += '.'
        else:
            clean_domain += char

    return clean_domain


def get_service_binding(input_str: str) -> str:
    """Parse DNS Service Binding record type.

    Args:
        input_str: Base64 encoded SVCB data

    Returns:
        Human-readable SVCB string

    Raises:
        DecoderError: If data cannot be decoded or parsed
    """
    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode DNS svcb details: {input_str}") from e

    try:
        return _parse_svcb(decoded_data)
    except Exception as e:
        raise DecoderError(f"Failed to parse DNS Service Binding data: {input_str}") from e


def _parse_svcb(data: bytes) -> str:
    """Parse DNS SVC Binding record.

    Args:
        data: Raw SVCB data bytes

    Returns:
        Human-readable SVCB string
    """
    # Format/documentation at https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/00/
    if len(data) < 6:
        raise ValueError("Data too short for SVCB")

    offset = 0
    id_val = struct.unpack_from('>H', data, offset)[0]
    offset += 2
    unknown_type = struct.unpack_from('>I', data, offset)[0]
    offset += 4

    DNS_OVER_HTTPS = 0x800000
    if unknown_type == DNS_OVER_HTTPS:
        url_size = data[offset]
        offset += 1
        _, url = extract_string_size(data[offset:], url_size)
        return url

    # ALPN = Application Layer Protocol Negotiation
    alpn_size = data[offset]
    offset += 1
    alpn_message = _parse_svcb_alpn(data[offset:offset + alpn_size])
    offset += alpn_size
    ip_message = _parse_svcb_ip(data[offset:])

    return f"rdata: {id_val} . {alpn_message} {ip_message}"


def _parse_svcb_alpn(data: bytes) -> str:
    """Parse the Application Layer Protocol Negotiation.

    Args:
        data: Raw ALPN data bytes

    Returns:
        ALPN string
    """
    message = "alpn="
    offset = 0

    while offset < len(data):
        alpn_entry_size = data[offset]
        offset += 1
        alpn_entry = data[offset:offset + alpn_entry_size]
        offset += alpn_entry_size
        _, alpn_name = extract_string(alpn_entry)
        message += alpn_name + ","

    return message


def _parse_svcb_ip(data: bytes) -> str:
    """Parse the IPs from SVCB record.

    Args:
        data: Raw IP data bytes

    Returns:
        IP hint string
    """
    IPV4 = 4
    IPV6 = 6

    ipv4s = []
    ipv6s = []
    offset = 0

    while offset + 4 <= len(data):
        ip_version = struct.unpack_from('>H', data, offset)[0]
        offset += 2
        ip_size = struct.unpack_from('>H', data, offset)[0]
        offset += 2

        if ip_version not in [IPV4, IPV6]:
            break

        if offset + ip_size > len(data):
            break

        ip_data = data[offset:offset + ip_size]
        offset += ip_size

        if ip_version == IPV4:
            ip_offset = 0
            while ip_offset + 4 <= len(ip_data):
                ip = get_ip_four(ip_data[ip_offset:ip_offset + 4])
                ipv4s.append(str(ip))
                ip_offset += 4
        elif ip_version == IPV6:
            ip_offset = 0
            while ip_offset + 16 <= len(ip_data):
                ip = get_ip_six(ip_data[ip_offset:ip_offset + 16])
                ipv6s.append(str(ip))
                ip_offset += 16

    return f"ipv4 hint:{','.join(ipv4s)}, ipv6 hint:{','.join(ipv6s)}"


def get_dns_mac_addr(input_str: str) -> str:
    """Get the MAC Address from the log data.

    Args:
        input_str: Base64 encoded MAC address

    Returns:
        MAC address string (e.g., "00:11:22:33:44:55")

    Raises:
        DecoderError: If data cannot be decoded
    """
    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode DNS mac address details: {input_str}") from e

    return ':'.join(f'{b:02X}' for b in decoded_data)


def dns_ip_addr(input_str: str) -> str:
    """Get IP Address info from log data.

    Args:
        input_str: Base64 encoded IP address data

    Returns:
        IP address string

    Raises:
        DecoderError: If data cannot be decoded or parsed
    """
    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode DNS ip address details: {input_str}") from e

    try:
        return _parse_dns_ip_addr(decoded_data)
    except Exception as e:
        raise DecoderError(f"Failed to parse DNS ip address data: {input_str}") from e


def _parse_dns_ip_addr(data: bytes) -> str:
    """Parse IP Address data.

    Args:
        data: Raw IP address data bytes

    Returns:
        IP address string
    """
    if len(data) < 4:
        raise ValueError("Data too short for IP address")

    ip_version = struct.unpack_from('<I', data, 0)[0]
    IPV4 = 4
    IPV6 = 6

    if ip_version == IPV4:
        return str(get_ip_four(data[4:8]))
    elif ip_version == IPV6:
        return str(get_ip_six(data[4:20]))
    else:
        raise ValueError(f"Unknown IP version: {ip_version}")


def dns_addrmv(data: str) -> str:
    """Translate DNS add/rmv log values.

    Args:
        data: "1" for add, other for rmv

    Returns:
        "add" or "rmv"
    """
    if data == "1":
        return "add"
    return "rmv"


def dns_records(data: str) -> str:
    """Translate DNS records to string.

    Args:
        data: DNS record type number as string

    Returns:
        DNS record type name

    Raises:
        DecoderError: If record type is unknown
    """
    if data in DNS_RECORD_TYPES:
        return DNS_RECORD_TYPES[data]

    raise DecoderError(f"Unknown DNS Resource Record Type: {data}")


def dns_reason(data: str) -> str:
    """Translate DNS response/reason to string.

    Args:
        data: DNS reason code as string

    Returns:
        Human-readable reason

    Raises:
        DecoderError: If reason code is unknown
    """
    reasons = {
        "1": "no-data",
        "2": "nxdomain",
        "3": "no-dns-service",
        "4": "query-suppressed",
        "5": "server error",
    }

    if data in reasons:
        return reasons[data]

    raise DecoderError(f"Unknown DNS Reason: {data}")


def dns_protocol(data: str) -> str:
    """Translate the DNS protocol used.

    Args:
        data: Protocol code as string

    Returns:
        Protocol name

    Raises:
        DecoderError: If protocol is unknown
    """
    protocols = {
        "1": "UDP",
        "2": "TCP",
        "4": "HTTPS",
    }

    if data in protocols:
        return protocols[data]

    raise DecoderError(f"Unknown DNS Protocol: {data}")


def dns_idflags(input_str: str) -> str:
    """Get just the DNS flags associated with the DNS header.

    Args:
        input_str: ID flags as integer string

    Returns:
        Human-readable ID flags string

    Raises:
        DecoderError: If data cannot be parsed
    """
    try:
        flags = int(input_str)
    except ValueError as e:
        raise DecoderError(f"Failed to convert ID Flags to int: {input_str}") from e

    # Convert to bytes (big endian)
    data = flags.to_bytes(4, byteorder='big')

    id_val = struct.unpack_from('>H', data, 0)[0]
    flags_val = struct.unpack_from('>H', data, 2)[0]

    try:
        flags_message = _get_dns_flags(flags_val)
    except Exception as e:
        logger.error(f"[macos-unifiedlogs] Failed to parse ID Flags: {e}")
        flags_message = "Failed to parse ID Flags"

    return f"id: {id_val:#X}, flags: {flags_val:#X} {flags_message}"


def dns_counts(input_str: str) -> DnsCounts:
    """Get just the DNS count data associated with the DNS header.

    Args:
        input_str: Counts as integer string

    Returns:
        DnsCounts object

    Raises:
        DecoderError: If data cannot be parsed
    """
    try:
        counts_int = int(input_str)
    except ValueError as e:
        raise DecoderError(f"Failed to convert counts to int: {input_str}") from e

    # Convert to bytes (big endian)
    data = counts_int.to_bytes(8, byteorder='big')

    return _parse_counts(data)


def dns_yes_no(data: str) -> str:
    """Translate DNS yes/no log values.

    Args:
        data: "0" for no, other for yes

    Returns:
        "yes" or "no"
    """
    if data == "0":
        return "no"
    return "yes"


def dns_acceptable(data: str) -> str:
    """Translate DNS acceptable log values.

    Args:
        data: "0" for unacceptable, other for acceptable

    Returns:
        "acceptable" or "unacceptable"
    """
    if data == "0":
        return "unacceptable"
    return "acceptable"


def dns_getaddrinfo_opts(data: str) -> str:
    """Translate DNS getaddrinfo log values.

    Args:
        data: Options code as string

    Returns:
        Human-readable options string

    Raises:
        DecoderError: If options code is unknown
    """
    options = {
        "0": "0x0 {}",
        "8": "0x8 {use-failover}",
        "12": "0xC {in-app-browser, use-failover}",
        "24": "0x18 {use-failover, prohibit-encrypted-dns}",
    }

    if data in options:
        return options[data]

    raise DecoderError(f"Unknown DNS getaddrinfo options: {data}")
