# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Open Directory decoders for Unified Log format strings."""

import base64
import logging
import struct
from typing import Tuple

from ..error import DecoderError

logger = logging.getLogger(__name__)

# Open Directory error codes from https://developer.apple.com/documentation/opendirectory/odframeworkerrors
OD_ERRORS = {
    "5301": "ODErrorCredentialsAccountDisabled",
    "5302": "ODErrorCredentialsAccountExpired",
    "5303": "ODErrorCredentialsAccountInactive",
    "5300": "ODErrorCredentialsAccountNotFound",
    "5000": "ODErrorCredentialsInvalid",
    "5001": "ODErrorCredentialsInvalidComputer",
    "5500": "ODErrorCredentialsInvalidLogonHours",
    "5100": "ODErrorCredentialsMethodNotSupported",
    "5101": "ODErrorCredentialsNotAuthorized",
    "5103": "ODErrorCredentialsOperationFailed",
    "5102": "ODErrorCredentialsParameterError",
    "5401": "ODErrorCredentialsPasswordChangeRequired",
    "5407": "ODErrorCredentialsPasswordChangeTooSoon",
    "5400": "ODErrorCredentialsPasswordExpired",
    "5406": "ODErrorCredentialsPasswordNeedsDigit",
    "5405": "ODErrorCredentialsPasswordNeedsLetter",
    "5402": "ODErrorCredentialsPasswordQualityFailed",
    "5403": "ODErrorCredentialsPasswordTooShort",
    "5404": "ODErrorCredentialsPasswordTooLong",
    "5408": "ODErrorCredentialsPasswordUnrecoverable",
    "5205": "ODErrorCredentialsServerCommunicationError",
    "5202": "ODErrorCredentialsServerError",
    "5201": "ODErrorCredentialsServerNotFound",
    "5203": "ODErrorCredentialsServerTimeout",
    "5200": "ODErrorCredentialsServerUnreachable",
    "10002": "ODErrorDaemonError",
    "2100": "ODErrorNodeConnectionFailed",
    "2002": "ODErrorNodeDisabled",
    "2200": "ODErrorNodeUnknownHost",
    "2000": "ODErrorNodeUnknownName",
    "2001": "ODErrorNodeUnknownType",
    "10001": "ODErrorPluginError",
    "10000": "ODErrorPluginOperationNotSupported",
    "10003": "ODErrorPluginOperationTimeout",
    "6001": "ODErrorPolicyOutOfRange",
    "6000": "ODErrorPolicyUnsupported",
    "3100": "ODErrorQueryInvalidMatchType",
    "3000": "ODErrorQuerySynchronize",
    "3102": "ODErrorQueryTimeout",
    "3101": "ODErrorQueryUnsupportedMatchType",
    "4102": "ODErrorRecordAlreadyExists",
    "4201": "ODErrorRecordAttributeNotFound",
    "4200": "ODErrorRecordAttributeUnknownType",
    "4203": "ODErrorRecordAttributeValueNotFound",
    "4202": "ODErrorRecordAttributeValueSchemaError",
    "4101": "ODErrorRecordInvalidType",
    "4104": "ODErrorRecordNoLongerExists",
    "4100": "ODErrorRecordParameterError",
    "4001": "ODErrorRecordPermissionError",
    "4000": "ODErrorRecordReadOnlyNode",
    "4103": "ODErrorRecordTypeDisabled",
    "1002": "ODErrorSessionDaemonNotRunning",
    "1003": "ODErrorSessionDaemonRefused",
    "1000": "ODErrorSessionLocalOnlyDaemonInUse",
    "1001": "ODErrorSessionNormalDaemonInUse",
    "1100": "ODErrorSessionProxyCommunicationError",
    "1102": "ODErrorSessionProxyIPUnreachable",
    "1103": "ODErrorSessionProxyUnknownHost",
    "1101": "ODErrorSessionProxyVersionMismatch",
    "0": "ODErrorSuccess",
    "5305": "ODErrorCredentialsAccountLocked",
    "5304": "ODErrorCredentialsAccountTemporarilyLocked",
    "5204": "ODErrorCredentialsContactPrimary",
    "2": "Not Found",
}

# Member ID types from /usr/include/membership.h
MEMBER_ID_TYPES = {
    "0": "UID",
    "1": "GID",
    "3": "SID",
    "4": "USERNAME",
    "5": "GROUPNAME",
    "6": "UUID",
    "7": "GROUP NFS",
    "8": "USER NFS",
    "10": "GSS EXPORT NAME",
    "11": "X509 DN",
    "12": "KERBEROS",
}


def errors(oderror: str) -> str:
    """Convert Open Directory error codes to message.

    Args:
        oderror: Error code as string

    Returns:
        Human-readable error message
    """
    if oderror in OD_ERRORS:
        return OD_ERRORS[oderror]

    logger.warning(f"[macos-unifiedlogs] Unknown open directory error code: {oderror}")
    return oderror


def member_id_type(member_string: str) -> str:
    """Convert Open Directory member ids to string.

    Args:
        member_string: Member ID type as string

    Returns:
        Human-readable member type
    """
    if member_string in MEMBER_ID_TYPES:
        return MEMBER_ID_TYPES[member_string]

    logger.warning(f"[macos-unifiedlogs] Unknown open directory member id type: {member_string}")
    return member_string


def member_details(input_str: str) -> str:
    """Convert Open Directory member details to string.

    Args:
        input_str: Base64 encoded member details data

    Returns:
        Human-readable member details

    Raises:
        DecoderError: If data cannot be decoded or parsed
    """
    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode open directory member details data: {input_str}") from e

    try:
        return _get_member_data(decoded_data)
    except Exception as e:
        raise DecoderError(f"Failed to get open directory member details: {input_str}") from e


def sid_details(input_str: str) -> str:
    """Parse SID log data to SID string.

    Args:
        input_str: Base64 encoded SID data

    Returns:
        SID string (e.g., "S-1-5-21-...")

    Raises:
        DecoderError: If data cannot be decoded or parsed
    """
    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode open directory SID details data: {input_str}") from e

    try:
        return _get_sid_data(decoded_data)
    except Exception as e:
        raise DecoderError(f"Failed to get open directory sid details: {input_str}") from e


def _extract_cstring(data: bytes, offset: int) -> Tuple[int, str]:
    """Extract a null-terminated C string from bytes.

    Args:
        data: Raw bytes
        offset: Starting offset

    Returns:
        Tuple of (new offset, extracted string)
    """
    end = offset
    while end < len(data) and data[end] != 0:
        end += 1

    string_data = data[offset:end]
    try:
        result = string_data.decode('utf-8')
    except UnicodeDecodeError:
        result = string_data.decode('latin-1')

    return end + 1, result


def _get_member_data(data: bytes) -> str:
    """Parse Open Directory membership details data.

    Args:
        data: Raw member data bytes

    Returns:
        Formatted member details string
    """
    if len(data) < 1:
        raise ValueError("Data too short for member data")

    member_type = data[0]
    offset = 1

    if member_type in [35, 163]:  # UID
        if len(data) < offset + 4:
            raise ValueError("Data too short for UID")
        uid = struct.unpack_from('<i', data, offset)[0]
        offset += 4
        member_message = f"user: {uid}"

    elif member_type in [36, 160, 164]:  # USER
        offset, name = _extract_cstring(data, offset)
        member_message = f"user: {name}"

    elif member_type == 68:  # GROUP
        offset, name = _extract_cstring(data, offset)
        member_message = f"group: {name}"

    elif member_type == 195:  # GID
        if len(data) < offset + 4:
            raise ValueError("Data too short for GID")
        gid = struct.unpack_from('<i', data, offset)[0]
        offset += 4
        member_message = f"group: {gid}"

    else:
        logger.warning(f"[macos-unifiedlogs] Unknown open directory member type: {member_type}")
        member_message = f"Unknown Member type {member_type}: @"

    # Try to extract source path
    try:
        _, source_path = _extract_cstring(data, offset)
        source_path_str = f"@{source_path}"
    except Exception:
        source_path_str = " <not found>"

    return f"{member_message}{source_path_str}"


def _get_sid_data(data: bytes) -> str:
    """Parse the SID data.

    Args:
        data: Raw SID data bytes

    Returns:
        SID string (e.g., "S-1-5-21-...")
    """
    if len(data) < 4:
        raise ValueError("Data too short for SID")

    offset = 0
    revision = data[offset]
    offset += 1

    unknown_size = data[offset]
    offset += 1
    offset += unknown_size  # Skip unknown data

    authority = data[offset]
    offset += 1

    subauthority = data[offset]
    offset += 1
    offset += 3  # Skip 3 bytes of padding

    # Build SID string
    sid_parts = [f"S-{revision}-{authority}-{subauthority}"]

    # Parse additional subauthorities (u32 values)
    while offset + 4 <= len(data):
        additional = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        sid_parts.append(str(additional))

    return "-".join(sid_parts)
