# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Main decoder dispatcher for Apple custom logging objects."""

import logging
from typing import List

from ..chunks.firehose.firehose_log import FirehoseItemInfo
from .bool_decoder import uppercase_bool, lowercase_bool
from .darwin import errno_codes, permission
from .time_decoder import parse_time
from .uuid_decoder import parse_uuid
from .network import ipv_four, ipv_six, sockaddr
from .location import (
    client_authorization_status,
    daemon_status_type,
    subharvester_identifier,
    sqlite_location,
    client_manager_state_tracker_state,
    location_manager_state_tracker_state,
    io_message,
)
from .opendirectory import errors, member_id_type, member_details, sid_details
from .dns import (
    parse_dns_header,
    get_domain_name,
    get_service_binding,
    get_dns_mac_addr,
    dns_ip_addr,
    dns_addrmv,
    dns_records,
    dns_reason,
    dns_protocol,
    dns_idflags,
    dns_counts,
    dns_yes_no,
    dns_acceptable,
    dns_getaddrinfo_opts,
)

logger = logging.getLogger(__name__)


def check_objects(
    format_string: str,
    message_values: List[FirehoseItemInfo],
    item_type: int,
    item_index: int,
) -> str:
    """Check if we support one of Apple's custom logging objects.

    Args:
        format_string: Format string containing object type info
        message_values: List of FirehoseItemInfo
        item_type: Type of the item
        item_index: Index into message_values

    Returns:
        Decoded object string, or empty string if not a supported object
    """
    index = item_index
    PRECISION_ITEM = 0x12

    # Increment index to get the actual firehose item data
    if item_type == PRECISION_ITEM:
        index += 1
        if index > len(message_values):
            return (
                f"Index out of bounds for FirehoseItemInfo Vec. "
                f"Got adjusted index {index}, Vec size is {len(message_values)}. "
                "This should not have happened"
            )

    MASKED_HASH_TYPE = 0xF2
    # Check if the log value is hashed or marked private
    if ((("mask.hash" in format_string) and message_values[index].item_type == MASKED_HASH_TYPE)
            or message_values[index].message_strings == "<private>"):
        return message_values[index].message_strings

    message_str = message_values[index].message_strings

    try:
        # Check if log value contains one of the supported decoders
        if "BOOL" in format_string:
            return uppercase_bool(message_str)
        elif "bool" in format_string:
            return lowercase_bool(message_str)
        elif "uuid_t" in format_string:
            return parse_uuid(message_str)
        elif "darwin.errno" in format_string:
            return errno_codes(message_str)
        elif "darwin.mode" in format_string:
            return permission(message_str)
        elif "odtypes:ODError" in format_string:
            return errors(message_str)
        elif "odtypes:mbridtype" in format_string:
            return member_id_type(message_str)
        elif "odtypes:mbr_details" in format_string:
            return member_details(message_str)
        elif "odtypes:nt_sid_t" in format_string:
            return sid_details(message_str)
        elif "location:CLClientAuthorizationStatus" in format_string:
            return client_authorization_status(message_str)
        elif "location:CLDaemonStatus_Type::Reachability" in format_string:
            return daemon_status_type(message_str)
        elif "location:CLSubHarvesterIdentifier" in format_string:
            return subharvester_identifier(message_str)
        elif "location:SqliteResult" in format_string:
            return sqlite_location(message_str)
        elif "location:_CLClientManagerStateTrackerState" in format_string:
            return client_manager_state_tracker_state(message_str)
        elif "location:_CLLocationManagerStateTrackerState" in format_string:
            return location_manager_state_tracker_state(message_str)
        elif "network:in6_addr" in format_string:
            return str(ipv_six(message_str))
        elif "network:in_addr" in format_string:
            return str(ipv_four(message_str))
        elif "network:sockaddr" in format_string:
            return sockaddr(message_str)
        elif "time_t" in format_string:
            return parse_time(message_str)
        elif "mdns:dnshdr" in format_string:
            return parse_dns_header(message_str)
        elif "mdns:rd.svcb" in format_string:
            return get_service_binding(message_str)
        elif "location:IOMessage" in format_string:
            return io_message(message_str)
        elif "mdnsresponder:domain_name" in format_string:
            return get_domain_name(message_str)
        elif "mdnsresponder:mac_addr" in format_string:
            return get_dns_mac_addr(message_str)
        elif "mdnsresponder:ip_addr" in format_string:
            return dns_ip_addr(message_str)
        elif "mdns:addrmv" in format_string:
            return dns_addrmv(message_str)
        elif "mdns:rrtype" in format_string:
            return dns_records(message_str)
        elif "mdns:nreason" in format_string:
            return dns_reason(message_str)
        elif "mdns:protocol" in format_string:
            return dns_protocol(message_str)
        elif "mdns:dns.idflags" in format_string:
            return dns_idflags(message_str)
        elif "mdns:dns.counts" in format_string:
            return str(dns_counts(message_str))
        elif "mdns:yesno" in format_string:
            return dns_yes_no(message_str)
        elif "mdns:acceptable" in format_string:
            return dns_acceptable(message_str)
        elif "mdns:gaiopts" in format_string:
            return dns_getaddrinfo_opts(message_str)
        else:
            return ""

    except Exception as e:
        logger.error(f"[macos-unifiedlogs] Failed to decode log object. Error: {e!r}")
        return str(e)
