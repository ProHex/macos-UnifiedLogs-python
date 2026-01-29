# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Apple object decoders for Unified Log format strings."""

from .decoder import check_objects
from .bool_decoder import uppercase_bool, lowercase_bool, lowercase_int_bool
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

__all__ = [
    'check_objects',
    'uppercase_bool',
    'lowercase_bool',
    'lowercase_int_bool',
    'errno_codes',
    'permission',
    'parse_time',
    'parse_uuid',
    'ipv_four',
    'ipv_six',
    'sockaddr',
    'client_authorization_status',
    'daemon_status_type',
    'subharvester_identifier',
    'sqlite_location',
    'client_manager_state_tracker_state',
    'location_manager_state_tracker_state',
    'io_message',
    'errors',
    'member_id_type',
    'member_details',
    'sid_details',
    'parse_dns_header',
    'get_domain_name',
    'get_service_binding',
    'get_dns_mac_addr',
    'dns_ip_addr',
    'dns_addrmv',
    'dns_records',
    'dns_reason',
    'dns_protocol',
    'dns_idflags',
    'dns_counts',
    'dns_yes_no',
    'dns_acceptable',
    'dns_getaddrinfo_opts',
]
