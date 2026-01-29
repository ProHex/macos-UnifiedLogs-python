# Copyright 2026 Aria Akhavan
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Location/GPS data decoders for Unified Log format strings."""

import base64
import logging
import struct
from dataclasses import dataclass, field
from typing import Tuple

from ..error import DecoderError
from .bool_decoder import lowercase_bool, lowercase_int_bool

logger = logging.getLogger(__name__)


@dataclass
class LocationTrackerState:
    """Location tracker state structure."""
    distance_filter: float = 0.0
    desired_accuracy: float = 0.0
    updating_location: int = 0
    requesting_location: int = 0
    requesting_ranging: int = 0
    updating_ranging: int = 0
    updating_heading: int = 0
    heading_filter: float = 0.0
    allows_location_prompts: int = 0
    allows_altered_locations: int = 0
    dynamic_accuracy: int = 0
    previous_authorization_status_valid: int = 0
    previous_authorization_status: int = 0
    limits_precision: int = 0
    activity_type: int = 0
    pauses_location_updates: int = 0
    paused: int = 0
    allows_background_updates: int = 0
    shows_background_location: int = 0
    allows_map_correction: int = 0
    batching_location: int = 0
    updating_vehicle_speed: int = 0
    updating_vehicle_heading: int = 0
    match_info: int = 0
    ground_altitude: int = 0
    fusion_info: int = 0
    courtesy_prompt: int = 0
    is_authorized_for_widgets: int = 0


def client_authorization_status(status: str) -> str:
    """Convert Core Location Client Authorization Status code to string.

    Args:
        status: Status code as string

    Returns:
        Human-readable status message

    Raises:
        DecoderError: If status code is unknown
    """
    status_map = {
        "0": "Not Determined",
        "1": "Restricted",
        "2": "Denied",
        "3": "Authorized Always",
        "4": "Authorized When In Use",
    }

    if status in status_map:
        return status_map[status]

    raise DecoderError(f"Unknown Core Location client authorization status: {status}")


def daemon_status_type(status: str) -> str:
    """Convert Core Location Daemon Status type to string.

    Args:
        status: Status code as string

    Returns:
        Human-readable status message

    Raises:
        DecoderError: If status code is unknown
    """
    status_map = {
        "0": "Reachability Unavailable",
        "1": "Reachability Small",
        "2": "Reachability Large",
        "56": "Reachability Unachievable",
    }

    if status in status_map:
        return status_map[status]

    raise DecoderError(f"Unknown Core Location daemon status type: {status}")


def subharvester_identifier(status: str) -> str:
    """Convert Core Location Subharvester id to string.

    Args:
        status: Subharvester ID as string

    Returns:
        Quoted string representation of the identifier

    Raises:
        DecoderError: If identifier is unknown
    """
    status_map = {
        "0": "CellLegacy",
        "1": "Cell",
        "2": "Wifi",
        "3": "Tracks",
        "4": "Realtime",
        "5": "App",
        "6": "Pass",
        "7": "Indoor",
        "8": "Pressure",
        "9": "Poi",
        "10": "Trace",
        "11": "Avenger",
        "12": "Altimeter",
        "13": "Ionosphere",
        "14": "Unknown",
    }

    if status in status_map:
        return f'"{status_map[status]}"'

    raise DecoderError(f"Unknown Core Location subharvester identifier type: {status}")


def sqlite_location(input_str: str) -> str:
    """Convert Core Location SQLITE code to string.

    Args:
        input_str: Base64 encoded sqlite result data

    Returns:
        SQLite result message

    Raises:
        DecoderError: If data cannot be decoded or parsed
    """
    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode sqlite details: {input_str}") from e

    if len(decoded_data) < 4:
        raise DecoderError(f"Data too short for sqlite code: {input_str}")

    sqlite_code = struct.unpack_from('<I', decoded_data, 0)[0]

    # Found at https://www.sqlite.org/rescode.html
    sqlite_messages = {
        0: "SQLITE OK",
        1: "SQLITE ERROR",
        2: "SQLITE INTERNAL",
        3: "SQLITE PERM",
        4: "SQLITE ABORT",
        5: "SQLITE BUSY",
        6: "SQLITE LOCKED",
        7: "SQLITE NOMEM",
        8: "SQLITE READ ONLY",
        9: "SQLITE INTERRUPT",
        10: "SQLITE IO ERR",
        11: "SQLITE CORRUPT",
        12: "SQLITE NOT FOUND",
        13: "SQLITE FULL",
        14: "SQLITE CAN'T OPEN",
        15: "SQLITE PROTOCOL",
        16: "SQLITE EMPTY",
        17: "SQLITE SCHEMA",
        18: "SQLITE TOO BIG",
        19: "SQLITE CONSTRAINT",
        20: "SQLITE MISMATCH",
        21: "SQLITE MISUSE",
        22: "SQLITE NO LFS",
        23: "SQLITE AUTH",
        24: "SQLITE FORMAT",
        25: "SQLITE RANGE",
        26: "SQLITE NOT A DB",
        27: "SQLITE NOTICE",
        28: "SQLITE WARNING",
        100: "SQLITE ROW",
        101: "SQLITE DONE",
        266: "SQLITE IO ERR READ",
    }

    if sqlite_code in sqlite_messages:
        return sqlite_messages[sqlite_code]

    logger.warning(f"[macos-unifiedlogs] Unknown Core Location sqlite error: {sqlite_code}")
    return "Unknown Core Location sqlite error"


def client_manager_state_tracker_state(input_str: str) -> str:
    """Parse the manager tracker state data.

    Args:
        input_str: Base64 encoded tracker state data

    Returns:
        JSON-formatted string representation

    Raises:
        DecoderError: If data cannot be decoded or parsed
    """
    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode client manager tracker state: {input_str}") from e

    if len(decoded_data) < 8:
        raise DecoderError(f"Data too short for client manager tracker state: {input_str}")

    location_enabled = struct.unpack_from('<I', decoded_data, 0)[0]
    location_restricted = struct.unpack_from('<I', decoded_data, 4)[0]

    return (
        f'{{"locationRestricted":{lowercase_bool(str(location_restricted))}, '
        f'"locationServicesenabledStatus":{location_enabled}}}'
    )


def location_manager_state_tracker_state(input_str: str) -> str:
    """Parse location tracker state data.

    Args:
        input_str: Base64 encoded location tracker state data

    Returns:
        JSON-formatted string representation

    Raises:
        DecoderError: If data cannot be decoded or parsed
    """
    try:
        decoded_data = base64.b64decode(input_str)
    except Exception as e:
        raise DecoderError(f"Failed to base64 decode location manager tracker data: {input_str}") from e

    try:
        tracker = _get_location_tracker_state(decoded_data)
        return _location_tracker_object(tracker)
    except Exception as e:
        raise DecoderError(f"Failed to get location manager tracker data: {input_str}") from e


def _get_location_tracker_state(data: bytes) -> LocationTrackerState:
    """Get the location state data from raw bytes.

    Args:
        data: Raw location tracker state bytes

    Returns:
        LocationTrackerState object
    """
    # https://github.com/cmsj/ApplePrivateHeaders/blob/main/macOS/11.3/System/Library/Frameworks/CoreLocation.framework/Versions/A/CoreLocation/CoreLocation-Structs.h
    tracker = LocationTrackerState()
    offset = 0

    # Parse accuracy tuple
    tracker.distance_filter = struct.unpack_from('<d', data, offset)[0]
    offset += 8
    tracker.desired_accuracy = struct.unpack_from('<d', data, offset)[0]
    offset += 8
    tracker.updating_location = data[offset]
    offset += 1
    tracker.requesting_location = data[offset]
    offset += 1
    tracker.requesting_ranging = data[offset]
    offset += 1
    tracker.updating_ranging = data[offset]
    offset += 1
    tracker.updating_heading = data[offset]
    offset += 1

    # Skip unknown 3 bytes
    offset += 3

    tracker.heading_filter = struct.unpack_from('<d', data, offset)[0]
    offset += 8
    tracker.allows_location_prompts = data[offset]
    offset += 1
    tracker.allows_altered_locations = data[offset]
    offset += 1
    tracker.dynamic_accuracy = data[offset]
    offset += 1

    tracker.previous_authorization_status_valid = data[offset]
    offset += 1
    tracker.previous_authorization_status = struct.unpack_from('<i', data, offset)[0]
    offset += 4
    tracker.limits_precision = data[offset]
    offset += 1

    # Skip unknown 7 bytes
    offset += 7

    tracker.activity_type = struct.unpack_from('<q', data, offset)[0]
    offset += 8
    tracker.pauses_location_updates = struct.unpack_from('<i', data, offset)[0]
    offset += 4

    tracker.paused = data[offset]
    offset += 1
    tracker.allows_background_updates = data[offset]
    offset += 1
    tracker.shows_background_location = data[offset]
    offset += 1
    tracker.allows_map_correction = data[offset]
    offset += 1

    # Sometimes location data only has 64 bytes. Seen only on Catalina.
    CATALINA_SIZE = 64
    if len(data) == CATALINA_SIZE:
        return tracker

    # Additional fields if we have more data
    if offset < len(data):
        tracker.batching_location = data[offset]
        offset += 1
    if offset < len(data):
        tracker.updating_vehicle_speed = data[offset]
        offset += 1
    if offset < len(data):
        tracker.updating_vehicle_heading = data[offset]
        offset += 1
    if offset < len(data):
        tracker.match_info = data[offset]
        offset += 1
    if offset < len(data):
        tracker.ground_altitude = data[offset]
        offset += 1
    if offset < len(data):
        tracker.fusion_info = data[offset]
        offset += 1
    if offset < len(data):
        tracker.courtesy_prompt = data[offset]
        offset += 1
    if offset < len(data):
        tracker.is_authorized_for_widgets = data[offset]

    return tracker


def _location_tracker_object(tracker: LocationTrackerState) -> str:
    """Create the location tracker JSON object.

    Args:
        tracker: LocationTrackerState object

    Returns:
        JSON-formatted string
    """
    return f"""{{
            "distanceFilter":{tracker.distance_filter},
            "desiredAccuracy":{tracker.desired_accuracy},
            "updatingLocation":{lowercase_int_bool(tracker.updating_location)},
            "requestingLocation":{lowercase_int_bool(tracker.requesting_location)},
            "requestingRanging":{lowercase_int_bool(tracker.requesting_ranging)},
            "updatingRanging":{lowercase_int_bool(tracker.updating_ranging)},
            "updatingHeading":{lowercase_int_bool(tracker.updating_heading)},
            "headingFilter":{tracker.heading_filter},
            "allowsLocationPrompts":{lowercase_int_bool(tracker.allows_location_prompts)},
            "allowsAlteredAccessoryLocations":{lowercase_int_bool(tracker.allows_altered_locations)},
            "dynamicAccuracyReductionEnabled":{lowercase_int_bool(tracker.dynamic_accuracy)},
            "previousAuthorizationStatusValid":{lowercase_int_bool(tracker.previous_authorization_status_valid)},
            "previousAuthorizationStatus":{tracker.previous_authorization_status},
            "limitsPrecision":{lowercase_int_bool(tracker.limits_precision)},
            "activityType":{tracker.activity_type},
            "pausesLocationUpdatesAutomatically":{tracker.pauses_location_updates},
            "paused":{lowercase_int_bool(tracker.paused)},
            "allowsBackgroundLocationUpdates":{lowercase_int_bool(tracker.allows_background_updates)},
            "showsBackgroundLocationIndicator":{lowercase_int_bool(tracker.shows_background_location)},
            "allowsMapCorrection":{lowercase_int_bool(tracker.allows_map_correction)},
            "batchingLocation":{lowercase_int_bool(tracker.batching_location)},
            "updatingVehicleSpeed":{lowercase_int_bool(tracker.updating_vehicle_speed)},
            "updatingVehicleHeading":{lowercase_int_bool(tracker.updating_vehicle_heading)},
            "matchInfoEnabled":{lowercase_int_bool(tracker.match_info)},
            "groundAltitudeEnabled":{lowercase_int_bool(tracker.ground_altitude)},
            "fusionInfoEnabled":{lowercase_int_bool(tracker.fusion_info)},
            "courtesyPromptNeeded":{lowercase_int_bool(tracker.courtesy_prompt)},
            "isAuthorizedForWidgetUpdates":{lowercase_int_bool(tracker.is_authorized_for_widgets)},
        }}"""


def io_message(data: str) -> str:
    """Parse location tracker state data for IO messages.

    Args:
        data: IO message code as string

    Returns:
        Human-readable IO message

    Raises:
        DecoderError: If message code is unknown
    """
    io_messages = {
        "3758097008": "CanSystemSleep",
        "3758097024": "SystemWillSleep",
        "3758097040": "SystemWillNotSleep",
        "3758097184": "SystemWillPowerOn",
        "3758097168": "SystemWillRestart",
        "3758097152": "SystemHasPoweredOn",
        "3758097200": "CopyClientID",
        "3758097216": "SystemCapabilityChange",
        "3758097232": "DeviceSignaledWakeup",
        "3758096400": "ServiceIsTerminated",
        "3758096416": "ServiceIsSuspended",
        "3758096432": "ServiceIsResumed",
        "3758096640": "ServiceIsRequestingClose",
        "3758096641": "ServiceIsAttemptingOpen",
        "3758096656": "ServiceWasClosed",
        "3758096672": "ServiceBusyStateChange",
        "3758096680": "ConsoleSecurityChange",
        "3758096688": "ServicePropertyChange",
        "3758096896": "CanDevicePowerOff",
        "3758096912": "DeviceWillPowerOff",
        "3758096928": "DeviceWillNotPowerOff",
        "3758096944": "DeviceHasPoweredOn",
        "3758096976": "SystemWillPowerOff",
        "3758096981": "SystemPagingOff",
    }

    if data in io_messages:
        return io_messages[data]

    raise DecoderError(f"Unknown IO Message: {data}")


def get_daemon_status_tracker(data: bytes) -> str:
    """Parse and get the location Daemon tracker.

    Args:
        data: Raw daemon status tracker bytes

    Returns:
        JSON-formatted string representation
    """
    offset = 0

    level = struct.unpack_from('<d', data, offset)[0]
    offset += 8
    charged = data[offset]
    offset += 1
    connected = data[offset]
    offset += 1
    _unknown = data[offset]
    offset += 1
    _unknown2 = data[offset]
    offset += 1
    charger_type = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    _unknown3 = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    _unknown4 = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    reachability = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    thermal_level = struct.unpack_from('<i', data, offset)[0]
    offset += 4
    airplane = data[offset]
    offset += 1
    battery_saver = data[offset]
    offset += 1
    push_service = data[offset]
    offset += 1
    restricted = data[offset]

    was_connected = False
    if _unknown != 0 and _unknown2 != 0 and _unknown3 != 0:
        was_connected = True

    reachability_map = {
        0: "kReachabilityUnavailable",
        1: "kReachabilitySmall",
        2: "kReachabilityLarge",
        1000: "kReachabilityUnachievable",
    }
    reachability_str = reachability_map.get(reachability)
    if reachability_str is None:
        logger.warning(f"[macos-unifiedlogs] Unknown reachability value: {reachability}")
        reachability_str = "Unknown reachability value"

    charger_type_map = {
        0: "kChargerTypeUnknown",
        2: "kChargerTypeUsb",
    }
    charger_type_str = charger_type_map.get(charger_type)
    if charger_type_str is None:
        logger.warning(f"[macos-unifiedlogs] Unknown charger type value: {charger_type}")
        charger_type_str = "Unknown charger type value"

    return (
        f'{{"thermalLevel": {thermal_level}, "reachability": "{reachability_str}", '
        f'"airplaneMode": {lowercase_int_bool(airplane)}, '
        f'"batteryData":{{"wasConnected": {"true" if was_connected else "false"}, '
        f'"charged": {lowercase_int_bool(charged)}, "level": {level}, '
        f'"connected": {lowercase_int_bool(connected)}, "chargerType": "{charger_type_str}"}}, '
        f'"restrictedMode": {lowercase_int_bool(restricted)}, '
        f'"batterySaverModeEnabled": {lowercase_int_bool(battery_saver)}, '
        f'"push_service":{lowercase_int_bool(push_service)}}}'
    )
