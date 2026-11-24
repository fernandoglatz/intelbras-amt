"""ISECNet "IP communication" framing (header 0xE7) used by AMT Remoto Mobile.

Wire format of every request and reply::

    [len] [0xE7] [n] [data: n bytes] [crc16: 2 bytes, little-endian] [checksum]

* ``len``      = 1 + 1 + n + 2  (counts 0xE7, n, data and the CRC)
* ``crc16``    = table-driven CRC over ``[n] + data`` (table copied from the app)
* ``checksum`` = XOR of every preceding byte, then XOR 0xFF

The first data byte is the sub-command (``Cmd``); the panel answers with the
same frame shape and ``Cmd | 0x80`` as the first data byte.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum

HEADER = 0xE7


class Cmd(IntEnum):
    REFRESH = 0x10
    IDENTIFY = 0x11
    READ_EEPROM = 0x12
    WRITE_EEPROM = 0x13
    PROBLEMS = 0x14
    HANG_UP = 0x15
    REMOTE_ARM = 0x16
    STATUS = 0x17
    CLOCK_ADJUST = 0x18
    MENU_FUNCTIONS = 0x19
    BYPASS = 0x1B
    CLEAN_TRIGGERED_ZONES = 0x1C
    BYPASSED_ZONES = 0x1D
    SET_PGM_4_TO_19 = 0x1E
    SEARCH_BUS_DEVICES = 0x22  # AMT 4010 Smart
    BUS_DEVICES = 0x23  # AMT 4010 Smart / Smart models
    STATUS_SMART = 0x27  # AMT 2018 E Smart, AMT 1000 Smart
    CONNECTIONS = 0x30  # Smart models
    NETWORK_CARD = 0x31  # Smart models
    CELL_CARD = 0x32  # Smart models
    NEW_PROBLEMS = 0x34  # Smart models
    WIRELESS_SENSORS = 0x36  # Smart models, firmware >= 1.80


class Answer(IntEnum):
    REFRESH = 0x90
    READ_EEPROM = 0x92
    WRITE_EEPROM = 0x93
    PROBLEMS = 0x94
    HANG_UP = 0x95
    REMOTE_ARM = 0x96
    STATUS = 0x97
    CLOCK_ADJUST = 0x98
    MENU_FUNCTIONS = 0x99
    BYPASS = 0x9B
    CLEAN_TRIGGERED_ZONES = 0x9C
    BYPASSED_ZONES = 0x9D
    SET_PGM_4_TO_19 = 0x9E
    SEARCH_BUS_DEVICES = 0xA2
    BUS_DEVICES = 0xA3
    STATUS_SMART = 0xA7
    CONNECTIONS = 0xB0
    NETWORK_CARD = 0xB1
    CELL_CARD = 0xB2
    NEW_PROBLEMS = 0xB4
    WIRELESS_SENSORS = 0xB6


# Commands that only read. Everything else changes the panel.
READ_ONLY_COMMANDS = frozenset(
    {
        Cmd.REFRESH,
        Cmd.READ_EEPROM,
        Cmd.PROBLEMS,
        Cmd.HANG_UP,
        Cmd.STATUS,
        Cmd.BYPASSED_ZONES,
        Cmd.BUS_DEVICES,
        Cmd.STATUS_SMART,
        Cmd.CONNECTIONS,
        Cmd.NETWORK_CARD,
        Cmd.CELL_CARD,
        Cmd.NEW_PROBLEMS,
        Cmd.WIRELESS_SENSORS,
    }
)

# Reads every v1 model supports (the official app sends them to all of them).
# Model-specific reads are NOT safe on other models: the Smart-only 0x30 sent
# to an AMT 1016 NET hung its network interface.
UNIVERSAL_READS = frozenset(
    {Cmd.REFRESH, Cmd.READ_EEPROM, Cmd.PROBLEMS, Cmd.HANG_UP, Cmd.STATUS, Cmd.BYPASSED_ZONES}
)

# MENU_FUNCTIONS (0x19) argument values.
MENU_SIREN_STATUS = 0x10
MENU_SILENCE_ALARM = 0x40
# PGM 1-3 toggles (DataTypes.ACTIVATE_PGM1..3); the reply carries the new state.
MENU_PGM_TOGGLE = {1: 0x60, 2: 0x80, 3: 0xC0}
# Bits of the MENU_FUNCTIONS reply byte.
PGM_STATE_BITS = {1: 0x40, 2: 0x20, 3: 0x10}
ALARM_FIRING_BIT = 0x04

# EEPROM limits (Protocol.EEPROM.ForbiddenAddress, min/maxValidAddress).
EEPROM_MAX_ADDRESS = 9215
EEPROM_FORBIDDEN_RANGES = ((976, 1023), (1791, 1791), (5375, 5375), (5888, 8191))

# IDENTIFY replies: 0x50 = accepted, 0x4D = accepted as master connection.
IDENTIFY_OK = (0x50, 0x4D)
IDENTIFY_TRAILER = 0x34

# fmt: off
CRC_TABLE = (
    0x0000, 0x0580, 0x0F80, 0x0A00, 0x1B80, 0x1E00, 0x1400, 0x1180,
    0x3380, 0x3600, 0x3C00, 0x3980, 0x2800, 0x2D80, 0x2780, 0x2200,
    0x6380, 0x6600, 0x6C00, 0x6980, 0x7800, 0x7D80, 0x7780, 0x7200,
    0x5000, 0x5580, 0x5F80, 0x5A00, 0x4B80, 0x4E00, 0x4400, 0x4180,
    0xC380, 0xC600, 0xCC00, 0xC980, 0xD800, 0xDD80, 0xD780, 0xD200,
    0xF000, 0xF580, 0xFF80, 0xFA00, 0xEB80, 0xEE00, 0xE400, 0xE180,
    0xA000, 0xA580, 0xAF80, 0xAA00, 0xBB80, 0xBE00, 0xB400, 0xB180,
    0x9380, 0x9600, 0x9C00, 0x9980, 0x8800, 0x8D80, 0x8780, 0x8200,
    0x8381, 0x8601, 0x8C01, 0x8981, 0x9801, 0x9D81, 0x9781, 0x9201,
    0xB001, 0xB581, 0xBF81, 0xBA01, 0xAB81, 0xAE01, 0xA401, 0xA181,
    0xE001, 0xE581, 0xEF81, 0xEA01, 0xFB81, 0xFE01, 0xF401, 0xF181,
    0xD381, 0xD601, 0xDC01, 0xD981, 0xC801, 0xCD81, 0xC781, 0xC201,
    0x4001, 0x4581, 0x4F81, 0x4A01, 0x5B81, 0x5E01, 0x5401, 0x5181,
    0x7381, 0x7601, 0x7C01, 0x7981, 0x6801, 0x6D81, 0x6781, 0x6201,
    0x2381, 0x2601, 0x2C01, 0x2981, 0x3801, 0x3D81, 0x3781, 0x3201,
    0x1001, 0x1581, 0x1F81, 0x1A01, 0x0B81, 0x0E01, 0x0401, 0x0181,
    0x0383, 0x0603, 0x0C03, 0x0983, 0x1803, 0x1D83, 0x1783, 0x1203,
    0x3003, 0x3583, 0x3F83, 0x3A03, 0x2B83, 0x2E03, 0x2403, 0x2183,
    0x6003, 0x6583, 0x6F83, 0x6A03, 0x7B83, 0x7E03, 0x7403, 0x7183,
    0x5383, 0x5603, 0x5C03, 0x5983, 0x4803, 0x4D83, 0x4783, 0x4203,
    0xC003, 0xC583, 0xCF83, 0xCA03, 0xDB83, 0xDE03, 0xD403, 0xD183,
    0xF383, 0xF603, 0xFC03, 0xF983, 0xE803, 0xED83, 0xE783, 0xE203,
    0xA383, 0xA603, 0xAC03, 0xA983, 0xB803, 0xBD83, 0xB783, 0xB203,
    0x9003, 0x9583, 0x9F83, 0x9A03, 0x8B83, 0x8E03, 0x8403, 0x8183,
    0x8002, 0x8582, 0x8F82, 0x8A02, 0x9B82, 0x9E02, 0x9402, 0x9182,
    0xB382, 0xB602, 0xBC02, 0xB982, 0xA802, 0xAD82, 0xA782, 0xA202,
    0xE382, 0xE602, 0xEC02, 0xE982, 0xF802, 0xFD82, 0xF782, 0xF202,
    0xD002, 0xD582, 0xDF82, 0xDA02, 0xCB82, 0xCE02, 0xC402, 0xC182,
    0x4382, 0x4602, 0x4C02, 0x4982, 0x5802, 0x5D82, 0x5782, 0x5202,
    0x7002, 0x7582, 0x7F82, 0x7A02, 0x6B82, 0x6E02, 0x6402, 0x6182,
    0x2002, 0x2582, 0x2F82, 0x2A02, 0x3B82, 0x3E02, 0x3402, 0x3182,
    0x1382, 0x1602, 0x1C02, 0x1982, 0x0802, 0x0D82, 0x0782, 0x0202,
    0x0001,
)
# fmt: on


class FrameError(ValueError):
    """A frame is truncated, has a wrong header, or fails CRC/checksum."""


def crc16(data: bytes) -> bytes:
    value = 0
    for byte in data:
        value = ((value >> 8) ^ CRC_TABLE[(value ^ byte) & 0xFF]) & 0xFFFF
    return value.to_bytes(2, "little")


def checksum(data: bytes) -> int:
    value = 0
    for byte in data:
        value ^= byte
    return value ^ 0xFF


def build_frame(data: bytes) -> bytes:
    if not data:
        raise ValueError("frame data must not be empty")
    if len(data) > 250:
        raise ValueError("frame data too long")
    payload = bytes([len(data)]) + bytes(data)
    body = bytes([len(payload) + 3, HEADER]) + payload + crc16(payload)
    return body + bytes([checksum(body)])


def frame_length(prefix: bytes) -> int | None:
    """Total length of the frame starting at ``prefix``, once its first byte is known."""
    if not prefix:
        return None
    return prefix[0] + 2


@dataclass(frozen=True)
class Frame:
    data: bytes

    @property
    def command(self) -> int:
        return self.data[0]

    @property
    def body(self) -> bytes:
        return self.data[1:]


def parse_frame(raw: bytes) -> Frame:
    if len(raw) < 6:
        raise FrameError(f"frame too short: {raw.hex(' ')}")
    total = frame_length(raw)
    if len(raw) != total:
        raise FrameError(f"frame length mismatch (want {total}, got {len(raw)}): {raw.hex(' ')}")
    if raw[1] != HEADER:
        raise FrameError(f"unexpected header 0x{raw[1]:02X}: {raw.hex(' ')}")
    n = raw[2]
    if 3 + n + 3 != len(raw):
        raise FrameError(f"data length {n} does not match frame size: {raw.hex(' ')}")
    payload = raw[2 : 3 + n]
    if raw[3 + n : 5 + n] != crc16(payload):
        raise FrameError(f"bad CRC: {raw.hex(' ')}")
    if raw[-1] != checksum(raw[:-1]):
        raise FrameError(f"bad checksum: {raw.hex(' ')}")
    return Frame(data=bytes(payload[1:]))


def encode_password(password: str) -> bytes:
    """Pack the remote-access password as the app does: each digit pair is one hex byte.

    ``"246810"`` -> ``24 68 10``; 4-digit passwords give two bytes.
    """
    if len(password) not in (4, 6) or not password.isdigit():
        raise ValueError("password must be 4 or 6 digits")
    return bytes(int(password[i : i + 2], 16) for i in range(0, len(password), 2))


def identify_data(password: str) -> bytes:
    return bytes([Cmd.IDENTIFY]) + encode_password(password) + bytes([IDENTIFY_TRAILER])


def read_eeprom_data(address: int, count: int) -> bytes:
    if not 0 <= address <= 0xFFFF:
        raise ValueError("address out of range")
    if not 1 <= count <= 64:
        raise ValueError("count must be 1..64")
    return bytes([Cmd.READ_EEPROM, address >> 8, address & 0xFF, count])


def arm_mask(partition: int | None, stay: bool) -> int:
    """Partition mask for REMOTE_ARM, as built by OnlineAmt2018DataSource.ActivatePanel.

    ``partition`` None/0 = whole panel, 1-4 = A-D. ``stay`` shifts the mask
    into the high nibble (whole panel stay = 0xF0).
    """
    if partition is not None and not 0 <= partition <= 4:
        raise ValueError("partition must be 1..4")
    mask = 0 if not partition else 1 << (partition - 1)
    if stay:
        mask = (mask << 4) or 0xF0
    return mask


def _bcd(value: int) -> int:
    return (value // 10) << 4 | (value % 10)


def clock_data(when: datetime) -> bytes:
    """CLOCK_ADJUST request (WriteInformationBuilder.WriteClockAdjust): BCD YY MM DD hh mm."""
    if not 2000 <= when.year <= 2099:
        raise ValueError("year must be 2000..2099")
    fields = (when.year - 2000, when.month, when.day, when.hour, when.minute)
    return bytes([Cmd.CLOCK_ADJUST, *(_bcd(v) for v in fields), 0x00])


def bypass_data(zones, zone_count: int = 48) -> bytes:
    """BYPASS request: the complete set of bypassed zones (zones not listed are un-bypassed)."""
    bitmap = bytearray(8)
    for zone in zones:
        if not 1 <= zone <= zone_count:
            raise ValueError(f"zone {zone} out of range 1..{zone_count}")
        bitmap[(zone - 1) // 8] |= 1 << ((zone - 1) % 8)
    return bytes([Cmd.BYPASS]) + bytes(bitmap)


def pgm_data(pgm: int) -> bytes:
    """PGM toggle request: 1-3 via MENU_FUNCTIONS, 4-19 via SET_PGM_4_TO_19 (4010 Smart)."""
    if pgm in MENU_PGM_TOGGLE:
        return bytes([Cmd.MENU_FUNCTIONS, MENU_PGM_TOGGLE[pgm]])
    if 4 <= pgm <= 19:
        return bytes([Cmd.SET_PGM_4_TO_19, pgm, 0x00])
    raise ValueError("PGM must be 1..19")


def write_eeprom_data(address: int, data: bytes) -> bytes:
    """WRITE_EEPROM request. Refuses the ranges the official app refuses."""
    if not 1 <= len(data) <= 64:
        raise ValueError("write 1..64 bytes at a time")
    last = address + len(data) - 1
    if address < 0 or last > EEPROM_MAX_ADDRESS:
        raise ValueError(f"address range {address}..{last} outside 0..{EEPROM_MAX_ADDRESS}")
    for low, high in EEPROM_FORBIDDEN_RANGES:
        if address <= high and last >= low:
            raise ValueError(f"address range {address}..{last} touches protected area {low}..{high}")
    return bytes([Cmd.WRITE_EEPROM, address >> 8, address & 0xFF, len(data)]) + bytes(data)


# -- Discovery frames: [len] [cmd] [payload…] [checksum], no password --------

DISCOVERY_MAC = 0xC4
DISCOVERY_MODEL = 0xC2


def build_simple(cmd: int, payload: bytes = b"") -> bytes:
    body = bytes([1 + len(payload), cmd]) + payload
    return body + bytes([checksum(body)])


def parse_simple(raw: bytes) -> tuple[int, bytes]:
    if len(raw) < 3 or len(raw) != raw[0] + 2:
        raise FrameError(f"bad frame length: {raw.hex(' ')}")
    if raw[-1] != checksum(raw[:-1]):
        raise FrameError(f"bad checksum: {raw.hex(' ')}")
    return raw[1], bytes(raw[2:-1])


# -- E9 "ISECMobile" frames (AMT Mobile V3 / Guardian) ------------------------
#    [len] E9 21 <password ASCII> <cmd…> 21 <checksum>

E9_HEADER = 0xE9
E9_DELIMITER = 0x21
E9_REPLY_CODES = {
    0xFE: None,
    0xE0: "invalid packet",
    0xE1: "wrong password",
    0xE2: "invalid command",
    0xE3: "panel has no partitions",
    0xE4: "open zones",
    0xE5: "command deprecated",
    0xE6: "bypass not allowed",
    0xE7: "deactivation not allowed",
    0xE8: "bypass not allowed while armed",
    0xFF: "invalid model",
}


class E9Cmd(IntEnum):
    ARM = 0x41  # + optional partition 0x41-0x44 (A-D) and 0x50 (stay)
    BYPASS = 0x42  # + 6-byte zone bitmap
    SIREN_ON = 0x43
    DISARM = 0x44  # + optional partition 0x41-0x44
    PANIC = 0x45  # + 0 silent, 1 audible, 2 medical, 3 fire
    PGM = 0x50  # + 0x4C on / 0x44 off + output 0x31-0x43
    PARTIAL_STATUS = 0x5A
    COMPLETE_STATUS = 0x5B
    READ_EEPROM = 0x5C  # + hi lo count
    COMPLETE_INFO = 0x5D
    SIREN_OFF = 0x63


E9_READ_ONLY = frozenset({E9Cmd.PARTIAL_STATUS, E9Cmd.COMPLETE_STATUS, E9Cmd.READ_EEPROM, E9Cmd.COMPLETE_INFO})


def build_e9(command: bytes, password: str) -> bytes:
    if not 4 <= len(password) <= 6 or not password.isdigit():
        raise ValueError("password must be 4 to 6 digits")
    if not command:
        raise ValueError("command must not be empty")
    body = bytes([E9_HEADER, E9_DELIMITER]) + password.encode("ascii") + bytes(command) + bytes([E9_DELIMITER])
    frame = bytes([len(body)]) + body
    return frame + bytes([checksum(frame)])


@dataclass(frozen=True)
class E9Reply:
    code: int
    body: bytes

    @property
    def error(self) -> str | None:
        return E9_REPLY_CODES.get(self.code, f"unknown reply 0x{self.code:02X}") if self.code != 0xFE else None


def parse_e9(raw: bytes) -> E9Reply:
    """Parse an E9 reply: ``02 E9 <code> <chk>`` for ACK/errors, longer for status data."""
    if len(raw) < 4 or len(raw) != raw[0] + 2:
        raise FrameError(f"bad E9 frame length: {raw.hex(' ')}")
    if raw[1] != E9_HEADER:
        raise FrameError(f"not an E9 frame: {raw.hex(' ')}")
    if raw[-1] != checksum(raw[:-1]):
        raise FrameError(f"bad checksum: {raw.hex(' ')}")
    if len(raw) == 4:
        return E9Reply(code=raw[2], body=b"")
    return E9Reply(code=0xFE, body=bytes(raw[2:-1]))
