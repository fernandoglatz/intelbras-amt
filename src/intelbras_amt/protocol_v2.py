"""ISECNet v2 framing (AMT 8000 family) on TCP 9009.

Wire format::

    [dest: 2] [source: 2] [length: 2] [command: 2] [payload…] [checksum]

* all 16-bit fields big-endian; ``length`` = 2 (command) + len(payload)
* ``dest`` is 00 00; a local client uses source 00 F1 (AMT Remoto's
  ``Packet(CommandTypesAmt8000, …)`` for local connections)
* ``checksum`` = XOR of every preceding byte, XOR 0xFF (same as v1)

A local session starts with the v1 refresh frame (``E7`` command ``10``):
v2 panels answer it with ``80`` (v1 panels with ``90``). That refresh is the
only command the official app sends before knowing the family.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .protocol import FrameError, checksum

DEST = b"\x00\x00"
LOCAL_SOURCE = b"\x00\xf1"
REFRESH_ANSWER_V2 = 0x80


class Cmd(IntEnum):
    """Commands from Guardian's ISECNetV2Protocol.Command and AMT Remoto's CommandTypesAmt8000."""

    ACK = 0xF0FE
    NACK = 0xF0FD
    AUTH = 0xF0F0
    DISCONNECT = 0xF0F1
    KEEP_ALIVE = 0xF0F7
    INFO = 0x0060  # model, firmware (CMD_INFO_CENTRAL_ALARME), sent first by AMT Remoto
    STATUS_BASIC = 0x0B01  # basic status (CMD_READ_STATUS_CENTRAL_ALARME), used for the ANM 24 NET
    STATUS = 0x0B4A  # complete status (AMT 8000)
    STATUS_G2 = 0x0B7A  # second-generation status (not decoded here)
    ARM_DISARM = 0x401E
    TURN_OFF_SIREN = 0x4019
    PANIC = 0x401A
    BYPASS = 0x401F
    PGM_ON_OFF = 0x45AF
    PGM_STATUS = 0x0B70
    CONNECTION_MODE = 0x0B71
    WIRELESS_SIGNAL = 0x0B73
    GET_MAC = 0x3FAA
    ZONES_NAME = 0x33E0
    USERS_NAME = 0x32E0
    PGMS_NAME = 0x35E0
    ZONE_PARTITION = 0x3A10
    ZONES_WITH_STAY = 0x3A20


# Commands that only read; everything else changes the panel.
READ_ONLY = frozenset(
    {
        Cmd.INFO,
        Cmd.STATUS_BASIC,
        Cmd.STATUS,
        Cmd.STATUS_G2,
        Cmd.KEEP_ALIVE,
        Cmd.PGM_STATUS,
        Cmd.CONNECTION_MODE,
        Cmd.WIRELESS_SIGNAL,
        Cmd.GET_MAC,
        Cmd.ZONES_NAME,
        Cmd.USERS_NAME,
        Cmd.PGMS_NAME,
        Cmd.ZONE_PARTITION,
        Cmd.ZONES_WITH_STAY,
    }
)


class ArmOp(IntEnum):
    """ARM_DISARM operation byte (ISECNetV2Protocol.AlarmOperation)."""

    DISARM = 0
    ARM = 1
    STAY = 2
    FORCE_ARM = 3


PANIC_TYPES = {"silent": 0, "audible": 1, "fire": 2, "medical": 3}
SIREN_OFF_PAYLOAD = bytes([0xFF])
ALL_PARTITIONS = 0xFF

# AUTH reply, payload byte 0 (ISECNetV2AuthResponse; AMT Remoto also accepts 12).
AUTH_RESULTS = {
    0: "accepted",
    1: "wrong password",
    2: "wrong software version",
    3: "panel will call back",
    4: "waiting for user permission",
    12: "accepted",
}

# NACK reply, payload byte 0 (ISECNetV2ErrorResponse).
ERRORS = {
    23: "wrong number of digits",
    24: "wrong number of password digits",
    25: "wrong password",
    26: "partition does not exist",
    27: "no permission for this partition",
    30: "disarming not allowed",
    32: "partition has no zones",
    33: "command denied",
    34: "user has no partitions",
    35: "event has no picture",
    36: "invalid picture index",
    37: "invalid fragment index",
    38: "panel is not partitioned",
    39: "open zones",
    40: "picture still recording",
    41: "mobile access disabled",
    42: "not allowed",
    45: "repeated password",
    46: "arming/disarming failed",
    47: "stay arming denied",
    48: "panel must be disarmed first",
    52: "panel not connected",
    54: "partition has no stay zones",
    55: "bypass denied",
    56: "corrupted firmware",
    63: "panel has no zones",
    0xFE: "invalid command",
}


class V2CommandError(RuntimeError):
    """The panel answered NACK."""


@dataclass(frozen=True)
class FrameV2:
    dest: bytes
    source: bytes
    command: int
    payload: bytes


def build_frame(command: int, payload: bytes = b"", source: bytes = LOCAL_SOURCE) -> bytes:
    if len(source) != 2:
        raise ValueError("source id must be 2 bytes")
    length = 2 + len(payload)
    if length > 0xFFFF:
        raise ValueError("payload too long")
    body = DEST + bytes(source) + length.to_bytes(2, "big") + int(command).to_bytes(2, "big") + bytes(payload)
    return body + bytes([checksum(body)])


def frame_length(header: bytes) -> int | None:
    """Total frame size once the first 6 bytes are known."""
    if len(header) < 6:
        return None
    return 6 + int.from_bytes(header[4:6], "big") + 1


def parse_frame(raw: bytes) -> FrameV2:
    total = frame_length(raw)
    if total is None or len(raw) < 9:
        raise FrameError(f"v2 frame too short: {raw.hex(' ')}")
    if len(raw) != total:
        raise FrameError(f"v2 frame length mismatch (want {total}, got {len(raw)}): {raw.hex(' ')}")
    if raw[-1] != checksum(raw[:-1]):
        raise FrameError(f"bad checksum: {raw.hex(' ')}")
    return FrameV2(
        dest=bytes(raw[0:2]),
        source=bytes(raw[2:4]),
        command=int.from_bytes(raw[6:8], "big"),
        payload=bytes(raw[8:-1]),
    )


def auth_payload(password: str) -> bytes:
    """AUTH payload as AMT Remoto builds it locally (LoginRepository.OpenAmt8000).

    ``01``, six password digits (each as its own byte, ``0`` -> 0x00, shorter
    passwords padded with 0x00), then ``10 00``. Guardian's relay login uses
    ``03 … 00 01`` and sends digit 0 as 0x0A instead.
    """
    if not 4 <= len(password) <= 6 or not password.isdigit():
        raise ValueError("password must be 4 to 6 digits")
    digits = [int(c) for c in password] + [0] * (6 - len(password))
    return bytes([0x01, *digits, 0x10, 0x00])


def arm_payload(partition: int | None, op: ArmOp) -> bytes:
    """ARM_DISARM payload: partition 1-16 (or 0xFF = all) then the operation."""
    if partition is not None and not 1 <= partition <= 16:
        raise ValueError("partition must be 1..16")
    return bytes([ALL_PARTITIONS if partition is None else partition, int(op)])


def bypass_payload(zones, bypass: bool) -> bytes:
    """BYPASS payload: (zone index from 0, 1/0) pairs for the listed zones only."""
    out = bytearray()
    for zone in zones:
        if not 1 <= zone <= 64:
            raise ValueError(f"zone {zone} out of range 1..64")
        out += bytes([zone - 1, 1 if bypass else 0])
    return bytes(out)


def pgm_payload(pgm: int, on: bool) -> bytes:
    if not 1 <= pgm <= 16:
        raise ValueError("PGM must be 1..16")
    return bytes([pgm - 1, 1 if on else 0])


def panic_payload(kind: str) -> bytes:
    try:
        return bytes([PANIC_TYPES[kind]])
    except KeyError:
        raise ValueError(f"panic type must be one of {', '.join(PANIC_TYPES)}") from None
