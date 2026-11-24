"""Decoders for ISECNet v2 replies (AMT 8000 family).

Status offsets are into the reply payload (frame bytes after the command),
from Guardian's ISECNetV2ParseHelper.parseStatusResponse, cross-checked with
AMT Remoto's OnlineInterpreter.Read8000StatusFull (raw index = payload + 8).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

from .protocol import FrameError
from .protocol_v2 import AUTH_RESULTS, ERRORS, Cmd, FrameV2, V2CommandError


@dataclass(frozen=True)
class ModelV2:
    name: str
    kind: str | None  # "8000" (full status), "anm" (basic status) or None (not decoded)
    reason: str = ""

    @property
    def decodable(self) -> bool:
        return self.kind is not None


MODELS_V2: dict[int, ModelV2] = {
    0x01: ModelV2("AMT 8000", "8000"),
    0x8A: ModelV2("AMT 8000 PRO", "8000"),
    0x8B: ModelV2("AMT 8000 LITE", "8000"),
    0x02: ModelV2("ANM 24 NET", "anm"),  # code used by AMT Remoto
    0x24: ModelV2("ANM 24 NET", "anm"),  # code used by Guardian / AMT Mobile V3
    0x25: ModelV2("ANM 24 NET G2", "anm"),
    0x90: ModelV2("AMT 9000", None, "uses its own paged status (not decoded)"),
    0x35: ModelV2("ELC 6012 NET", None, "electric fence controller (not decoded)"),
    0x39: ModelV2("ELC 6012 IND", None, "electric fence controller (not decoded)"),
    0x38: ModelV2("4G communicator", None, "communicator, not a panel"),
}

BATTERY_LEVELS = {1: "missing", 2: "low", 3: "medium", 4: "high"}
MIN_STATUS_PAYLOAD = 139  # last byte read: PGM state at 137-138


def model_v2(code: int) -> ModelV2:
    return MODELS_V2.get(code, ModelV2(f"unknown v2 model 0x{code:02X}", None, "unknown model"))


def _bits(data: bytes, first: int = 1) -> list[int]:
    return [first + i * 8 + b for i, byte in enumerate(data) for b in range(8) if byte & (1 << b)]


def _bcd(byte: int) -> int | None:
    high, low = byte >> 4, byte & 0x0F
    return None if high > 9 or low > 9 else high * 10 + low


@dataclass
class PartitionV2:
    id: int
    armed: bool
    stay: bool
    firing: bool


@dataclass
class StatusV2:
    model_code: int
    model: str
    firmware: str
    state: str  # disarmed | partial | armed | stay
    armed: bool
    firing: bool
    partitioned: bool
    partitions: list[PartitionV2]
    open_zones: list[int]
    violated_zones: list[int]
    bypassed_zones: list[int]
    tamper_zones: list[int]
    low_battery_zones: list[int]
    communication_error_zones: list[int]
    clock: str | None
    clock_raw: str
    battery: str | None
    pgm: dict[int, bool] = field(default_factory=dict)
    pgm_low_battery: list[int] = field(default_factory=list)
    pgm_communication_error: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _general_state(byte: int) -> str:
    """ISECNetV2ParseHelper.parseAlarmState: bits 5+6 armed, bit 5 alone partial, bit 7 stay."""
    if byte & 0x20 and byte & 0x40:
        state = "armed"
    elif not byte & 0x20:
        state = "disarmed"
    else:
        state = "partial"
    return "stay" if byte & 0x80 and state != "disarmed" else state


def _clock(data: bytes) -> str | None:
    """Day, month, year, hour, minute. Read as BCD, as AMT Remoto shows it."""
    values = [_bcd(b) for b in data[:5]]
    if None in values:
        return None
    day, month, year, hour, minute = values
    try:
        return datetime(2000 + year, month, day, hour, minute).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return None


def decode_status(frame: FrameV2) -> StatusV2:
    if frame.command != Cmd.STATUS:
        raise FrameError(f"expected v2 status 0x{Cmd.STATUS:04X}, got 0x{frame.command:04X}")
    p = frame.payload
    if len(p) < 1:
        raise FrameError("v2 status too short")
    info = model_v2(p[0])
    if info.kind != "8000":
        reason = info.reason or "it uses the basic status (see decode_status_anm)"
        raise FrameError(f"full status of {info.name} is not supported: {reason}")
    if len(p) < MIN_STATUS_PAYLOAD:
        raise FrameError(f"v2 status too short ({len(p)} bytes, need {MIN_STATUS_PAYLOAD})")
    state = _general_state(p[20])
    partitions = []
    for index in range(1, 17):
        byte = p[21 + index]
        if byte & 0x80:  # partition enabled
            partitions.append(PartitionV2(id=index, armed=bool(byte & 0x01), stay=bool(byte & 0x02), firing=bool(byte & 0x04)))
    pgm_on = _bits(p[137:139])
    return StatusV2(
        model_code=p[0],
        model=info.name,
        firmware=f"{p[1]}.{p[2]}.{p[3]}",
        state=state,
        armed=state in ("armed", "stay"),
        firing=bool(p[20] & 0x02),
        partitioned=bool(p[4] & 0x10),
        partitions=partitions,
        open_zones=_bits(p[38:46]),
        violated_zones=_bits(p[46:54]),
        bypassed_zones=_bits(p[54:62]),
        communication_error_zones=_bits(p[73:81]),
        tamper_zones=_bits(p[89:97]),
        low_battery_zones=_bits(p[105:113]),
        clock=_clock(p[64:70]),
        clock_raw=p[64:70].hex(" "),
        battery=BATTERY_LEVELS.get(p[134]),
        pgm={i: i in pgm_on for i in range(1, 17)},
        pgm_low_battery=_bits(p[119:121]),
        pgm_communication_error=_bits(p[87:89]),
    )


@dataclass
class InfoV2:
    model_code: int
    model: str
    kind: str | None
    firmware: str
    firmware_number: int  # "6.1.0" -> 610, as AMT Remoto compares versions
    partitioned: bool

    def to_dict(self) -> dict:
        return asdict(self)


def decode_info(frame: FrameV2) -> InfoV2:
    """INFO reply (OnlineInterpreter.Read24NetStatus): model, firmware, partitioned flag."""
    if frame.command != Cmd.INFO:
        raise FrameError(f"expected v2 INFO 0x{Cmd.INFO:04X}, got 0x{frame.command:04X}")
    p = frame.payload
    if len(p) < 5:
        raise FrameError("v2 INFO reply too short")
    info = model_v2(p[0])
    if info.kind == "8000" or p[1] > 0:
        numbers = (p[1], p[2], p[3])
    else:  # ANM 24 NET with packed version: (p2 >> 4).(p2 & 0x0F).p1
        numbers = (p[2] >> 4, p[2] & 0x0F, p[1])
    firmware = ".".join(map(str, numbers))
    if info.name == "ANM 24 NET G2" and len(p) > 6 and p[6] in (0, 1):
        firmware += " dev" if p[6] == 0 else " beta"
    return InfoV2(
        model_code=p[0],
        model=info.name,
        kind=info.kind,
        firmware=firmware,
        firmware_number=int("".join(map(str, numbers))),
        partitioned=bool(p[4] & 0x10),
    )


def _anm_state(byte: int, firmware_number: int) -> str:
    """OnlineInterpreter.Read8000Status for the ANM 24 NET."""
    if byte & 0x20 and byte & 0x40 and not byte & 0x80:
        return "armed"
    if firmware_number >= 600 and byte & 0x80:
        return "stay"
    if firmware_number < 600 and byte & 0x20 and not byte & 0x40:
        return "stay"
    return "disarmed"


def decode_status_anm(frame: FrameV2, info: InfoV2) -> StatusV2:
    """Basic status (0x0B01) of the ANM 24 NET: state, 24 zones, bypass, clock."""
    if frame.command != Cmd.STATUS_BASIC:
        raise FrameError(f"expected v2 basic status 0x{Cmd.STATUS_BASIC:04X}, got 0x{frame.command:04X}")
    p = frame.payload
    if len(p) < 48:
        raise FrameError(f"ANM status too short ({len(p)} bytes, need 48)")
    first, second = _bits(p[17:20]), _bits(p[25:28])
    # G2: first array = open, second = triggered; first generation: the other way round.
    opened, triggered = (first, second) if info.model == "ANM 24 NET G2" else (second, first)
    state = _anm_state(p[0], info.firmware_number)
    return StatusV2(
        model_code=info.model_code,
        model=info.model,
        firmware=info.firmware,
        state=state,
        armed=state in ("armed", "stay"),
        firing=bool(p[0] & 0x02),
        partitioned=info.partitioned,
        partitions=[],
        open_zones=opened,
        violated_zones=triggered,
        bypassed_zones=_bits(p[33:36]),
        tamper_zones=[],
        low_battery_zones=[],
        communication_error_zones=[],
        clock=_clock(p[43:48]),
        clock_raw=p[43:49].hex(" "),
        battery=None,
    )


def check_reply(frame: FrameV2) -> FrameV2:
    """Raise V2CommandError on NACK; anything else counts as success (as in Guardian)."""
    if frame.command == Cmd.NACK:
        code = frame.payload[0] if frame.payload else 0
        raise V2CommandError(ERRORS.get(code, f"error 0x{code:02X}"))
    return frame


def auth_result(frame: FrameV2) -> tuple[bool, str]:
    if frame.command == Cmd.NACK:
        check_reply(frame)
    if not frame.payload:
        return False, "empty AUTH reply"
    code = frame.payload[0]
    text = AUTH_RESULTS.get(code, f"unknown AUTH result {code}")
    return text == "accepted", text
