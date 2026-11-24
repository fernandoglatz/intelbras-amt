"""Decoders for ISECNet v1 (E7) replies: AMT 2018 family, Smart models and AMT 4010 Smart.

Offsets follow AMT Remoto's parsers (OnlineInterpreter.Read2018Status,
Read4010Status, InterpreterInformation.*). The app indexes the raw frame; here
``data`` starts at the answer byte, so app index ``i`` is ``data[i - 3]``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

from .protocol import Answer, Frame, FrameError


@dataclass(frozen=True)
class ModelInfo:
    name: str
    partitions: int
    zones: int
    pgms: int
    layout: str | None  # "2018", "smart", "4010" or None (status not decodable)


MODELS: dict[int, ModelInfo] = {
    0x1E: ModelInfo("AMT 2018 E/EG", 2, 48, 2, "2018"),
    0x2E: ModelInfo("AMT 2118 EG", 2, 48, 2, "2018"),
    0x31: ModelInfo("AMT 2016 E3G", 2, 48, 2, "2018"),
    0x32: ModelInfo("AMT 2018 E3G", 2, 48, 2, "2018"),
    0x34: ModelInfo("AMT 2018 E Smart", 2, 48, 2, "smart"),
    0x36: ModelInfo("AMT 1000 Smart", 0, 48, 2, "smart"),
    0x41: ModelInfo("AMT 4010 Smart", 4, 64, 19, "4010"),
    0x61: ModelInfo("AMT 1016 NET", 2, 48, 2, "2018"),
    0x24: ModelInfo("ANM 24 NET", 0, 24, 1, None),
    0x25: ModelInfo("ANM 24 NET G2", 0, 24, 1, None),
}

SMART_MODELS = {code for code, info in MODELS.items() if info.layout == "smart"}
VOLTAGE_DIVISOR = 67.0


def model_info(code: int) -> ModelInfo:
    return MODELS.get(code, ModelInfo(f"unknown 0x{code:02X}", 0, 48, 0, None))


def _problem_names() -> list[str]:
    names = [
        "AC power failure",
        "Low battery",
        "Battery missing or reversed",
        "Battery short circuit",
        "Auxiliary output overload",
        "Reserved 05",
        "Reserved 06",
        "Reserved 07",
    ]
    names += [f"Keypad {i} problem" for i in range(1, 5)]
    names += [f"Receiver {i} problem" for i in range(1, 5)]
    names += [f"PGM expander {i} problem" for i in range(1, 5)]
    names += [f"Zone expander {i} problem" for i in range(1, 7)]
    names += ["Reserved 26", "Reserved 27"]
    names += [f"Keypad {i} tamper" for i in range(1, 5)]
    names += [
        "Siren wire cut",
        "Siren wire short circuit",
        "Phone line cut",
        "Event communication failure",
    ]
    names += [f"Reserved {i}" for i in range(36, 40)]
    names += [f"Wireless sensor low battery, zone {z}" for z in range(17, 65)]
    names += [f"Zone {z} tamper" for z in range(1, 65)]
    names += [f"Zone {z} short circuit" for z in range(1, 65)]
    assert len(names) == 216
    return names


PROBLEM_NAMES = _problem_names()


def _expect(frame: Frame, answer: int, min_len: int) -> bytes:
    if frame.command != answer:
        raise FrameError(f"expected answer 0x{answer:02X}, got 0x{frame.command:02X}")
    if len(frame.data) < min_len:
        raise FrameError(f"answer 0x{answer:02X} too short: {frame.data.hex(' ')}")
    return frame.data


def _bits(data: bytes, first_zone: int = 1) -> list[int]:
    return [
        first_zone + index * 8 + bit
        for index, byte in enumerate(data)
        for bit in range(8)
        if byte & (1 << bit)
    ]


def firmware(byte: int) -> str:
    return f"{byte >> 4}.{byte & 0x0F}"


def _firmware_number(byte: int) -> int:
    """Firmware as the app compares it: "5.7" -> 57."""
    return (byte >> 4) * 10 + (byte & 0x0F)


@dataclass
class Partition:
    id: int
    name: str
    armed: bool
    stay_armed: bool | None = None


@dataclass
class Status:
    model_code: int
    model: str
    firmware: str
    armed_mask: int
    armed: bool
    partitions: list[Partition]
    open_zones: list[int]
    triggered_zones: list[int]
    ac_voltage: float
    battery_voltage: float
    clock: str | None
    unknown_flags: int
    zone_count: int = 48
    stay_armed: bool | None = None
    bypassed_zones: list[int] = field(default_factory=list)
    partitioned: bool | None = None
    alarm_firing: bool | None = None
    pgm: dict[str, bool] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    # Smart models only (from the 0x27 reply).
    enabled_zones: list[int] | None = None
    stay_zones: list[int] | None = None
    wireless_zones: list[int] | None = None
    zone_partitions: dict[str, list[int]] | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class NeedsSmartStatus(FrameError):
    """A Smart model answered STATUS (0x17); its full status comes from 0x27."""

    def __init__(self, model_code: int):
        super().__init__(f"{model_info(model_code).name} reports its status with command 0x27")
        self.model_code = model_code


def status_model(frame: Frame) -> int:
    """Model code from a STATUS / STATUS_SMART reply."""
    if frame.command not in (Answer.STATUS, Answer.STATUS_SMART) or len(frame.data) < 2:
        raise FrameError(f"not a status reply: {frame.data.hex(' ')}")
    return frame.data[1]


def _zone_pairs(data: bytes, start: int, pairs: int) -> tuple[list[int], list[int]]:
    open_zones: list[int] = []
    triggered: list[int] = []
    for group in range(pairs):
        opened, fired = data[start + group * 2], data[start + group * 2 + 1]
        for bit in range(8):
            zone = group * 8 + bit + 1
            if opened & (1 << bit):
                open_zones.append(zone)
            if fired & (1 << bit):
                triggered.append(zone)
    return open_zones, triggered


def _voltage(data: bytes, index: int) -> float:
    return round((data[index] << 8 | data[index + 1]) / VOLTAGE_DIVISOR, 2)


def _partitions(info: ModelInfo, armed_mask: int, stay_mask: int | None) -> list[Partition]:
    return [
        Partition(
            id=i,
            name=f"Partition {chr(64 + i)}",
            armed=bool(armed_mask & (1 << (i - 1))),
            stay_armed=None if stay_mask is None else bool(stay_mask & (1 << (i - 1))),
        )
        for i in range(1, info.partitions + 1)
    ]


def _whole_mask(info: ModelInfo) -> int:
    return 0x0F if info.partitions == 4 else 0x03


def decode_status(frame: Frame) -> Status:
    code = status_model(frame)
    info = model_info(code)
    if frame.command == Answer.STATUS_SMART:
        if info.layout != "smart":
            raise FrameError(f"0x27 status from non-Smart model {info.name}")
        return _decode_smart(frame.data, code, info)
    if info.layout == "smart":
        raise NeedsSmartStatus(code)
    if info.layout == "4010":
        return _decode_4010(frame.data, code, info)
    if info.layout == "2018":
        return _decode_2018(frame.data, code, info)
    raise FrameError(f"status layout for {info.name} is not supported")


def _decode_2018(data: bytes, code: int, info: ModelInfo) -> Status:
    if len(data) < 26:
        raise FrameError(f"status too short: {data.hex(' ')}")
    armed_mask = data[3]
    open_zones, triggered = _zone_pairs(data, 4, 6)
    return Status(
        model_code=code,
        model=info.name,
        firmware=firmware(data[2]),
        armed_mask=armed_mask,
        armed=(armed_mask & 0x03) == 0x03,
        partitions=_partitions(info, armed_mask, None),
        open_zones=open_zones,
        triggered_zones=triggered,
        ac_voltage=_voltage(data, 17),
        battery_voltage=_voltage(data, 19),
        clock=_clock(data[21], data[22], data[23], data[24], data[25]),
        unknown_flags=data[16],
        zone_count=info.zones,
    )


def _decode_4010(data: bytes, code: int, info: ModelInfo) -> Status:
    if len(data) < 30:
        raise FrameError(f"status too short: {data.hex(' ')}")
    armed_mask = data[3]
    stay_known = _firmware_number(data[2]) >= 57  # Read4010Status: stay bits from fw 5.7
    stay_mask = armed_mask >> 4 if stay_known else None
    open_zones, triggered = _zone_pairs(data, 4, 8)
    return Status(
        model_code=code,
        model=info.name,
        firmware=firmware(data[2]),
        armed_mask=armed_mask,
        armed=(armed_mask & 0x0F) == 0x0F,
        stay_armed=None if stay_mask is None else stay_mask == 0x0F,
        partitions=_partitions(info, armed_mask & 0x0F, stay_mask),
        open_zones=open_zones,
        triggered_zones=triggered,
        ac_voltage=_voltage(data, 21),
        battery_voltage=_voltage(data, 23),
        clock=_clock(data[25], data[26], data[27], data[28], data[29]),
        unknown_flags=data[20],
        zone_count=info.zones,
    )


def _decode_smart(data: bytes, code: int, info: ModelInfo) -> Status:
    if len(data) < 90:
        raise FrameError(f"Smart status too short: {data.hex(' ')}")
    base = _decode_2018(data, code, info)
    stay_mask = data[87]
    base.firmware = firmware(data[89]) + ".0"
    base.partitioned = data[88] == 1
    base.stay_armed = (stay_mask & 0x03) == 0x03
    base.partitions = _partitions(info, base.armed_mask, stay_mask)
    base.bypassed_zones = _bits(data[27:33])
    base.enabled_zones = _bits(data[33:39])
    base.zone_partitions = {"A": _bits(data[39:45]), "B": _bits(data[45:51])}
    base.stay_zones = _bits(data[51:57])
    base.wireless_zones = _bits(data[57:63])
    return base


def _clock(hour: int, minute: int, day: int, month: int, year: int) -> str | None:
    try:
        return datetime(2000 + year, month, day, hour, minute).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return None


def decode_bypassed(frame: Frame, zone_count: int = 48) -> list[int]:
    size = zone_count // 8
    data = _expect(frame, Answer.BYPASSED_ZONES, 1 + size)
    return _bits(data[1 : 1 + size])


def decode_problems(frame: Frame) -> list[str]:
    answer = Answer.NEW_PROBLEMS if frame.command == Answer.NEW_PROBLEMS else Answer.PROBLEMS
    data = _expect(frame, answer, 1)
    return [PROBLEM_NAMES[bit - 1] for bit in _bits(data[1:28]) if bit - 1 < len(PROBLEM_NAMES)]


@dataclass
class SirenStatus:
    alarm_firing: bool
    pgm: dict[str, bool]


def decode_siren(frame: Frame) -> SirenStatus:
    data = _expect(frame, Answer.MENU_FUNCTIONS, 2)
    flags = data[1]
    return SirenStatus(
        alarm_firing=bool(flags & 0x04),
        pgm={"PGM1": bool(flags & 0x40), "PGM2": bool(flags & 0x20), "PGM3": bool(flags & 0x10)},
    )


def decode_eeprom(frame: Frame) -> bytes:
    return _expect(frame, Answer.READ_EEPROM, 2)[1:]


def decode_mac(frame: Frame) -> str:
    data = decode_eeprom(frame)
    if len(data) < 6:
        raise FrameError("MAC reply too short")
    return _mac(data[:6])


def _mac(data: bytes) -> str:
    return ":".join(f"{b:02X}" for b in data)


def _ipv4(data: bytes) -> str:
    return ".".join(str(b) for b in data)


def decode_bus_devices(frame: Frame) -> dict[str, list[int]]:
    """READ_BUS_DEVICES: keypads (XAT) and receivers (XAR) present on the bus."""
    flags = _expect(frame, Answer.BUS_DEVICES, 2)[1]
    return {
        "keypads": [i + 1 for i in range(4) if flags & (1 << i)],
        "receivers": [i + 1 for i in range(4) if flags & (1 << (i + 4))],
    }


CELL_MODULES_CONNECTIONS = {0: "GPRS", 1: "3G", 2: "4G", 3: None}


def decode_connections(frame: Frame) -> dict:
    data = _expect(frame, Answer.CONNECTIONS, 3)
    links = data[2]

    def flags(shift: int) -> dict[str, bool]:
        return {name: bool(links & (1 << (shift + i))) for i, name in enumerate(("ip1", "ip2", "cloud"))}

    return {
        "cellular_module": CELL_MODULES_CONNECTIONS.get(data[1]),
        "ethernet": flags(0),
        "cellular": flags(4),
    }


def decode_network_card(frame: Frame) -> dict[str, str]:
    data = _expect(frame, Answer.NETWORK_CARD, 27)
    return {
        "ip": _ipv4(data[1:5]),
        "mask": _ipv4(data[5:9]),
        "gateway": _ipv4(data[9:13]),
        "dns1": _ipv4(data[13:17]),
        "dns2": _ipv4(data[17:21]),
        "mac": _mac(data[21:27]),
    }


CELL_MODULES = {1: "2G", 2: "3G", 3: "4G"}
CARRIERS = {0: "Claro", 1: "Oi", 2: "Tim", 3: "Vivo", 4: "unknown"}


def _ascii(data: bytes) -> str:
    return data.decode("ascii", errors="replace").strip("\x00 ")


def decode_cell_card(frame: Frame) -> dict:
    data = _expect(frame, Answer.CELL_CARD, 5)
    module = CELL_MODULES.get(data[1])
    return {
        "module": module,
        "signal": data[2],
        "signal_percent": min(100, round(data[2] * 100 / 31)) if module else None,
        "sim": data[3] if data[3] in (1, 2) else None,
        "carrier": CARRIERS.get(data[4]) if module else None,
        "iccid": _ascii(data[5:25]),
        "imei": _ascii(data[25:40]),
    }


def decode_wireless_sensors(frame: Frame) -> list[dict]:
    """WIRELESS_SENSORS (Smart, fw >= 1.80): per-sensor state for zones 25-48."""
    data = _expect(frame, Answer.WIRELESS_SENSORS, 48)

    def bit(offset: int, index: int) -> bool:
        return bool(data[offset + index // 8] & (1 << (index % 8)))

    sensors = []
    for index in range(24):
        if not bit(1, index):
            continue
        level = data[24 + index]
        sensors.append(
            {
                "zone": 25 + index,
                "low_battery": bit(4, index),
                "fsk": bit(7, index),
                "supervision_failure": bit(10, index),
                "tamper": bit(13, index),
                "motion_sensor": bit(16, index),
                "signal_percent": None if level == 0xFF else level * 10,
            }
        )
    return sensors


def expect_ack(frame: Frame, answer: int) -> bytes:
    """Check a write command's answer code; returns the rest of the reply."""
    return _expect(frame, answer, 1)[1:]


def expect_write_ack(frame: Frame, address: int) -> None:
    data = _expect(frame, Answer.WRITE_EEPROM, 3)
    if data[1] != address >> 8 or data[2] != address & 0xFF:
        raise FrameError(f"write acknowledged for another address: {data.hex(' ')}")


def decode_search_bus(frame: Frame) -> bool:
    return _expect(frame, Answer.SEARCH_BUS_DEVICES, 2)[1] == 0


class OpenZonesError(RuntimeError):
    """The panel refused to arm because zones are open."""


def check_arm_answer(frame: Frame) -> None:
    data = _expect(frame, Answer.REMOTE_ARM, 2)
    if data[1] & 0xF0 == 0x80:
        raise OpenZonesError("panel refused: there are open zones")


def is_hang_up_ack(frame: Frame) -> bool:
    return frame.data[:2] == bytes([Answer.HANG_UP, 0x48])
