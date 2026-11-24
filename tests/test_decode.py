import pytest

from intelbras_amt import decode
from intelbras_amt.protocol import FrameError, build_frame, parse_frame

from conftest import LIVE, status_data


def frame(data: bytes):
    return parse_frame(build_frame(data))


def test_live_status():
    st = decode.decode_status(parse_frame(LIVE["status"]))
    assert st.model == "AMT 1016 NET"
    assert st.firmware == "2.6"
    assert st.armed is True
    assert [p.armed for p in st.partitions] == [True, True]
    assert st.open_zones == [] and st.triggered_zones == []
    assert st.ac_voltage == 14.57
    assert st.battery_voltage == 13.13
    assert st.clock == "2026-11-24 00:02"
    assert st.unknown_flags == 0x08


def test_status_zone_pairs_are_open_then_triggered():
    zones = bytearray(12)
    zones[0] = 0b0000_0101  # open 1, 3
    zones[1] = 0b0000_0100  # triggered 3
    zones[2] = 0b1000_0000  # open 16
    zones[11] = 0b1000_0000  # triggered 48
    st = decode.decode_status(frame(status_data(0x01, bytes(zones))))
    assert st.open_zones == [1, 3, 16]
    assert st.triggered_zones == [3, 48]
    assert st.armed is False
    assert [p.armed for p in st.partitions] == [True, False]


def test_status_invalid_clock_is_none():
    data = bytearray(status_data())
    data[24] = 13  # month 13
    assert decode.decode_status(frame(bytes(data))).clock is None


@pytest.mark.parametrize("model,name", [(0x24, "ANM 24 NET"), (0x99, "unknown 0x99")])
def test_status_rejects_unsupported_model(model, name):
    with pytest.raises(FrameError, match=name):
        decode.decode_status(frame(status_data(model=model)))


def test_4010_status_with_2018_length_is_too_short():
    with pytest.raises(FrameError, match="too short"):
        decode.decode_status(frame(status_data(model=0x41)))


def test_status_rejects_wrong_answer_and_short_data():
    with pytest.raises(FrameError, match="not a status reply"):
        decode.decode_status(parse_frame(LIVE["siren"]))
    with pytest.raises(FrameError, match="too short"):
        decode.decode_status(frame(bytes([0x97, 0x61])))


def test_bypassed_zones():
    assert decode.decode_bypassed(parse_frame(LIVE["bypassed"])) == []
    assert decode.decode_bypassed(frame(bytes([0x9D, 0x01, 0, 0, 0, 0, 0x80]))) == [1, 48]


def test_problems():
    assert decode.decode_problems(parse_frame(LIVE["problems"])) == []
    data = bytearray([0x94]) + bytes(27)
    data[1] = 0b0000_0011  # AC failure, low battery
    data[5] = 0b0000_0001  # bit 32: siren wire cut
    data[12] = 0b0000_0001  # bit 88: zone 1 tamper
    assert decode.decode_problems(frame(bytes(data))) == [
        "AC power failure",
        "Low battery",
        "Siren wire cut",
        "Zone 1 tamper",
    ]


def test_problem_table_size():
    assert len(decode.PROBLEM_NAMES) == 216
    assert decode.PROBLEM_NAMES[40] == "Wireless sensor low battery, zone 17"
    assert decode.PROBLEM_NAMES[215] == "Zone 64 short circuit"


def test_siren():
    live = decode.decode_siren(parse_frame(LIVE["siren"]))
    assert live.alarm_firing is False and not any(live.pgm.values())
    firing = decode.decode_siren(frame(bytes([0x99, 0x44])))
    assert firing.alarm_firing is True and firing.pgm["PGM1"] is True


def test_eeprom_and_mac():
    assert decode.decode_eeprom(parse_frame(LIVE["config675"])) == bytes([0xF9])
    mac = frame(bytes([0x92, 0x02, 0x00, 0x00, 0xAB, 0xCD, 0xEF]))
    assert decode.decode_mac(mac) == "02:00:00:AB:CD:EF"
    with pytest.raises(FrameError):
        decode.decode_mac(frame(bytes([0x92, 0x01])))


def test_arm_answer():
    decode.check_arm_answer(frame(bytes([0x96, 0x03])))
    with pytest.raises(decode.OpenZonesError):
        decode.check_arm_answer(frame(bytes([0x96, 0x80])))


def test_hang_up_ack():
    assert decode.is_hang_up_ack(parse_frame(LIVE["hangup"]))
    assert not decode.is_hang_up_ack(frame(bytes([0x95, 0x00])))
