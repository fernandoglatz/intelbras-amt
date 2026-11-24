"""Decoders for the Smart and 4010 layouts and the extra read commands.

Offsets follow AMT Remoto's parsers (raw frame index - 3 = data index):
Read4010Status, Read2018Status (Smart branch), SetBypassedInto4010Status,
ReadStatusWirelessDevicesAmt2018ESmart, ReadStatusNetworkCardAmt2018ESmart,
ReadStatusCellCardAmt2018ESmart, ReadZonesWirelessSensorStatus and
OnlineConnections2018DataSource.
"""

import pytest

from intelbras_amt import decode
from intelbras_amt.protocol import FrameError, build_frame, parse_frame


def frame(data: bytes):
    return parse_frame(build_frame(data))


def base_tail():
    # unknown, AC 14.57 V, battery 13.13 V, 00:02, 24/11/26
    return bytes([0x08, 0x03, 0xD0, 0x03, 0x70, 0x00, 0x02, 0x18, 0x0B, 0x1A])


# -- AMT 4010 Smart ----------------------------------------------------------

def status_4010(armed: int, zones: bytes = bytes(16), firmware: int = 0x57) -> bytes:
    return bytes([0x97, 0x41, firmware, armed]) + zones + base_tail()


def test_4010_status_layout():
    zones = bytearray(16)
    zones[0] = 0x01  # zone 1 open
    zones[15] = 0x80  # zone 64 triggered
    st = decode.decode_status(frame(status_4010(0x15, bytes(zones))))
    assert st.model == "AMT 4010 Smart" and st.firmware == "5.7"
    assert st.zone_count == 64
    assert st.open_zones == [1] and st.triggered_zones == [64]
    assert [p.name for p in st.partitions] == ["Partition A", "Partition B", "Partition C", "Partition D"]
    # low nibble 0x5: A and C armed; high nibble 0x1: A stay
    assert [p.armed for p in st.partitions] == [True, False, True, False]
    assert [p.stay_armed for p in st.partitions] == [True, False, False, False]
    assert st.armed is False and st.stay_armed is False
    assert (st.ac_voltage, st.battery_voltage, st.clock) == (14.57, 13.13, "2026-11-24 00:02")


def test_4010_whole_panel_armed_and_stay():
    st = decode.decode_status(frame(status_4010(0xFF)))
    assert st.armed is True and st.stay_armed is True


def test_4010_stay_unknown_before_firmware_5_7():
    st = decode.decode_status(frame(status_4010(0x0F, firmware=0x56)))
    assert st.armed is True and st.stay_armed is None
    assert all(p.stay_armed is None for p in st.partitions)


# -- Smart models (answer 0xA7) -----------------------------------------------

def status_smart(model=0x34, armed=0x01, stay=0x00, partitioned=1) -> bytes:
    head = bytes([0xA7, model, 0x18, armed]) + bytes(12) + base_tail()  # data[0..25]
    ext = bytearray(64)  # data[26..89]
    ext[1] = 0x02  # data[27]: bypassed zone 2
    ext[7] = 0x0F  # data[33]: zones 1-4 enabled
    ext[13] = 0x03  # data[39]: zones 1-2 in partition A
    ext[19] = 0x0C  # data[45]: zones 3-4 in partition B
    ext[25] = 0x04  # data[51]: zone 3 is a stay zone
    ext[31] = 0x09  # data[57]: zones 1 and 4 wireless
    ext[61] = stay  # data[87]: stay armed bits
    ext[62] = partitioned  # data[88]
    ext[63] = 0x18  # data[89]: firmware 1.8
    return head + bytes(ext)


def test_smart_status_extended_fields():
    st = decode.decode_status(frame(status_smart(stay=0x02)))
    assert st.model == "AMT 2018 E Smart" and st.firmware == "1.8.0"
    assert st.partitioned is True
    assert st.bypassed_zones == [2]
    assert st.enabled_zones == [1, 2, 3, 4]
    assert st.zone_partitions == {"A": [1, 2], "B": [3, 4]}
    assert st.stay_zones == [3]
    assert st.wireless_zones == [1, 4]
    assert [p.armed for p in st.partitions] == [True, False]
    assert [p.stay_armed for p in st.partitions] == [False, True]
    assert st.stay_armed is False


def test_amt_1000_smart_has_no_partitions():
    st = decode.decode_status(frame(status_smart(model=0x36, armed=0x03, stay=0x03, partitioned=0)))
    assert st.model == "AMT 1000 Smart"
    assert st.partitions == [] and st.armed is True and st.stay_armed is True
    assert st.partitioned is False


def test_smart_status_too_short():
    with pytest.raises(FrameError, match="too short"):
        decode.decode_status(frame(status_smart()[:60]))


def test_smart_model_answering_plain_status_points_to_smart_command():
    data = bytes([0x97, 0x34, 0x18, 0x00]) + bytes(12) + base_tail()
    with pytest.raises(decode.NeedsSmartStatus):
        decode.decode_status(frame(data))


# -- other reads ----------------------------------------------------------------

def test_new_problems_answer_is_accepted():
    data = bytearray([0xB4]) + bytes(27)
    data[1] = 0x01
    assert decode.decode_problems(frame(bytes(data))) == ["AC power failure"]


def test_bypassed_64_zones():
    data = bytes([0x9D, 0x01, 0, 0, 0, 0, 0, 0, 0x80])
    assert decode.decode_bypassed(frame(data), zone_count=64) == [1, 64]
    assert decode.decode_bypassed(frame(data), zone_count=48) == [1]


def test_bypassed_64_zones_too_short():
    with pytest.raises(FrameError):
        decode.decode_bypassed(frame(bytes([0x9D, 0, 0, 0, 0, 0, 0])), zone_count=64)


def test_bus_devices():
    assert decode.decode_bus_devices(frame(bytes([0xA3, 0x31]))) == {"keypads": [1], "receivers": [1, 2]}


def test_connections():
    info = decode.decode_connections(frame(bytes([0xB0, 0x02, 0x15])))
    assert info == {
        "cellular_module": "4G",
        "ethernet": {"ip1": True, "ip2": False, "cloud": True},
        "cellular": {"ip1": True, "ip2": False, "cloud": False},
    }


def test_network_card():
    body = bytes([192, 168, 1, 50, 255, 255, 255, 0, 192, 168, 1, 1, 8, 8, 8, 8, 1, 1, 1, 1])
    info = decode.decode_network_card(frame(bytes([0xB1]) + body + bytes.fromhex("020000abcdef")))
    assert info == {
        "ip": "192.168.1.50",
        "mask": "255.255.255.0",
        "gateway": "192.168.1.1",
        "dns1": "8.8.8.8",
        "dns2": "1.1.1.1",
        "mac": "02:00:00:AB:CD:EF",
    }


def test_cell_card():
    iccid = b"89550000000000000001"
    imei = b"350000000000001"
    data = bytes([0xB2, 0x03, 31, 0x01, 0x03]) + iccid + imei
    info = decode.decode_cell_card(frame(data))
    assert info == {
        "module": "4G",
        "signal": 31,
        "signal_percent": 100,
        "sim": 1,
        "carrier": "Vivo",
        "iccid": iccid.decode(),
        "imei": imei.decode(),
    }


def test_cell_card_without_module():
    info = decode.decode_cell_card(frame(bytes([0xB2, 0x00, 0x00, 0x00, 0x00]) + bytes(35)))
    assert info["module"] is None and info["carrier"] is None and info["signal_percent"] is None


def test_wireless_sensors():
    data = bytearray([0xB6]) + bytes(47)
    data[1] = 0x03  # zones 25, 26 have sensors
    data[4] = 0x02  # zone 26 low battery
    data[7] = 0x01  # zone 25 FSK
    data[10] = 0x02  # zone 26 supervision failure
    data[13] = 0x01  # zone 25 tamper
    data[16] = 0x02  # zone 26 is a motion sensor
    data[24] = 9  # zone 25 signal 90 %
    data[25] = 0xFF  # zone 26 signal unknown
    sensors = decode.decode_wireless_sensors(frame(bytes(data)))
    assert sensors == [
        {"zone": 25, "low_battery": False, "fsk": True, "supervision_failure": False,
         "tamper": True, "motion_sensor": False, "signal_percent": 90},
        {"zone": 26, "low_battery": True, "fsk": False, "supervision_failure": True,
         "tamper": False, "motion_sensor": True, "signal_percent": None},
    ]


def test_ack_checks():
    decode.expect_ack(frame(bytes([0x98, 0x00])), 0x98)
    with pytest.raises(FrameError, match="expected answer 0x9C"):
        decode.expect_ack(frame(bytes([0x98])), 0x9C)


def test_write_eeprom_ack_checks_address():
    decode.expect_write_ack(frame(bytes([0x93, 0x02, 0xA5])), 677)
    with pytest.raises(FrameError, match="address"):
        decode.expect_write_ack(frame(bytes([0x93, 0x02, 0xA4])), 677)


def test_search_bus_result():
    assert decode.decode_search_bus(frame(bytes([0xA2, 0x00]))) is True
    assert decode.decode_search_bus(frame(bytes([0xA2, 0x01]))) is False
