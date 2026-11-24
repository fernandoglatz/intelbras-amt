import pytest

from intelbras_amt.protocol import (
    FrameError,
    arm_mask,
    build_frame,
    crc16,
    encode_password,
    identify_data,
    parse_frame,
    read_eeprom_data,
)

from conftest import LIVE

# Requests the app logic produced and the live panel accepted.
CAPTURED_REQUESTS = {
    bytes([0x10]): "05 e7 01 10 06 60 6a",
    bytes([0x17]): "05 e7 01 17 86 71 fc",
    bytes([0x15]): "05 e7 01 15 06 7e 71",
    bytes([0x14]): "05 e7 01 14 86 7b f5",
    bytes([0x1D]): "05 e7 01 1d 86 4d ca",
    bytes([0x19, 0x10]): "06 e7 02 19 10 d6 4b 88",
    bytes([0x12, 0x02, 0xA3, 0x01]): "08 e7 04 12 02 a3 01 a3 c2 c7",
    bytes([0x12, 0x06, 0xF0, 0x06]): "08 e7 04 12 06 f0 06 c9 85 ba",
}


@pytest.mark.parametrize("data,expected", CAPTURED_REQUESTS.items())
def test_build_frame_matches_captured_requests(data, expected):
    assert build_frame(data) == bytes.fromhex(expected)


@pytest.mark.parametrize("name", sorted(LIVE))
def test_parse_live_replies(name):
    frame = parse_frame(LIVE[name])
    assert frame.data[0] & 0x80 or frame.data[0] in (0x50, 0x4D)


def test_round_trip():
    data = bytes(range(1, 40))
    assert parse_frame(build_frame(data)).data == data


def test_crc_is_little_endian_table_crc():
    assert crc16(bytes([0x01, 0x10])) == bytes([0x06, 0x60])
    assert crc16(b"") == b"\x00\x00"


@pytest.mark.parametrize(
    "raw,message",
    [
        (bytes.fromhex("05 e7 01 90 85"), "too short"),
        (bytes.fromhex("05 e7 01 90 85 63"), "length mismatch"),
        (bytes.fromhex("05 e7 01 90 85 63 6b"), "checksum"),
        (bytes.fromhex("05 e7 01 90 85 64 6d"), "CRC"),
        (bytes.fromhex("05 e9 01 90 85 63 6a"), "header"),
        (bytes.fromhex("06 e7 01 90 85 63 6a"), "length"),
        (bytes.fromhex("05 e7 02 90 85 63 6a"), "data length"),
    ],
)
def test_parse_rejects_corrupt_frames(raw, message):
    with pytest.raises(FrameError, match=message):
        parse_frame(raw)


def test_build_frame_rejects_empty_and_oversized():
    with pytest.raises(ValueError):
        build_frame(b"")
    with pytest.raises(ValueError):
        build_frame(bytes(251))


def test_password_digit_pairs_become_hex_bytes():
    assert encode_password("246810") == bytes([0x24, 0x68, 0x10])
    assert encode_password("1234") == bytes([0x12, 0x34])
    assert identify_data("123456") == bytes([0x11, 0x12, 0x34, 0x56, 0x34])


@pytest.mark.parametrize("bad", ["", "123", "12345", "1234567", "12ab56"])
def test_password_validation(bad):
    with pytest.raises(ValueError):
        encode_password(bad)


def test_read_eeprom_request_layout():
    assert read_eeprom_data(675, 1) == bytes([0x12, 0x02, 0xA3, 0x01])
    with pytest.raises(ValueError):
        read_eeprom_data(0x10000, 1)
    with pytest.raises(ValueError):
        read_eeprom_data(0, 0)


@pytest.mark.parametrize(
    "partition,stay,mask",
    [(None, False, 0x00), (1, False, 0x01), (2, False, 0x02), (None, True, 0xF0), (1, True, 0x10), (2, True, 0x20)],
)
def test_arm_mask_matches_app(partition, stay, mask):
    assert arm_mask(partition, stay) == mask
