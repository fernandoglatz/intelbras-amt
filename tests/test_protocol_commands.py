"""Builders for the full E7 command set, the discovery frames and the E9 family."""

from datetime import datetime

import pytest

from intelbras_amt.protocol import (
    E9Reply,
    FrameError,
    build_e9,
    build_frame,
    build_simple,
    bypass_data,
    clock_data,
    parse_e9,
    parse_simple,
    pgm_data,
    write_eeprom_data,
)


def test_clock_is_bcd_with_trailing_zero():
    # WriteInformationBuilder.WriteClockAdjust: 18 YY MM DD hh mm, 7-byte array.
    assert clock_data(datetime(2026, 11, 24, 0, 2)) == bytes([0x18, 0x26, 0x11, 0x24, 0x00, 0x02, 0x00])
    assert clock_data(datetime(2009, 1, 5, 23, 59)) == bytes([0x18, 0x09, 0x01, 0x05, 0x23, 0x59, 0x00])


def test_clock_rejects_years_outside_2000s():
    with pytest.raises(ValueError):
        clock_data(datetime(1999, 12, 31, 0, 0))


def test_bypass_bitmap_is_lsb_first_eight_bytes():
    assert bypass_data([]) == bytes([0x1B]) + bytes(8)
    assert bypass_data([1, 3, 16, 48]) == bytes([0x1B, 0x05, 0x80, 0, 0, 0, 0x80, 0, 0])
    assert bypass_data([64], zone_count=64) == bytes([0x1B, 0, 0, 0, 0, 0, 0, 0, 0x80])


@pytest.mark.parametrize("zones,count", [([0], 48), ([49], 48), ([65], 64)])
def test_bypass_rejects_zones_out_of_range(zones, count):
    with pytest.raises(ValueError):
        bypass_data(zones, zone_count=count)


@pytest.mark.parametrize("pgm,expected", [(1, "19 60"), (2, "19 80"), (3, "19 c0"), (4, "1e 04 00"), (19, "1e 13 00")])
def test_pgm_data(pgm, expected):
    assert pgm_data(pgm) == bytes.fromhex(expected)


@pytest.mark.parametrize("pgm", [0, 20])
def test_pgm_out_of_range(pgm):
    with pytest.raises(ValueError):
        pgm_data(pgm)


def test_write_eeprom_layout():
    assert write_eeprom_data(677, b"\x00") == bytes([0x13, 0x02, 0xA5, 0x01, 0x00])


@pytest.mark.parametrize(
    "address,data",
    [
        (976, b"\x00"),  # forbidden 976..1023
        (970, bytes(10)),  # runs into 976
        (1791, b"\x00"),  # single forbidden address
        (5375, b"\x00"),
        (6000, b"\x00"),  # forbidden 5888..8191
        (9215, b"\x00\x00"),  # past the last valid address
        (-1, b"\x00"),
        (0, b""),
        (0, bytes(65)),
    ],
)
def test_write_eeprom_refuses_forbidden_or_invalid(address, data):
    with pytest.raises(ValueError):
        write_eeprom_data(address, data)


def test_simple_frames_match_live_capture():
    assert build_simple(0xC4) == bytes.fromhex("01 c4 3a")
    assert build_simple(0xC2) == bytes.fromhex("01 c2 3c")
    cmd, body = parse_simple(bytes.fromhex("0c c2 41 4d 54 31 30 31 36 20 4e 45 54 10"))
    assert cmd == 0xC2 and body == b"AMT1016 NET"


@pytest.mark.parametrize(
    "raw", ["0c c2 41 4d 54 31 30 31 36 20 4e 45 54 11", "0c c2 41", "00"]
)
def test_simple_frame_rejects_corrupt(raw):
    with pytest.raises(FrameError):
        parse_simple(bytes.fromhex(raw))


# Vectors confirmed by AMT Mobile V3's montaMyHome and independent projects.
@pytest.mark.parametrize(
    "cmd,expected",
    [
        ([0x5A], "08 E9 21 31 32 33 34 5A 21 40"),
        ([0x41], "08 E9 21 31 32 33 34 41 21 5B"),
        ([0x44], "08 E9 21 31 32 33 34 44 21 5E"),
        ([0x63], "08 E9 21 31 32 33 34 63 21 79"),
        ([0x50, 0x4C, 0x31], "0A E9 21 31 32 33 34 50 4C 31 21 35"),
    ],
)
def test_e9_frames(cmd, expected):
    assert build_e9(bytes(cmd), "1234") == bytes.fromhex(expected)


def test_e9_rejects_bad_password():
    with pytest.raises(ValueError):
        build_e9(b"\x5a", "12a4")


def test_parse_e9_ack_and_errors():
    assert parse_e9(bytes.fromhex("02 e9 fe ea")) == E9Reply(code=0xFE, body=b"")
    reply = parse_e9(bytes.fromhex("02 e9 e1 f5"))
    assert reply.code == 0xE1 and reply.error == "wrong password"
    assert parse_e9(bytes.fromhex("02 e9 fe ea")).error is None


def test_parse_e9_rejects_corrupt():
    with pytest.raises(FrameError):
        parse_e9(bytes.fromhex("02 e9 fe eb"))
    with pytest.raises(FrameError):
        parse_e9(bytes.fromhex("02 e7 fe ec"))


def test_existing_builder_still_used_for_new_commands():
    # Clock request as sent on the wire (BCD date inside a normal E7 frame).
    frame = build_frame(clock_data(datetime(2026, 11, 24, 0, 2)))
    assert frame[:3] == bytes([0x0B, 0xE7, 0x07])  # len = n + 4
