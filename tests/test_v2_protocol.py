"""ISECNet v2 (AMT 8000 family) framing, payloads and status decoding.

Sources: Guardian ISECNetV2Protocol / ISECNetV2ServerProtocol / ISECNetV2ParseHelper,
AMT Remoto LoginRepository.OpenAmt8000, Packet(CommandTypesAmt8000) and
OnlineInterpreter.Read8000StatusFull.
"""

import pytest

from intelbras_amt import decode_v2, protocol_v2 as p2
from intelbras_amt.protocol import FrameError


def test_frame_layout_and_checksum():
    frame = p2.build_frame(p2.Cmd.STATUS)
    # dest 00 00, local source 00 F1, length 2 (command only), command 0B 4A, checksum
    assert frame[:8] == bytes.fromhex("00 00 00 f1 00 02 0b 4a")
    body = frame[:-1]
    chk = 0
    for b in body:
        chk ^= b
    assert frame[-1] == chk ^ 0xFF


def test_frame_length_counts_command_and_payload():
    frame = p2.build_frame(p2.Cmd.ARM_DISARM, bytes([0xFF, 0x01]))
    assert frame[4:6] == bytes([0x00, 0x04])
    assert p2.frame_length(frame[:6]) == len(frame)


def test_parse_round_trip():
    frame = p2.parse_frame(p2.build_frame(p2.Cmd.PGM_ON_OFF, bytes([0x00, 0x01]), source=b"\x12\x34"))
    assert frame.command == p2.Cmd.PGM_ON_OFF and frame.payload == bytes([0x00, 0x01])
    assert frame.source == b"\x12\x34"


@pytest.mark.parametrize(
    "raw",
    [
        bytes.fromhex("00 00 00 f1 00 02 0b"),  # truncated
        bytes.fromhex("00 00 00 f1 00 05 0b 4a 00"),  # length beyond data
    ],
)
def test_parse_rejects_truncated(raw):
    with pytest.raises(FrameError):
        p2.parse_frame(raw)


def test_parse_rejects_bad_checksum():
    frame = bytearray(p2.build_frame(p2.Cmd.STATUS))
    frame[-1] ^= 0x01
    with pytest.raises(FrameError, match="checksum"):
        p2.parse_frame(bytes(frame))


def test_auth_payload_follows_amt_remoto():
    # OpenAmt8000: 01, six password digits (hex nibble value), 0x10, 0x00
    assert p2.auth_payload("123450") == bytes([0x01, 1, 2, 3, 4, 5, 0, 0x10, 0x00])
    assert p2.auth_payload("1234") == bytes([0x01, 1, 2, 3, 4, 0, 0, 0x10, 0x00])


@pytest.mark.parametrize("bad", ["", "123", "1234567", "12a4"])
def test_auth_payload_validation(bad):
    with pytest.raises(ValueError):
        p2.auth_payload(bad)


@pytest.mark.parametrize(
    "partition,op,expected",
    [(None, p2.ArmOp.ARM, "ff 01"), (1, p2.ArmOp.DISARM, "01 00"), (16, p2.ArmOp.STAY, "10 02")],
)
def test_arm_payload(partition, op, expected):
    assert p2.arm_payload(partition, op) == bytes.fromhex(expected)


def test_arm_payload_partition_range():
    with pytest.raises(ValueError):
        p2.arm_payload(17, p2.ArmOp.ARM)


def test_bypass_pgm_panic_siren_payloads():
    assert p2.bypass_payload([1, 64], True) == bytes([0, 1, 63, 1])
    assert p2.bypass_payload([2], False) == bytes([1, 0])
    assert p2.pgm_payload(1, True) == bytes([0, 1])
    assert p2.pgm_payload(16, False) == bytes([15, 0])
    assert p2.panic_payload("audible") == bytes([1])
    assert p2.panic_payload("medical") == bytes([3])
    assert p2.SIREN_OFF_PAYLOAD == bytes([0xFF])
    with pytest.raises(ValueError):
        p2.bypass_payload([65], True)
    with pytest.raises(ValueError):
        p2.pgm_payload(17, True)
    with pytest.raises(ValueError):
        p2.panic_payload("loud")


def test_nack_is_an_error_with_reason():
    nack = p2.parse_frame(p2.build_frame(p2.Cmd.NACK, bytes([39])))
    with pytest.raises(p2.V2CommandError, match="open zones"):
        decode_v2.check_reply(nack)
    ack = p2.parse_frame(p2.build_frame(p2.Cmd.ACK))
    decode_v2.check_reply(ack)


def test_auth_result():
    ok = p2.parse_frame(p2.build_frame(p2.Cmd.AUTH, bytes([0x00, 0x01])))
    assert decode_v2.auth_result(ok) == (True, "accepted")
    bad = p2.parse_frame(p2.build_frame(p2.Cmd.AUTH, bytes([0x01])))
    assert decode_v2.auth_result(bad) == (False, "wrong password")


# -- status -----------------------------------------------------------------

def status_payload(general=0x00, partitions=None, model=0x01) -> bytearray:
    payload = bytearray(143)
    payload[0] = model
    payload[1:4] = bytes([3, 2, 5])
    payload[4] = 0x10  # partitioned
    payload[20] = general
    for i, value in (partitions or {}).items():
        payload[21 + i] = value
    payload[38] = 0x01  # zone 1 open
    payload[46 + 7] = 0x80  # zone 64 violated
    payload[54] = 0x02  # zone 2 bypassed
    payload[64:70] = bytes([0x24, 0x11, 0x26, 0x13, 0x05, 0x00])  # BCD 24/11/26 13:05:00
    payload[73] = 0x04  # zone 3 communication error
    payload[89] = 0x08  # zone 4 tamper
    payload[105] = 0x10  # zone 5 low battery
    payload[134] = 4  # battery high
    payload[137] = 0x01  # PGM 1 on
    return payload


def status_frame(payload):
    return p2.parse_frame(p2.build_frame(p2.Cmd.STATUS, bytes(payload)))


def test_status_decoding():
    st = decode_v2.decode_status(status_frame(status_payload(0x60, {1: 0x81, 2: 0x82})))
    assert st.model == "AMT 8000" and st.firmware == "3.2.5"
    assert st.state == "armed" and st.armed is True and st.firing is False
    assert st.partitioned is True
    assert [(p.id, p.armed, p.stay) for p in st.partitions] == [(1, True, False), (2, False, True)]
    assert st.open_zones == [1] and st.violated_zones == [64] and st.bypassed_zones == [2]
    assert st.communication_error_zones == [3] and st.tamper_zones == [4] and st.low_battery_zones == [5]
    assert st.clock == "2026-11-24 13:05"
    assert st.battery == "high"
    assert st.pgm == {i: i == 1 for i in range(1, 17)}


@pytest.mark.parametrize(
    "general,state",
    [(0x00, "disarmed"), (0x20, "partial"), (0x60, "armed"), (0xE0, "stay"), (0x62, "armed")],
)
def test_general_state(general, state):
    st = decode_v2.decode_status(status_frame(status_payload(general)))
    assert st.state == state
    assert st.firing is bool(general & 0x02)


def test_status_unsupported_models():
    with pytest.raises(FrameError, match="AMT 9000"):
        decode_v2.decode_status(status_frame(status_payload(model=0x90)))
    with pytest.raises(FrameError, match="ELC 6012"):
        decode_v2.decode_status(status_frame(status_payload(model=0x35)))


def test_status_too_short():
    with pytest.raises(FrameError, match="too short"):
        decode_v2.decode_status(status_frame(status_payload()[:100]))


def test_invalid_bcd_clock_is_none():
    payload = status_payload()
    payload[64] = 0x3F
    assert decode_v2.decode_status(status_frame(payload)).clock is None


# -- INFO and ANM 24 NET (basic status) --------------------------------------

def info_frame(model, fw=(3, 2, 5), flags=0x10, tag=0x02):
    return p2.parse_frame(p2.build_frame(p2.Cmd.INFO, bytes([model, *fw, flags, 0, tag])))


def test_info_8000_and_anm():
    info = decode_v2.decode_info(info_frame(0x01))
    assert (info.model, info.kind, info.firmware, info.partitioned) == ("AMT 8000", "8000", "3.2.5", True)
    anm = decode_v2.decode_info(info_frame(0x24, fw=(0x00, 0x52, 0x00), flags=0x00))
    assert (anm.model, anm.kind, anm.firmware, anm.partitioned) == ("ANM 24 NET", "anm", "5.2.0", False)
    assert decode_v2.decode_info(info_frame(0x02)).model == "ANM 24 NET"  # AMT Remoto's code
    g2 = decode_v2.decode_info(info_frame(0x25, fw=(6, 1, 0), tag=0x01))
    assert (g2.model, g2.firmware) == ("ANM 24 NET G2", "6.1.0 beta")


def test_info_wrong_answer():
    with pytest.raises(FrameError, match="INFO"):
        decode_v2.decode_info(p2.parse_frame(p2.build_frame(p2.Cmd.STATUS, bytes(5))))


def anm_payload(general=0x00):
    p = bytearray(49)
    p[0] = general
    p[17] = 0x01  # first array: zone 1
    p[25] = 0x02  # second array: zone 2
    p[33] = 0x04  # zone 3 bypassed
    p[43:49] = bytes([0x24, 0x11, 0x26, 0x13, 0x05, 0x00])
    return p2.parse_frame(p2.build_frame(p2.Cmd.STATUS_BASIC, bytes(p)))


def test_anm_status_g1_and_g2_zone_arrays():
    g1 = decode_v2.decode_info(info_frame(0x24, fw=(5, 2, 0)))
    st = decode_v2.decode_status_anm(anm_payload(0x60), g1)
    assert st.model == "ANM 24 NET" and st.state == "armed"
    # first generation: first array = triggered, second = open (Read8000Status)
    assert st.violated_zones == [1] and st.open_zones == [2] and st.bypassed_zones == [3]
    assert st.clock == "2026-11-24 13:05" and st.partitions == []
    g2 = decode_v2.decode_info(info_frame(0x25, fw=(6, 1, 0)))
    st2 = decode_v2.decode_status_anm(anm_payload(0x00), g2)
    assert st2.open_zones == [1] and st2.violated_zones == [2]


@pytest.mark.parametrize(
    "fw,general,state",
    [
        ((6, 0, 0), 0xE0, "stay"),  # fw >= 6.0.0: 0x80 = partial (stay)
        ((6, 0, 0), 0x60, "armed"),
        ((5, 2, 0), 0x20, "stay"),  # older: 0x20 without 0x40 = partial
        ((5, 2, 0), 0x00, "disarmed"),
        ((5, 2, 0), 0x62, "armed"),
    ],
)
def test_anm_states(fw, general, state):
    info = decode_v2.decode_info(info_frame(0x24, fw=fw))
    st = decode_v2.decode_status_anm(anm_payload(general), info)
    assert st.state == state and st.firing is bool(general & 0x02)


def test_anm_status_too_short():
    info = decode_v2.decode_info(info_frame(0x24))
    short = p2.parse_frame(p2.build_frame(p2.Cmd.STATUS_BASIC, bytes(20)))
    with pytest.raises(FrameError, match="too short"):
        decode_v2.decode_status_anm(short, info)
