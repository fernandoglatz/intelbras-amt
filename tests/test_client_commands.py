"""Client support for the full E7 command set, discovery and E9 frames."""

from datetime import datetime

import pytest

from intelbras_amt.client import AmtClient, CommandError, PanelTimeout, discover, e9_request
from intelbras_amt.protocol import FrameError

from conftest import CLOSE, FakePanel, PanelState, discovery_handler

PASSWORD = "123456"


@pytest.fixture
def make_panel():
    panels = []

    def factory(**state):
        st = PanelState(**state)
        panel = FakePanel(st)
        panels.append(panel)
        return st, panel

    yield factory
    for panel in panels:
        panel.close()


def client_for(panel, **kwargs):
    kwargs.setdefault("timeout", 1)
    return AmtClient("127.0.0.1", PASSWORD, port=panel.port, **kwargs)


def sent(panel, cmd):
    return [r for r in panel.requests if r[0] == cmd]


# -- status per layout ---------------------------------------------------------

def test_smart_status_uses_0x27_and_new_problems(make_panel):
    state, panel = make_panel(model=0x34)
    state.bypassed = {5}
    with client_for(panel) as c:
        st = c.status()
    assert st.model == "AMT 2018 E Smart" and st.bypassed_zones == [5]
    assert st.partitioned is True
    assert sent(panel, 0x27) and sent(panel, 0x34)
    assert not sent(panel, 0x1D) and not sent(panel, 0x14)


def test_4010_status_reads_64_bypass_zones(make_panel):
    state, panel = make_panel(model=0x41)
    state.bypassed = {64}
    with client_for(panel) as c:
        st = c.status()
    assert st.model == "AMT 4010 Smart" and st.bypassed_zones == [64]
    assert len(st.partitions) == 4


# -- arming -------------------------------------------------------------------

def test_arm_partition_c_on_4010(make_panel):
    state, panel = make_panel(model=0x41)
    with client_for(panel) as c:
        st = c.set_armed(True, partition=3)
    assert [p.armed for p in st.partitions] == [False, False, True, False]
    assert sent(panel, 0x16) == [bytes([0x16, 0x04])]


def test_stay_arm_on_smart_is_state_checked(make_panel):
    state, panel = make_panel(model=0x34)
    with client_for(panel) as c:
        st = c.set_armed(True, partition=2, stay=True)
        assert st.partitions[1].stay_armed is True
        c.set_armed(True, partition=2, stay=True)  # already stay-armed: no packet
    assert sent(panel, 0x16) == [bytes([0x16, 0x20])]


def test_whole_panel_stay_refused_when_partially_stay_armed(make_panel):
    state, panel = make_panel(model=0x34)
    state.stay_mask = 0x01
    with client_for(panel) as c:
        with pytest.raises(CommandError, match="individually"):
            c.set_armed(True, stay=True)
    assert sent(panel, 0x16) == []


def test_stay_refused_where_state_cannot_be_read(fake_panel):
    with client_for(fake_panel) as c:
        with pytest.raises(CommandError, match="stay"):
            c.set_armed(True, stay=True)
    assert sent(fake_panel, 0x16) == []


def test_partition_beyond_model_refused(make_panel):
    _, panel = make_panel()
    with client_for(panel) as c:
        with pytest.raises(CommandError, match="no partition 3"):
            c.set_armed(True, partition=3)


# -- PGM ----------------------------------------------------------------------

def test_pgm_on_off_is_state_checked(make_panel):
    state, panel = make_panel()
    with client_for(panel) as c:
        assert c.set_pgm(2, True) == {"PGM1": False, "PGM2": True, "PGM3": False}
        c.set_pgm(2, True)  # already on: nothing sent
        c.set_pgm(2, False)
    assert [r for r in panel.requests if r[:1] == b"\x19" and r[1] != 0x10] == [b"\x19\x80", b"\x19\x80"]


def test_pgm_state_not_changed_raises(make_panel):
    state, panel = make_panel()
    state.ignore_writes = True
    with client_for(panel) as c:
        with pytest.raises(CommandError, match="PGM1"):
            c.set_pgm(1, True)


def test_pgm_4_to_19_only_on_4010(make_panel):
    state, panel = make_panel(model=0x41)
    with client_for(panel) as c:
        c.toggle_pgm(7)
    assert state.pgm_extra == {7}
    _, other = make_panel()
    with client_for(other) as c:
        with pytest.raises(CommandError, match="PGM 7"):
            c.toggle_pgm(7)


# -- bypass / triggered / clock ------------------------------------------------------

def test_set_bypassed_full_set_and_verified(make_panel):
    state, panel = make_panel()
    state.bypassed = {1}
    with client_for(panel) as c:
        assert c.set_bypassed({2, 48}) == [2, 48]
    assert state.bypassed == {2, 48}


def test_set_bypassed_unverified_raises(make_panel):
    state, panel = make_panel()
    state.ignore_writes = True
    with client_for(panel) as c:
        with pytest.raises(CommandError, match="bypass"):
            c.set_bypassed({3})


def test_bypass_zone_out_of_range(make_panel):
    _, panel = make_panel()
    with client_for(panel) as c:
        with pytest.raises(ValueError):
            c.set_bypassed({49})


def test_clear_triggered(make_panel):
    state, panel = make_panel()
    with client_for(panel) as c:
        c.clear_triggered()
    assert state.triggered_cleared


def test_set_clock(make_panel):
    state, panel = make_panel()
    with client_for(panel) as c:
        c.set_clock(datetime(2026, 11, 24, 0, 2))
    assert state.clock == bytes([0x26, 0x11, 0x24, 0x00, 0x02, 0x00])


# -- EEPROM write -----------------------------------------------------------------

def test_write_eeprom_returns_previous_and_verifies(make_panel):
    state, panel = make_panel()
    with client_for(panel) as c:
        before = c.write_eeprom(677, b"\x20")
    assert before == b"\x00"  # unwritten fake EEPROM reads back 00
    assert state.eeprom[677] == 0x20


def test_write_eeprom_mismatch_raises(make_panel):
    state, panel = make_panel()
    state.ignore_writes = True
    with client_for(panel) as c:
        with pytest.raises(CommandError, match="read back"):
            c.write_eeprom(677, b"\x20")


def test_write_eeprom_protected_area_sends_nothing(make_panel):
    _, panel = make_panel()
    with client_for(panel) as c:
        with pytest.raises(ValueError, match="protected"):
            c.write_eeprom(1000, b"\x00")
    assert sent(panel, 0x13) == []


# -- model-specific reads --------------------------------------------------------------

def test_smart_extras(make_panel):
    _, panel = make_panel(model=0x34)
    with client_for(panel) as c:
        assert c.connections()["cellular_module"] == "4G"
        assert c.network_card()["ip"] == "192.168.1.50"
        assert c.cell_card()["carrier"] == "Vivo"
        assert c.wireless_sensors()[0]["zone"] == 25
        assert c.bus_devices() == {"keypads": [1], "receivers": [1]}


def test_4010_bus_search(make_panel):
    _, panel = make_panel(model=0x41)
    with client_for(panel) as c:
        assert c.search_bus() is True


def test_unsupported_command_refused_before_sending(make_panel):
    _, panel = make_panel()  # AMT 1016 NET: 0x30 hung a real one
    with client_for(panel, timeout=0.3) as c:
        for call in (c.connections, c.network_card, c.cell_card, c.wireless_sensors, c.bus_devices, c.search_bus):
            with pytest.raises(CommandError, match="not supported by AMT 1016 NET; not sent"):
                call()
    sent_cmds = {r[0] for r in panel.requests}
    assert not sent_cmds & {0x22, 0x23, 0x30, 0x31, 0x32, 0x36}


def test_bus_search_refused_on_smart(make_panel):
    _, panel = make_panel(model=0x34)
    with client_for(panel) as c:
        with pytest.raises(CommandError, match="not sent"):
            c.search_bus()
    assert sent(panel, 0x22) == []


# -- raw --------------------------------------------------------------------------------

def test_raw_request(make_panel):
    _, panel = make_panel()
    with client_for(panel) as c:
        frame = c.raw(bytes([0x17]))
    assert frame.command == 0x97


# -- discovery and E9 ---------------------------------------------------------------------

def test_discover_reads_mac_and_model():
    panel = FakePanel(discovery_handler, raw=True)
    try:
        info = discover("127.0.0.1", port=panel.port, timeout=1)
    finally:
        panel.close()
    assert info == {"host": "127.0.0.1", "mac": "02:00:00:00:00:01", "model": "AMT1016 NET"}


def test_discover_silent_host_returns_none():
    panel = FakePanel(lambda raw: None, raw=True)
    try:
        assert discover("127.0.0.1", port=panel.port, timeout=0.3) is None
    finally:
        panel.close()


def test_discover_closed_port_returns_none():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert discover("127.0.0.1", port=port, timeout=0.3) is None


def test_e9_request_ack_and_error():
    replies = iter([bytes.fromhex("02 e9 fe ea"), bytes.fromhex("02 e9 e1 f5")])
    panel = FakePanel(lambda raw: next(replies), raw=True)
    try:
        assert e9_request("127.0.0.1", "1234", bytes([0x5A]), port=panel.port, timeout=1).error is None
        assert e9_request("127.0.0.1", "1234", bytes([0x5A]), port=panel.port, timeout=1).error == "wrong password"
    finally:
        panel.close()
    assert panel.requests[0] == bytes.fromhex("08 E9 21 31 32 33 34 5A 21 40")


def test_e9_request_timeout():
    panel = FakePanel(lambda raw: None, raw=True)
    try:
        with pytest.raises(PanelTimeout):
            e9_request("127.0.0.1", "1234", bytes([0x5A]), port=panel.port, timeout=0.3)
    finally:
        panel.close()


def test_e9_request_corrupt_reply():
    panel = FakePanel(lambda raw: bytes.fromhex("02 e9 fe eb"), raw=True)
    try:
        with pytest.raises(FrameError):
            e9_request("127.0.0.1", "1234", bytes([0x5A]), port=panel.port, timeout=1)
    finally:
        panel.close()


# -- review fixes ---------------------------------------------------------------------------

def test_connection_reset_mid_request_is_amt_error():
    from intelbras_amt.client import AmtError

    def handler(data):
        return CLOSE if data[0] == 0x17 else PanelState()(data)

    panel = FakePanel(handler)
    try:
        with client_for(panel) as c:
            with pytest.raises(AmtError):
                c.status()
    finally:
        panel.close()


def test_e9_connection_closed_is_amt_error():
    from intelbras_amt.client import AmtError

    panel = FakePanel(lambda raw: CLOSE, raw=True)
    try:
        with pytest.raises(AmtError):
            e9_request("127.0.0.1", "1234", bytes([0x5A]), port=panel.port, timeout=1)
    finally:
        panel.close()
