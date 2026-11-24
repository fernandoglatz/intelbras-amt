import socket

import pytest

from intelbras_amt.client import AmtClient, AmtError, AuthError, CommandError, PanelTimeout
from intelbras_amt.decode import OpenZonesError

from conftest import CLOSE, FakePanel, PanelState

PASSWORD = "123456"


def client_for(panel, password=PASSWORD, **kwargs):
    kwargs.setdefault("timeout", 2)
    return AmtClient("127.0.0.1", password, port=panel.port, **kwargs)


def test_login_status_and_hang_up(fake_panel):
    with client_for(fake_panel) as client:
        st = client.status()
    assert st.model == "AMT 1016 NET"
    assert st.partitioned is True
    assert st.alarm_firing is False
    assert st.problems == [] and st.bypassed_zones == []
    commands = [r[0] for r in fake_panel.requests]
    assert commands[:2] == [0x10, 0x11]
    assert fake_panel.requests[1] == bytes([0x11, 0x12, 0x34, 0x56, 0x34])
    assert commands[-1] == 0x15


def test_quick_status_sends_only_status(fake_panel):
    with client_for(fake_panel) as client:
        client.status(full=False)
    assert [r[0] for r in fake_panel.requests] == [0x10, 0x11, 0x17, 0x15]


def test_wrong_password_raises_and_closes(fake_panel):
    with pytest.raises(AuthError, match="password rejected"):
        client_for(fake_panel, password="999999").open()


def test_invalid_password_fails_before_connecting():
    client = AmtClient("127.0.0.1", "12", port=1, connect_attempts=1)
    with pytest.raises(ValueError):
        client.open()


def test_non_2018_panel_is_rejected():
    panel = FakePanel(lambda data: bytes.fromhex("00 00 00 00 00 03 f0 f0 01 00"))
    try:
        with pytest.raises(AmtError, match="not an AMT 2018-family or AMT 8000 panel"):
            client_for(panel).open()
    finally:
        panel.close()


def test_timeout_when_panel_is_silent():
    panel = FakePanel(lambda data: None)
    try:
        with pytest.raises(PanelTimeout):
            client_for(panel, timeout=0.3).open()
    finally:
        panel.close()


def test_connection_refused_after_retries():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    client = AmtClient("127.0.0.1", PASSWORD, port=port, connect_attempts=2, retry_delay=0, connect_timeout=0.5)
    with pytest.raises(AmtError, match="cannot connect"):
        client.open()


def test_panel_closing_connection_is_an_error():
    panel = FakePanel(lambda data: CLOSE)
    try:
        with pytest.raises(AmtError, match="closed by panel"):
            client_for(panel).open()
    finally:
        panel.close()


def arm_requests(panel):
    return [r for r in panel.requests if r[0] == 0x16]


def test_arm_whole_panel_toggles_once_and_verifies(fake_panel, panel_state):
    with client_for(fake_panel) as client:
        st = client.set_armed(True)
    assert st.armed is True
    assert arm_requests(fake_panel) == [bytes([0x16, 0x00])]


def test_arm_when_already_armed_sends_nothing():
    state = PanelState(armed_mask=0x03)
    panel = FakePanel(state)
    try:
        with client_for(panel) as client:
            assert client.set_armed(True).armed is True
        assert arm_requests(panel) == []
    finally:
        panel.close()


def test_disarm_partition_b():
    state = PanelState(armed_mask=0x03)
    panel = FakePanel(state)
    try:
        with client_for(panel) as client:
            st = client.set_armed(False, partition=2)
        assert [p.armed for p in st.partitions] == [True, False]
        assert arm_requests(panel) == [bytes([0x16, 0x02])]
    finally:
        panel.close()


@pytest.mark.parametrize(
    "start, armed, expected_packets",
    [
        (0x01, False, [bytes([0x16, 0x01])]),  # A armed: disarm only A
        (0x02, False, [bytes([0x16, 0x02])]),  # B armed: disarm only B
        (0x01, True, [bytes([0x16, 0x02])]),  # A armed: arm only B
    ],
)
def test_whole_panel_from_partial_state_goes_partition_by_partition(start, armed, expected_packets):
    # Regression: a live 1016 NET with only A armed refused "disarm" for the whole panel.
    # The whole-panel toggle is ambiguous there, so each partition that differs is toggled.
    panel = FakePanel(PanelState(armed_mask=start))
    try:
        with client_for(panel) as client:
            st = client.set_armed(armed)
        assert st.armed_mask & 0x03 == (0x03 if armed else 0x00)
        assert arm_requests(panel) == expected_packets
    finally:
        panel.close()


def test_whole_panel_from_partial_state_unverified_raises(panel_state, fake_panel):
    panel_state.armed_mask = 0x01
    panel_state.ignore_arm = True
    with client_for(fake_panel) as client:
        with pytest.raises(CommandError, match="did not change"):
            client.set_armed(False)


def test_arm_refused_with_open_zones(fake_panel, panel_state):
    panel_state.open_zones = True
    with client_for(fake_panel) as client:
        with pytest.raises(OpenZonesError):
            client.set_armed(True)


def test_arm_unverified_state_raises(fake_panel, panel_state):
    panel_state.ignore_arm = True
    with client_for(fake_panel) as client:
        with pytest.raises(CommandError, match="did not change"):
            client.set_armed(True)


def test_unknown_partition(fake_panel):
    with client_for(fake_panel) as client:
        with pytest.raises(CommandError, match="no partition 3"):
            client.set_armed(True, partition=3)


def test_mac_eeprom_and_silence(fake_panel):
    with client_for(fake_panel) as client:
        assert client.mac() == "02:00:00:00:00:01"
        assert client.read_eeprom(256, 4) == bytes([0, 1, 2, 3])
        client.silence_alarm()
    assert bytes([0x19, 0x40]) in fake_panel.requests


def test_request_without_connection():
    with pytest.raises(AmtError, match="not connected"):
        AmtClient("127.0.0.1", PASSWORD).request(bytes([0x17]))
