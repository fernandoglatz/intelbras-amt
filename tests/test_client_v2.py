"""v2 client (AMT 8000 family), family detection and cross-family refusal."""

import pytest

from intelbras_amt import protocol_v2 as p2
from intelbras_amt.client import AmtClient, AuthError, CommandError, WrongFamilyError
from intelbras_amt.client_v2 import AmtV2Client, open_panel
from intelbras_amt.protocol_v2 import V2CommandError

from conftest import FakePanel, FakeV2Panel, PanelState, V2State


@pytest.fixture
def v2():
    panels = []

    def factory(**kwargs):
        state = V2State(**kwargs)
        panel = FakeV2Panel(state)
        panels.append(panel)
        return state, panel

    yield factory
    for panel in panels:
        panel.close()


def v2_client(panel, password="123456"):
    return AmtV2Client("127.0.0.1", password, port=panel.port, timeout=1, connect_attempts=1)


def commands(panel):
    return [c for c, _ in panel.requests]


def test_login_status_disconnect(v2):
    _, panel = v2()
    with v2_client(panel) as c:
        st = c.status()
    assert st.model == "AMT 8000" and st.state == "disarmed"
    assert commands(panel) == ["refresh", p2.Cmd.AUTH, p2.Cmd.INFO, p2.Cmd.STATUS, p2.Cmd.DISCONNECT]


def test_wrong_password(v2):
    _, panel = v2()
    with pytest.raises(AuthError, match="wrong password"):
        v2_client(panel, "999999").open()


def test_v2_client_refuses_v1_panel_after_refresh_only():
    state = PanelState()
    panel = FakePanel(state)
    try:
        with pytest.raises(WrongFamilyError, match="ISECNet v1"):
            v2_client(panel).open()
    finally:
        panel.close()
    assert [r[0] for r in panel.requests] == [0x10]


def test_v1_client_refuses_v2_panel_after_refresh_only(v2):
    _, panel = v2()
    with pytest.raises(WrongFamilyError, match="ISECNet v2"):
        AmtClient("127.0.0.1", "123456", port=panel.port, timeout=1, connect_attempts=1).open()
    assert commands(panel) == ["refresh"]


def test_arm_whole_panel_then_noop(v2):
    state, panel = v2()
    with v2_client(panel) as c:
        st = c.set_armed(True)
        assert st.state == "armed"
        c.set_armed(True)  # already armed: nothing sent
    arms = [p for c, p in panel.requests if c == p2.Cmd.ARM_DISARM]
    assert arms == [bytes([0xFF, 0x01])]


def test_stay_and_disarm_partition(v2):
    state, panel = v2()
    with v2_client(panel) as c:
        st = c.set_armed(True, partition=2, stay=True)
        assert [(p.id, p.armed, p.stay) for p in st.partitions] == [(1, False, False), (2, False, True)]
        st = c.set_armed(False, partition=2)
        assert st.partitions[1].stay is False
    arms = [p for c, p in panel.requests if c == p2.Cmd.ARM_DISARM]
    assert arms == [bytes([0x02, 0x02]), bytes([0x02, 0x00])]


def test_arm_with_open_zones_reports_reason(v2):
    state, panel = v2()
    state.open_zones = True
    with v2_client(panel) as c:
        with pytest.raises(V2CommandError, match="open zones"):
            c.set_armed(True)


def test_arm_not_applied_raises(v2):
    state, panel = v2()
    state.ignore_writes = True
    with v2_client(panel) as c:
        with pytest.raises(CommandError, match="did not change"):
            c.set_armed(True)


def test_unknown_partition_refused_before_sending(v2):
    _, panel = v2()
    with v2_client(panel) as c:
        with pytest.raises(CommandError, match="partition 5"):
            c.set_armed(True, partition=5)
    assert p2.Cmd.ARM_DISARM not in commands(panel)


def test_bypass_and_unbypass(v2):
    state, panel = v2()
    with v2_client(panel) as c:
        assert c.set_bypass([3, 64], True) == [3, 64]
        assert c.set_bypass([3], False) == [64]
    assert state.bypassed == {64}


def test_bypass_not_applied_raises(v2):
    state, panel = v2()
    state.ignore_writes = True
    with v2_client(panel) as c:
        with pytest.raises(CommandError, match="bypass"):
            c.set_bypass([3], True)


def test_pgm_on_off_state_checked(v2):
    state, panel = v2()
    with v2_client(panel) as c:
        assert c.set_pgm(4, True)[4] is True
        c.set_pgm(4, True)  # already on
        assert c.set_pgm(4, False)[4] is False
    pgms = [p for c, p in panel.requests if c == p2.Cmd.PGM_ON_OFF]
    assert pgms == [bytes([3, 1]), bytes([3, 0])]


def test_siren_off_and_panic(v2):
    state, panel = v2()
    with v2_client(panel) as c:
        c.silence_alarm()
        c.panic("medical")
    assert state.siren_off and state.panic == 3


def test_raw_v2(v2):
    _, panel = v2()
    with v2_client(panel) as c:
        frame = c.raw(p2.Cmd.STATUS)
    assert frame.command == p2.Cmd.STATUS and len(frame.payload) == 143


def test_raw_unknown_command_reports_nack(v2):
    _, panel = v2()
    with v2_client(panel) as c:
        with pytest.raises(V2CommandError, match="invalid command"):
            c.raw(0x1234)


# -- open_panel --------------------------------------------------------------------------

def test_open_panel_auto_picks_v2(v2):
    _, panel = v2()
    with open_panel("127.0.0.1", "123456", port=panel.port, timeout=1, connect_attempts=1) as c:
        assert isinstance(c, AmtV2Client)
        assert c.status().model == "AMT 8000"


def test_open_panel_auto_picks_v1():
    panel = FakePanel(PanelState())
    try:
        with open_panel("127.0.0.1", "123456", port=panel.port, timeout=1, connect_attempts=1) as c:
            assert isinstance(c, AmtClient)
            assert c.status().model == "AMT 1016 NET"
    finally:
        panel.close()


def test_open_panel_wrong_explicit_family_stops_after_refresh(v2):
    _, panel = v2()
    with pytest.raises(WrongFamilyError, match="v2"):
        open_panel("127.0.0.1", "123456", port=panel.port, protocol="v1", timeout=1, connect_attempts=1)
    assert commands(panel) == ["refresh"]


def test_open_panel_families_filter(v2):
    _, panel = v2()
    with pytest.raises(WrongFamilyError, match="only for ISECNet v1"):
        open_panel("127.0.0.1", "123456", port=panel.port, families={"v1"}, timeout=1, connect_attempts=1)
    assert commands(panel) == ["refresh"]


def test_open_panel_rejects_bad_protocol_name():
    with pytest.raises(ValueError):
        open_panel("127.0.0.1", "123456", protocol="v3")


# -- ANM 24 NET ------------------------------------------------------------------------------

def test_anm_status_uses_basic_command_only(v2):
    _, panel = v2(model=0x24)
    with v2_client(panel) as c:
        st = c.status()
    assert st.model == "ANM 24 NET" and st.firmware == "6.1.0" and st.state == "disarmed"
    assert p2.Cmd.STATUS_BASIC in commands(panel)
    assert p2.Cmd.STATUS not in commands(panel)  # never sent to an ANM (as in AMT Remoto)


def test_anm_arm_stay_disarm(v2):
    state, panel = v2(model=0x24)
    with v2_client(panel) as c:
        assert c.set_armed(True).state == "armed"
        assert c.set_armed(True, stay=True).state == "stay"
        assert c.set_armed(False).state == "disarmed"
    arms = [p for cmd, p in panel.requests if cmd == p2.Cmd.ARM_DISARM]
    assert arms == [bytes([0xFF, 1]), bytes([0xFF, 2]), bytes([0xFF, 0])]


def test_anm_refuses_unsupported_commands_before_sending(v2):
    _, panel = v2(model=0x24)
    with v2_client(panel) as c:
        for call in (
            lambda: c.set_armed(True, partition=1),
            lambda: c.set_bypass([1], True),
            lambda: c.set_pgm(1, True),
            c.silence_alarm,
            lambda: c.panic("audible"),
        ):
            with pytest.raises(CommandError, match="ANM 24 NET"):
                call()
    assert not set(commands(panel)) & {p2.Cmd.ARM_DISARM, p2.Cmd.BYPASS, p2.Cmd.PGM_ON_OFF,
                                       p2.Cmd.TURN_OFF_SIREN, p2.Cmd.PANIC}


def test_unknown_v2_model_status_refused(v2):
    _, panel = v2(model=0x90)  # AMT 9000
    with v2_client(panel) as c:
        with pytest.raises(CommandError, match="AMT 9000"):
            c.status()
    assert p2.Cmd.STATUS not in commands(panel)


# -- review regressions ----------------------------------------------------------------------

@pytest.mark.parametrize("armed, op", [(False, 0), (True, 1)])
def test_whole_panel_from_partial_state_is_sent(v2, armed, op):
    # Regression: "partial" read as (not armed, not stay), so a whole-panel disarm was a no-op.
    state, panel = v2()
    state.partitions[1] = [True, False]
    with v2_client(panel) as c:
        st = c.set_armed(armed)
    assert st.state == ("armed" if armed else "disarmed")
    assert [p for cmd, p in panel.requests if cmd == p2.Cmd.ARM_DISARM] == [bytes([0xFF, op])]


class _TrackedSocket:
    closed = False

    def close(self):
        self.closed = True


@pytest.mark.parametrize("client_cls", [AmtClient, AmtV2Client])
def test_attach_with_invalid_password_closes_socket(client_cls):
    # Regression: the password was validated before the socket was owned, so it leaked.
    sock = _TrackedSocket()
    with pytest.raises(ValueError):
        client_cls("127.0.0.1", "12").attach(sock)
    assert sock.closed
