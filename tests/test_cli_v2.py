"""CLI with ISECNet v2 panels and cross-family refusal."""

import json

import pytest

from intelbras_amt import cli
from intelbras_amt import protocol_v2 as p2

from conftest import FakePanel, FakeV2Panel, PanelState, V2State


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for key in ("AMT_HOST", "AMT_PORT", "AMT_PASSWORD", "AMT_PROTOCOL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def v2panel():
    panels = []

    def factory(**kwargs):
        state = V2State(**kwargs)
        panel = FakeV2Panel(state)
        panels.append(panel)
        return state, panel

    yield factory
    for panel in panels:
        panel.close()


def run(panel, *argv, protocol=None):
    base = ["--host", "127.0.0.1", "--port", str(panel.port), "--password", "123456", "--format", "json"]
    if protocol:
        base += ["--protocol", protocol]
    return cli.main(base + list(argv))


def test_status_auto_detects_v2(v2panel, capsys):
    _, panel = v2panel()
    assert run(panel, "status") == 0
    out = json.loads(capsys.readouterr().out)
    assert out["model"] == "AMT 8000" and out["state"] == "disarmed"


def test_info(v2panel, capsys):
    _, panel = v2panel(model=0x24)
    assert run(panel, "info") == 0
    assert json.loads(capsys.readouterr().out)["model"] == "ANM 24 NET"


def test_v1_command_refused_on_v2_panel_after_refresh_only(v2panel, capsys):
    _, panel = v2panel()
    assert run(panel, "connections") == 1
    assert "only for ISECNet v1" in capsys.readouterr().err
    assert [c for c, _ in panel.requests] == ["refresh"]


def test_v2_command_refused_on_v1_panel_after_refresh_only(capsys):
    state = PanelState()
    panel = FakePanel(state)
    try:
        code = cli.main(["--host", "127.0.0.1", "--port", str(panel.port), "--password", "123456", "info"])
    finally:
        panel.close()
    assert code == 1
    assert "only for ISECNet v2" in capsys.readouterr().err
    assert [r[0] for r in panel.requests] == [0x10]


@pytest.mark.parametrize("argv,protocol", [(["panic", "audible", "--yes"], "v1"), (["set-clock", "--yes"], "v2")])
def test_explicit_protocol_mismatch_refused_before_connecting(argv, protocol, capsys):
    # No panel at all: the refusal must happen before any connection attempt.
    assert cli.main(["--host", "127.0.0.1", "--port", "1", "--password", "123456", "--protocol", protocol] + argv) == 1
    assert "nothing sent" in capsys.readouterr().err


def test_explicit_protocol_wrong_family(v2panel, capsys):
    _, panel = v2panel()
    assert run(panel, "status", protocol="v1") == 1
    assert "panel speaks ISECNet v2" in capsys.readouterr().err
    assert [c for c, _ in panel.requests] == ["refresh"]


def test_protocol_from_env(v2panel, monkeypatch, capsys):
    _, panel = v2panel()
    monkeypatch.setenv("AMT_PROTOCOL", "v1")
    assert run(panel, "status") == 1
    assert "ISECNet v2" in capsys.readouterr().err


def test_bad_protocol_env(monkeypatch, capsys):
    monkeypatch.setenv("AMT_PROTOCOL", "v9")
    assert cli.main(["--host", "127.0.0.1", "--password", "123456", "status"]) == 1
    assert "auto, v1 or v2" in capsys.readouterr().err


def test_arm_partition_and_stay(v2panel, capsys):
    state, panel = v2panel()
    assert run(panel, "arm", "--partition", "2", "--stay", "--yes") == 0
    assert state.partitions[2] == [False, True]
    assert run(panel, "disarm", "--partition", "2", "--yes") == 0
    assert state.partitions[2] == [False, False]


def test_arm_open_zones_reason(v2panel, capsys):
    state, panel = v2panel()
    state.open_zones = True
    assert run(panel, "arm", "--yes") == 1
    assert "open zones" in capsys.readouterr().err


def test_bypass_add_set_clear(v2panel, capsys):
    state, panel = v2panel()
    assert run(panel, "bypass", "--add", "3,5", "--yes") == 0
    assert state.bypassed == {3, 5}
    assert run(panel, "bypass", "--set", "5,7", "--yes") == 0
    assert state.bypassed == {5, 7}
    assert run(panel, "bypass", "--clear", "--yes") == 0
    assert state.bypassed == set()


def test_pgm_on_and_toggle_rejected(v2panel, capsys):
    state, panel = v2panel()
    assert run(panel, "pgm", "3", "on", "--yes") == 0
    assert state.pgm == {3}
    assert run(panel, "pgm", "3", "toggle", "--yes") == 1
    assert "on' or 'off'" in capsys.readouterr().err


def test_panic_and_silence(v2panel):
    state, panel = v2panel()
    assert run(panel, "panic", "fire", "--yes") == 0
    assert run(panel, "silence", "--yes") == 0
    assert state.panic == 2 and state.siren_off


def test_panic_needs_yes(capsys):
    assert cli.main(["--host", "127.0.0.1", "--password", "123456", "panic", "silent"]) == 2
    assert "silent panic" in capsys.readouterr().err


def test_raw2_read_without_yes_and_write_with_yes(v2panel, capsys):
    _, panel = v2panel()
    assert run(panel, "raw2", "0b4a") == 0
    assert json.loads(capsys.readouterr().out)["command"] == "0B4A"
    assert cli.main(["--host", "127.0.0.1", "--password", "123456", "raw2", "401e", "ff 01"]) == 2


def test_anm_bypass_refused(v2panel, capsys):
    _, panel = v2panel(model=0x24)
    assert run(panel, "bypass", "--add", "1", "--yes") == 1
    assert "not supported for ANM 24 NET; not sent" in capsys.readouterr().err
    assert p2.Cmd.BYPASS not in [c for c, _ in panel.requests]


def test_partition_argument_range():
    with pytest.raises(SystemExit):
        cli.main(["arm", "--partition", "17"])


def test_raw2_command_code_out_of_range_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--host", "127.0.0.1", "--password", "123456", "raw2", "1ffff"])
    assert exc.value.code == 2
    assert "0000-FFFF" in capsys.readouterr().err
