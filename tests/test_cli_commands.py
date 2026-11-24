import json

import pytest

from intelbras_amt import cli

from conftest import FakePanel, PanelState, discovery_handler


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for key in ("AMT_HOST", "AMT_PORT", "AMT_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def panel_factory():
    panels = []

    def factory(**kwargs):
        state = PanelState(**kwargs)
        panel = FakePanel(state)
        panels.append(panel)
        return state, panel

    yield factory
    for panel in panels:
        panel.close()


def run(panel, *argv, fmt="json"):
    return cli.main(["--host", "127.0.0.1", "--port", str(panel.port), "--password", "123456", "--format", fmt, *argv])


BASE = ["--host", "127.0.0.1", "--password", "123456"]


@pytest.mark.parametrize(
    "argv",
    [
        ["arm"],
        ["disarm", "--partition", "C", "--stay"],
        ["silence"],
        ["pgm", "1", "on"],
        ["bypass", "--add", "3"],
        ["bypass", "--clear"],
        ["clear-triggered"],
        ["set-clock"],
        ["eeprom-write", "677", "00"],
        ["bus-search"],
        ["raw", "16 00"],
        ["raw", "13 02 a5 01 00"],
        ["e9", "41"],
    ],
)
def test_writes_need_yes(argv, capsys):
    assert cli.main(BASE + argv) == 2
    assert "--yes" in capsys.readouterr().err


@pytest.mark.parametrize("data", ["17", "12 02 a3 01", "19 10", "14", "1d"])
def test_raw_universal_reads_need_no_yes(panel_factory, data, capsys):
    _, panel = panel_factory()
    assert run(panel, "raw", data) == 0
    assert json.loads(capsys.readouterr().out)["answer"]


@pytest.mark.parametrize("data", ["27", "30", "31", "32", "34", "36", "23"])
def test_raw_model_specific_reads_need_yes(data, capsys):
    # 0x30 sent to an AMT 1016 NET hung its network interface.
    assert cli.main(BASE + ["raw", data]) == 2
    assert "--yes" in capsys.readouterr().err


def test_bypass_set_empty_without_yes_does_not_crash(capsys):
    assert cli.main(BASE + ["bypass", "--set", ""]) == 2
    assert "un-bypass every zone" in capsys.readouterr().err


def test_parse_zones():
    assert cli.parse_zones("1,3,5-8, 3") == [1, 3, 5, 6, 7, 8]
    with pytest.raises(ValueError):
        cli.parse_zones("8-5")


def test_bad_zone_list_rejected():
    with pytest.raises(SystemExit):
        cli.main(BASE + ["bypass", "--add", "x"])


def test_bypass_add_remove(panel_factory, capsys):
    state, panel = panel_factory()
    state.bypassed = {1}
    assert run(panel, "bypass", "--add", "3-4", "--yes") == 0
    assert state.bypassed == {1, 3, 4}
    assert run(panel, "bypass", "--remove", "1", "--yes") == 0
    assert state.bypassed == {3, 4}
    assert run(panel, "bypass", "--clear", "--yes") == 0
    assert state.bypassed == set()
    assert '"bypassed_zones": []' in capsys.readouterr().out


def test_pgm_on(panel_factory, capsys):
    state, panel = panel_factory()
    assert run(panel, "pgm", "1", "on", "--yes") == 0
    assert json.loads(capsys.readouterr().out)["PGM1"] is True


def test_pgm_above_3_needs_toggle(panel_factory, capsys):
    _, panel = panel_factory(model=0x41)
    assert run(panel, "pgm", "5", "on", "--yes") == 1
    assert "toggle" in capsys.readouterr().err
    assert run(panel, "pgm", "5", "toggle", "--yes") == 0


def test_set_clock_with_time(panel_factory, capsys):
    state, panel = panel_factory()
    assert run(panel, "set-clock", "--time", "2026-11-24 13:05", "--yes") == 0
    assert state.clock[:5] == bytes([0x26, 0x11, 0x24, 0x13, 0x05])


def test_bad_time_rejected():
    with pytest.raises(SystemExit):
        cli.main(BASE + ["set-clock", "--time", "tomorrow", "--yes"])


def test_eeprom_write(panel_factory, capsys):
    state, panel = panel_factory()
    assert run(panel, "eeprom-write", "677", "20", "--yes") == 0
    assert json.loads(capsys.readouterr().out) == {"address": 677, "before": "00", "after": "20"}


def test_eeprom_write_protected(panel_factory, capsys):
    _, panel = panel_factory()
    assert run(panel, "eeprom-write", "1000", "00", "--yes") == 1
    assert "protected" in capsys.readouterr().err


def test_smart_reads(panel_factory, capsys):
    _, panel = panel_factory(model=0x34)
    for command in ("connections", "network", "cell", "wireless", "bus-devices"):
        assert run(panel, command) == 0
    out = capsys.readouterr().out
    assert '"cellular_module": "4G"' in out and '"carrier": "Vivo"' in out


def test_unsupported_read_on_1016(panel_factory, capsys):
    _, panel = panel_factory()
    assert run(panel, "network") == 1
    assert "not supported" in capsys.readouterr().err


def test_stay_on_1016_is_refused(panel_factory, capsys):
    _, panel = panel_factory()
    assert run(panel, "arm", "--stay", "--yes") == 1
    assert "stay" in capsys.readouterr().err


def test_discover_single_host(capsys):
    panel = FakePanel(discovery_handler, raw=True)
    try:
        code = cli.main(["--port", str(panel.port), "--format", "json", "discover", "127.0.0.1"])
    finally:
        panel.close()
    assert code == 0
    assert json.loads(capsys.readouterr().out) == [{"host": "127.0.0.1", "mac": "02:00:00:00:00:01", "model": "AMT1016 NET"}]


def test_discover_needs_target(capsys):
    assert cli.main(["discover"]) == 1
    assert "network to scan" in capsys.readouterr().err


def test_discover_rejects_huge_network(capsys):
    assert cli.main(["discover", "10.0.0.0/16"]) == 1
    assert "too large" in capsys.readouterr().err


def test_e9_read_and_error_exit_codes(capsys):
    replies = iter([bytes.fromhex("02 e9 fe ea"), bytes.fromhex("02 e9 e1 f5")])
    panel = FakePanel(lambda raw: next(replies), raw=True)
    try:
        argv = ["--host", "127.0.0.1", "--port", str(panel.port), "--password", "1234", "--protocol", "v1"]
        assert cli.main(argv + ["e9", "5a"]) == 0
        assert cli.main(argv + ["e9", "5a"]) == 1
    finally:
        panel.close()
    out = capsys.readouterr().out
    assert "ACK" in out and "wrong password" in out


def test_e9_needs_explicit_v1(capsys):
    assert cli.main(BASE + ["e9", "5a"]) == 1
    assert "--protocol v1" in capsys.readouterr().err
