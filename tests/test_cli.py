import json

import pytest

from intelbras_amt import cli
from intelbras_amt.config import ConfigError, load_settings


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for key in ("AMT_HOST", "AMT_PORT", "AMT_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)


def args_for(fake_panel, *extra):
    return ["--host", "127.0.0.1", "--port", str(fake_panel.port), "--password", "123456", *extra]


def test_status_json(fake_panel, capsys):
    assert cli.main(args_for(fake_panel, "--format", "json", "status")) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["model"] == "AMT 1016 NET"
    assert out["partitioned"] is True


def test_status_text(fake_panel, capsys):
    assert cli.main(args_for(fake_panel, "status")) == 0
    out = capsys.readouterr().out
    assert "AMT 1016 NET (firmware 2.6)" in out
    assert "Problems:   none" in out


@pytest.mark.parametrize("command", [["arm"], ["disarm", "--partition", "B"], ["silence"]])
def test_writes_need_yes(command, capsys):
    assert cli.main(["--host", "127.0.0.1", "--password", "123456", *command]) == 2
    assert "--yes" in capsys.readouterr().err


def test_arm_with_yes(fake_panel, capsys):
    assert cli.main(args_for(fake_panel, "arm", "--yes")) == 0
    assert "Armed:      yes" in capsys.readouterr().out


def test_invalid_partition_is_rejected():
    with pytest.raises(SystemExit):
        cli.main(["arm", "--partition", "E"])


def test_missing_password_is_reported(capsys):
    assert cli.main(["--host", "127.0.0.1", "status"]) == 1
    assert "AMT_PASSWORD" in capsys.readouterr().err


def test_auth_failure_exit_code(fake_panel, capsys):
    argv = ["--host", "127.0.0.1", "--port", str(fake_panel.port), "--password", "999999", "status"]
    assert cli.main(argv) == 1
    assert "password rejected" in capsys.readouterr().err


def test_settings_precedence(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("# comment\nAMT_HOST=10.0.0.1\nAMT_PASSWORD='111111'\nAMT_PORT=9000\n")
    s = load_settings(env_file=env_file, environ={})
    assert (s.host, s.port, s.password) == ("10.0.0.1", 9000, "111111")
    s = load_settings(env_file=env_file, environ={"AMT_HOST": "10.0.0.2"})
    assert s.host == "10.0.0.2"
    s = load_settings(host="10.0.0.3", port=1, password="222222", env_file=env_file, environ={})
    assert (s.host, s.port, s.password) == ("10.0.0.3", 1, "222222")


def test_settings_errors(tmp_path):
    missing = tmp_path / "none.env"
    with pytest.raises(ConfigError, match="AMT_HOST"):
        load_settings(env_file=missing, environ={})
    with pytest.raises(ConfigError, match="AMT_PORT"):
        load_settings(env_file=missing, environ={"AMT_HOST": "h", "AMT_PASSWORD": "123456", "AMT_PORT": "x"})
