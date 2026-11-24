"""Connection settings from flags, environment and an optional ``.env`` file."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .client import DEFAULT_PORT


class ConfigError(ValueError):
    pass


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


@dataclass
class Settings:
    host: str | None
    port: int
    password: str | None
    protocol: str = "auto"


def load_settings(
    host: str | None = None,
    port: int | None = None,
    password: str | None = None,
    env_file: Path | None = None,
    environ: dict[str, str] | None = None,
    require_host: bool = True,
    require_password: bool = True,
    protocol: str | None = None,
) -> Settings:
    """Flags win over environment variables, which win over the ``.env`` file."""
    env = dict(read_env_file(env_file or Path.cwd() / ".env"))
    env.update({k: v for k, v in (os.environ if environ is None else environ).items() if k.startswith("AMT_")})
    host = host or env.get("AMT_HOST")
    password = password or env.get("AMT_PASSWORD")
    if not host and require_host:
        raise ConfigError("panel address missing: pass --host or set AMT_HOST")
    if not password and require_password:
        raise ConfigError("remote-access password missing: set AMT_PASSWORD (or pass --password)")
    if port is None:
        try:
            port = int(env.get("AMT_PORT", DEFAULT_PORT))
        except ValueError as exc:
            raise ConfigError("AMT_PORT must be a number") from exc
    protocol = (protocol or env.get("AMT_PROTOCOL") or "auto").lower()
    if protocol not in ("auto", "v1", "v2"):
        raise ConfigError("AMT_PROTOCOL / --protocol must be auto, v1 or v2")
    return Settings(host=host, port=port, password=password, protocol=protocol)
