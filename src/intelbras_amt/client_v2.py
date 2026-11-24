"""Client for ISECNet v2 panels (AMT 8000 family) on TCP 9009, and ``open_panel``.

Untested on real hardware: built from Guardian's and AMT Remoto's code. The
session follows AMT Remoto's local login: the v1 refresh (answered 0x80 by v2
panels), then AUTH, commands, DISCONNECT. v2 commands are explicit
(arm/disarm/stay, PGM on/off, bypass on/off), and the client still reads the
state before and after each write.
"""

from __future__ import annotations

import socket

from . import decode_v2
from .client import (
    DEFAULT_PORT,
    AmtClient,
    AmtError,
    AuthError,
    CommandError,
    PanelTimeout,
    WrongFamilyError,
    connect_socket,
    probe_family,
)
from .protocol import FrameError
from .protocol_v2 import (
    SIREN_OFF_PAYLOAD,
    ArmOp,
    Cmd,
    FrameV2,
    arm_payload,
    auth_payload,
    build_frame,
    bypass_payload,
    frame_length,
    panic_payload,
    parse_frame,
    pgm_payload,
)

FAMILIES = ("v1", "v2")


class AmtV2Client:
    """One authenticated v2 session. Use as a context manager so DISCONNECT is sent."""

    def __init__(
        self,
        host: str,
        password: str,
        port: int = DEFAULT_PORT,
        timeout: float = 5.0,
        connect_timeout: float = 15.0,
        connect_attempts: int = 4,
        retry_delay: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.connect_attempts = connect_attempts
        self.retry_delay = retry_delay
        self.model_code: int | None = None
        self._info: decode_v2.InfoV2 | None = None
        self._sock: socket.socket | None = None

    def __enter__(self) -> "AmtV2Client":
        if self._sock is None:
            self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def open(self) -> None:
        auth_payload(self.password)  # validate before touching the network
        sock = connect_socket(
            self.host, self.port, self.timeout, self.connect_timeout, self.connect_attempts, self.retry_delay
        )
        try:
            if probe_family(sock) != "v2":
                raise WrongFamilyError("this panel speaks ISECNet v1 (AMT 2018 family); use the v1 client / --protocol v1")
        except BaseException:
            sock.close()
            raise
        self.attach(sock)

    def attach(self, sock: socket.socket) -> None:
        """Log in on a socket whose refresh already identified a v2 panel."""
        self._sock = sock  # owned from here on, so any failure below closes it
        try:
            payload = auth_payload(self.password)
            frame = self.request(Cmd.AUTH, payload, check=False)
            ok, text = decode_v2.auth_result(frame)
            if not ok:
                raise AuthError(f"login refused: {text}")
            if len(frame.payload) > 1:
                self.model_code = frame.payload[1]
        except BaseException:
            self._drop()
            raise

    def close(self) -> None:
        if self._sock is None:
            return
        try:
            self.request(Cmd.DISCONNECT, check=False)
        except (AmtError, FrameError, OSError):
            pass
        finally:
            self._drop()

    def _drop(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    # -- transport -------------------------------------------------------

    def request(self, command: int, payload: bytes = b"", check: bool = True) -> FrameV2:
        if self._sock is None:
            raise AmtError("not connected")
        try:
            self._sock.sendall(build_frame(command, payload))
            frame = parse_frame(self._read_frame())
        except socket.timeout as exc:
            raise PanelTimeout(f"no answer to v2 command 0x{int(command):04X}") from exc
        except OSError as exc:
            raise AmtError(f"connection lost during v2 command 0x{int(command):04X}: {exc}") from exc
        return decode_v2.check_reply(frame) if check else frame

    def _read_frame(self) -> bytes:
        assert self._sock is not None
        buf = b""
        while True:
            total = frame_length(buf)
            if total is not None and len(buf) >= total:
                return buf[:total]
            chunk = self._sock.recv(512)
            if not chunk:
                raise AmtError("connection closed by panel")
            buf += chunk

    def raw(self, command: int, payload: bytes = b"") -> FrameV2:
        return self.request(command, payload)

    # -- reads -----------------------------------------------------------

    def info(self) -> decode_v2.InfoV2:
        """Model and firmware (INFO), asked first as AMT Remoto does; cached."""
        if self._info is None:
            self._info = decode_v2.decode_info(self.request(Cmd.INFO))
            self.model_code = self._info.model_code
        return self._info

    def _require(self, kinds: set[str], what: str) -> decode_v2.InfoV2:
        info = self.info()
        if info.kind not in kinds:
            raise CommandError(f"{what} is not supported for {info.model}; not sent")
        return info

    def status(self) -> decode_v2.StatusV2:
        """Full status (AMT 8000 family) or basic status (ANM 24 NET), chosen by model."""
        info = self.info()
        if info.kind == "anm":
            return decode_v2.decode_status_anm(self.request(Cmd.STATUS_BASIC), info)
        if info.kind == "8000":
            return decode_v2.decode_status(self.request(Cmd.STATUS))
        reason = decode_v2.model_v2(info.model_code).reason
        raise CommandError(f"status of {info.model} is not supported ({reason}); not sent")

    # -- writes (explicit commands, still state-checked) ----------------------

    @staticmethod
    def _state(st: decode_v2.StatusV2, partition: int | None) -> tuple[bool | None, bool | None]:
        """(armed, stay) for the whole panel or one partition; (None, None) when partially armed."""
        if partition is None:
            if st.state == "partial":  # never equal to a wanted state, so the command is sent
                return None, None
            return st.state == "armed", st.state == "stay"
        for part in st.partitions:
            if part.id == partition:
                return part.armed, part.stay
        enabled = ", ".join(str(p.id) for p in st.partitions) or "none"
        raise CommandError(f"{st.model} has no enabled partition {partition} (enabled: {enabled})")

    def set_armed(self, armed: bool, partition: int | None = None, stay: bool = False) -> decode_v2.StatusV2:
        info = self._require({"8000", "anm"}, "arming")
        if info.kind == "anm" and partition is not None:
            raise CommandError(f"{info.model} has no partitions; arm or disarm the whole panel")
        want = (armed and not stay, armed and stay)
        before = self.status()
        if self._state(before, partition) == want:
            return before
        op = ArmOp.DISARM if not armed else (ArmOp.STAY if stay else ArmOp.ARM)
        self.request(Cmd.ARM_DISARM, arm_payload(partition, op))
        after = self.status()
        if self._state(after, partition) != want:
            raise CommandError(f"panel state did not change (now {after.state})")
        return after

    def silence_alarm(self) -> None:
        self._require({"8000"}, "siren off")
        self.request(Cmd.TURN_OFF_SIREN, SIREN_OFF_PAYLOAD)

    def panic(self, kind: str) -> None:
        """Trigger a panic: silent, audible, fire or medical."""
        payload = panic_payload(kind)
        self._require({"8000"}, "panic")
        self.request(Cmd.PANIC, payload)

    def set_bypass(self, zones, bypass: bool) -> list[int]:
        zones = sorted(set(zones))
        payload = bypass_payload(zones, bypass)  # validates before sending
        self._require({"8000"}, "bypass")
        self.request(Cmd.BYPASS, payload)
        now = self.status().bypassed_zones
        if any((z in now) != bypass for z in zones):
            raise CommandError(f"bypass not applied: panel reports {now or 'none'}")
        return now

    def set_pgm(self, pgm: int, on: bool) -> dict[int, bool]:
        payload = pgm_payload(pgm, on)
        self._require({"8000"}, "PGM control")
        state = self.status().pgm
        if state.get(pgm) == on:
            return state
        self.request(Cmd.PGM_ON_OFF, payload)
        state = self.status().pgm
        if state.get(pgm) != on:
            raise CommandError(f"PGM {pgm} did not change")
        return state


def open_panel(
    host: str,
    password: str,
    port: int = DEFAULT_PORT,
    protocol: str = "auto",
    families: set[str] | None = None,
    timeout: float = 5.0,
    connect_timeout: float = 15.0,
    connect_attempts: int = 4,
    retry_delay: float = 10.0,
):
    """Connect once, detect the family from the refresh answer and log in.

    ``protocol`` "auto", "v1" or "v2"; ``families`` limits which families the
    caller's command supports. A mismatch stops right after the refresh, so a
    panel never receives the other family's commands.
    """
    if protocol not in ("auto", *FAMILIES):
        raise ValueError("protocol must be auto, v1 or v2")
    sock = connect_socket(host, port, timeout, connect_timeout, connect_attempts, retry_delay)
    try:
        family = probe_family(sock)
        if protocol != "auto" and family != protocol:
            raise WrongFamilyError(f"panel speaks ISECNet {family}, but --protocol {protocol} was given")
        if families is not None and family not in families:
            only = " / ".join(f"ISECNet {f}" for f in sorted(families))
            raise WrongFamilyError(f"this command is only for {only}; the panel speaks ISECNet {family}")
    except BaseException:
        sock.close()
        raise
    client = (AmtClient if family == "v1" else AmtV2Client)(
        host, password, port=port, timeout=timeout, connect_timeout=connect_timeout,
        connect_attempts=connect_attempts, retry_delay=retry_delay,
    )
    client.attach(sock)
    return client
