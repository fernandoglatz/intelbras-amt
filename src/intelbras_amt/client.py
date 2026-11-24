"""TCP client for the panel's local port (9009), speaking the app's 0xE7 frames.

Also: unauthenticated discovery probes (``discover``) and one-shot E9 frames
(``e9_request``), which use their own short connections.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from . import decode
from .protocol import (
    DISCOVERY_MAC,
    DISCOVERY_MODEL,
    IDENTIFY_OK,
    MENU_SILENCE_ALARM,
    MENU_SIREN_STATUS,
    Answer,
    Cmd,
    E9Reply,
    Frame,
    FrameError,
    arm_mask,
    build_e9,
    build_frame,
    build_simple,
    bypass_data,
    clock_data,
    identify_data,
    parse_e9,
    parse_frame,
    parse_simple,
    pgm_data,
    read_eeprom_data,
    write_eeprom_data,
)

DEFAULT_PORT = 9009
MAC_ADDRESS = 1776
CONFIG_BYTE_1 = 675  # bit 0 = panel is partitioned
_PARTIAL = object()


class AmtError(RuntimeError):
    pass


class AuthError(AmtError):
    pass


class PanelTimeout(AmtError):
    pass


class CommandError(AmtError):
    pass


class WrongFamilyError(AmtError):
    """The panel speaks the other ISECNet family (v1 E7 vs v2 AMT 8000)."""


REFRESH_ANSWER_V1 = Answer.REFRESH  # 0x90
REFRESH_ANSWER_V2 = 0x80  # AMT 8000 family (Converters.TranslateAmt8000)
NOT_ISECNET = "not an AMT 2018-family or AMT 8000 panel"


def connect_socket(host: str, port: int, timeout: float, connect_timeout: float, attempts: int, retry_delay: float):
    last: OSError | None = None
    for attempt in range(attempts):
        try:
            sock = socket.create_connection((host, port), timeout=connect_timeout)
            sock.settimeout(timeout)
            return sock
        except OSError as exc:  # the panel needs a while to free a previous session
            last = exc
            if attempt + 1 < attempts:
                time.sleep(retry_delay)
    raise AmtError(f"cannot connect to {host}:{port}: {last}")


def probe_family(sock: socket.socket) -> str:
    """Send the v1 refresh and tell the family from the answer: "v1" (0x90) or "v2" (0x80).

    AMT Remoto sends exactly this refresh first on every local login, to both
    families; it is the only command sent before the family is known.
    """
    try:
        sock.sendall(build_frame(bytes([Cmd.REFRESH])))
        raw = _read_frame(sock)
    except socket.timeout as exc:
        raise PanelTimeout("no answer to refresh") from exc
    except OSError as exc:
        raise AmtError(f"connection lost during refresh: {exc}") from exc
    try:
        answer = parse_frame(raw).command
    except FrameError as exc:
        if len(raw) >= 4 and raw[1] == 0xE7:
            answer = raw[3]
        else:
            raise AmtError(f"unrecognised answer to refresh ({exc}); {NOT_ISECNET}") from exc
    if answer == REFRESH_ANSWER_V1:
        return "v1"
    if answer == REFRESH_ANSWER_V2:
        return "v2"
    raise AmtError(f"panel answered refresh with 0x{answer:02X}; {NOT_ISECNET}")


class AmtClient:
    """One authenticated session. The panel serves few sessions at a time, so
    always close it (or use it as a context manager) to send HANG_UP."""

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
        self.master = False
        self.model_code: int | None = None
        self._sock: socket.socket | None = None

    # -- session ---------------------------------------------------------

    def __enter__(self) -> "AmtClient":
        if self._sock is None:  # open_panel() hands over an already logged-in client
            self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def open(self) -> None:
        # Validate before touching the network.
        identify_data(self.password)
        sock = connect_socket(
            self.host, self.port, self.timeout, self.connect_timeout, self.connect_attempts, self.retry_delay
        )
        try:
            family = probe_family(sock)
            if family != "v1":
                raise WrongFamilyError(
                    "this panel speaks ISECNet v2 (AMT 8000 family); use the v2 client / --protocol v2"
                )
        except BaseException:
            sock.close()
            raise
        self.attach(sock)

    def attach(self, sock: socket.socket) -> None:
        """Log in on a socket whose refresh already identified a v1 panel."""
        self._sock = sock  # owned from here on, so any failure below closes it
        try:
            identify = identify_data(self.password)
            reply = self.request(identify)
            if reply.command not in IDENTIFY_OK:
                raise AuthError(f"password rejected (answer 0x{reply.command:02X})")
            self.master = reply.command == 0x4D
        except BaseException:
            self._drop()
            raise

    def close(self) -> None:
        if self._sock is None:
            return
        try:
            self.request(bytes([Cmd.HANG_UP]))
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

    def request(self, data: bytes) -> Frame:
        if self._sock is None:
            raise AmtError("not connected")
        try:
            self._sock.sendall(build_frame(data))
            return parse_frame(_read_frame(self._sock))
        except socket.timeout as exc:
            raise PanelTimeout(f"no answer to command 0x{data[0]:02X}") from exc
        except OSError as exc:  # reset / broken pipe while talking to the panel
            raise AmtError(f"connection lost during command 0x{data[0]:02X}: {exc}") from exc

    def raw(self, data: bytes) -> Frame:
        """Send any E7 data (command byte first) and return the parsed reply."""
        return self.request(bytes(data))

    def _query(self, data: bytes, answer: int, what: str) -> Frame:
        """Request for a model-specific command; a missing/odd answer means unsupported."""
        try:
            frame = self.request(data)
        except PanelTimeout as exc:
            raise CommandError(f"{what} not supported by this panel (no answer)") from exc
        if frame.command != answer:
            raise CommandError(f"{what} not supported by this panel (answer 0x{frame.command:02X})")
        return frame

    # -- reads -----------------------------------------------------------

    def _status_only(self) -> decode.Status:
        frame = self.request(bytes([Cmd.STATUS]))
        try:
            st = decode.decode_status(frame)
        except decode.NeedsSmartStatus:
            st = decode.decode_status(self.request(bytes([Cmd.STATUS_SMART])))
        self.model_code = st.model_code
        return st

    def model(self) -> decode.ModelInfo:
        if self.model_code is None:
            self.model_code = decode.status_model(self.request(bytes([Cmd.STATUS])))
        return decode.model_info(self.model_code)

    def status(self, full: bool = True) -> decode.Status:
        st = self._status_only()
        if not full:
            return st
        info = decode.model_info(st.model_code)
        if info.layout == "smart":
            st.problems = decode.decode_problems(self.request(bytes([Cmd.NEW_PROBLEMS])))
        else:
            st.bypassed_zones = self.bypassed_zones()
            st.problems = decode.decode_problems(self.request(bytes([Cmd.PROBLEMS])))
            st.partitioned = bool(self.read_eeprom(CONFIG_BYTE_1, 1)[0] & 0x01)
        siren = decode.decode_siren(self.request(bytes([Cmd.MENU_FUNCTIONS, MENU_SIREN_STATUS])))
        st.alarm_firing = siren.alarm_firing
        st.pgm = siren.pgm
        return st

    def problems(self) -> list[str]:
        cmd = Cmd.NEW_PROBLEMS if self.model().layout == "smart" else Cmd.PROBLEMS
        return decode.decode_problems(self.request(bytes([cmd])))

    def bypassed_zones(self) -> list[int]:
        info = self.model()
        if info.layout == "smart":
            return self._status_only().bypassed_zones
        return decode.decode_bypassed(self.request(bytes([Cmd.BYPASSED_ZONES])), zone_count=info.zones)

    def pgm_state(self) -> dict[str, bool]:
        return decode.decode_siren(self.request(bytes([Cmd.MENU_FUNCTIONS, MENU_SIREN_STATUS]))).pgm

    def read_eeprom(self, address: int, count: int) -> bytes:
        return decode.decode_eeprom(self.request(read_eeprom_data(address, count)))

    def mac(self) -> str:
        return decode.decode_mac(self.request(read_eeprom_data(MAC_ADDRESS, 6)))

    def _require(self, layouts: set[str], what: str) -> None:
        """Refuse a model-specific command before sending it to a model that lacks it.

        An AMT 1016 NET sent the Smart-only CONNECTIONS (0x30) stopped
        answering on the network, so these are never sent blindly.
        """
        info = self.model()
        if info.layout not in layouts:
            raise CommandError(f"{what} is not supported by {info.name}; not sent")

    def bus_devices(self) -> dict[str, list[int]]:
        self._require({"4010", "smart"}, "bus devices")
        return decode.decode_bus_devices(self._query(bytes([Cmd.BUS_DEVICES]), Answer.BUS_DEVICES, "bus devices"))

    def connections(self) -> dict:
        self._require({"smart"}, "connection status")
        return decode.decode_connections(self._query(bytes([Cmd.CONNECTIONS]), Answer.CONNECTIONS, "connection status"))

    def network_card(self) -> dict[str, str]:
        self._require({"smart"}, "network card info")
        return decode.decode_network_card(self._query(bytes([Cmd.NETWORK_CARD]), Answer.NETWORK_CARD, "network card info"))

    def cell_card(self) -> dict:
        self._require({"smart"}, "cellular card info")
        return decode.decode_cell_card(self._query(bytes([Cmd.CELL_CARD]), Answer.CELL_CARD, "cellular card info"))

    def wireless_sensors(self) -> list[dict]:
        self._require({"smart"}, "wireless sensor status")
        frame = self._query(bytes([Cmd.WIRELESS_SENSORS]), Answer.WIRELESS_SENSORS, "wireless sensor status")
        return decode.decode_wireless_sensors(frame)

    # -- writes (state-checked where the panel lets us read the state) -----

    def set_armed(self, armed: bool, partition: int | None = None, stay: bool = False) -> decode.Status:
        """Arm or disarm the whole panel (partition None) or partition 1-4, optionally stay.

        REMOTE_ARM is a toggle (the app sends the same packet both ways), so the
        current state is read first and the command is only sent when it would
        change something; the state is read again afterwards to confirm.
        """
        before = self._status_only()
        current = self._armed_state(before, partition, stay)
        if current is _PARTIAL:
            if stay:
                raise CommandError("only some partitions are stay-armed; arm/disarm partitions individually")
            # The whole-panel toggle is ambiguous here: toggle each partition that differs.
            for index, part in enumerate(before.partitions, start=1):
                if part.armed != armed:
                    decode.check_arm_answer(self.request(bytes([Cmd.REMOTE_ARM, arm_mask(index, False)])))
            after = self._status_only()
            if self._armed_state(after, None, False) != armed:
                raise CommandError(f"panel state did not change (armed mask 0x{after.armed_mask:02X})")
            return after
        if current == armed:
            return before
        decode.check_arm_answer(self.request(bytes([Cmd.REMOTE_ARM, arm_mask(partition, stay)])))
        after = self._status_only()
        if self._armed_state(after, partition, stay) != armed:
            raise CommandError(f"panel state did not change (armed mask 0x{after.armed_mask:02X})")
        return after

    @staticmethod
    def _armed_state(st: decode.Status, partition: int | None, stay: bool):
        if partition:
            if not 1 <= partition <= len(st.partitions):
                raise CommandError(f"{st.model} has no partition {partition}")
            part = st.partitions[partition - 1]
            value = part.stay_armed if stay else part.armed
        elif stay:
            stays = [p.stay_armed for p in st.partitions]
            if stays and None not in stays and any(stays) and not all(stays):
                return _PARTIAL
            value = st.stay_armed
        else:
            whole = 0x0F if len(st.partitions) == 4 else 0x03
            low = st.armed_mask & whole
            if low not in (0, whole):
                return _PARTIAL
            value = low == whole
        if value is None:
            raise CommandError(
                f"{st.model} does not report the stay state, so stay arming cannot be checked; "
                "it is available on Smart models and the AMT 4010 Smart (firmware 5.7+)"
            )
        return value

    def silence_alarm(self) -> None:
        reply = self.request(bytes([Cmd.MENU_FUNCTIONS, MENU_SILENCE_ALARM]))
        if reply.command != Answer.MENU_FUNCTIONS:
            raise CommandError(f"unexpected answer 0x{reply.command:02X}")

    def set_pgm(self, pgm: int, on: bool) -> dict[str, bool]:
        """Switch PGM 1-3 on or off. The command toggles, so the state is checked."""
        if pgm not in (1, 2, 3):
            raise CommandError("only PGM 1-3 report their state; use toggle_pgm for PGM 4-19")
        key = f"PGM{pgm}"
        if self.pgm_state()[key] == on:
            return self.pgm_state()
        state = decode.decode_siren(self.request(pgm_data(pgm))).pgm
        if state[key] != on:
            raise CommandError(f"{key} did not change")
        return state

    def toggle_pgm(self, pgm: int) -> None:
        """Toggle PGM 4-19 (AMT 4010 Smart). Their state cannot be read back."""
        data = pgm_data(pgm)
        if pgm >= 4 and self.model().layout != "4010":
            raise CommandError(f"PGM {pgm} exists only on the AMT 4010 Smart")
        if pgm <= 3:
            self.request(data)
            return
        decode.expect_ack(self.request(data), Answer.SET_PGM_4_TO_19)

    def set_bypassed(self, zones) -> list[int]:
        """Set the complete bypassed-zone set (zones not listed are un-bypassed)."""
        info = self.model()
        wanted = sorted(set(zones))
        packet = bypass_data(wanted, zone_count=info.zones)
        decode.expect_ack(self.request(packet), Answer.BYPASS)
        now = self.bypassed_zones()
        if now != wanted:
            raise CommandError(f"bypass not applied: panel reports {now or 'none'}")
        return now

    def clear_triggered(self) -> None:
        decode.expect_ack(self.request(bytes([Cmd.CLEAN_TRIGGERED_ZONES])), Answer.CLEAN_TRIGGERED_ZONES)

    def set_clock(self, when: datetime | None = None) -> datetime:
        when = (when or datetime.now()).replace(second=0, microsecond=0)
        decode.expect_ack(self.request(clock_data(when)), Answer.CLOCK_ADJUST)
        return when

    def write_eeprom(self, address: int, data: bytes) -> bytes:
        """Write configuration memory; returns the previous bytes. Verified by reading back."""
        packet = write_eeprom_data(address, data)  # validates before any traffic
        before = self.read_eeprom(address, len(data))
        decode.expect_write_ack(self.request(packet), address)
        after = self.read_eeprom(address, len(data))
        if after != bytes(data):
            raise CommandError(f"read back {after.hex(' ')} after writing {bytes(data).hex(' ')} at {address}")
        return before

    def search_bus(self) -> bool:
        """Ask the panel to scan its keypad/receiver bus (AMT 4010 Smart)."""
        self._require({"4010"}, "bus search")
        frame = self._query(bytes([Cmd.SEARCH_BUS_DEVICES]), Answer.SEARCH_BUS_DEVICES, "bus search")
        return decode.decode_search_bus(frame)


# -- connection helpers shared by discovery and E9 ------------------------------

def _read_frame(sock: socket.socket) -> bytes:
    """Read one ``[len] … `` frame (total length len + 2), for every frame family."""
    buf = b""
    while True:
        chunk = sock.recv(512)
        if not chunk:
            raise AmtError("connection closed by panel")
        buf += chunk
        total = buf[0] + 2
        if len(buf) >= total:
            return buf[:total]


def discover(host: str, port: int = DEFAULT_PORT, timeout: float = 2.0) -> dict | None:
    """Unauthenticated MAC + model probe (Guardian's AMTSearcher). None if no panel answers."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    with sock:
        sock.settimeout(timeout)
        try:
            sock.sendall(build_simple(DISCOVERY_MAC))
            cmd, mac = parse_simple(_read_frame(sock))
            if cmd != DISCOVERY_MAC or len(mac) < 6:
                return None
            sock.sendall(build_simple(DISCOVERY_MODEL))
            cmd, name = parse_simple(_read_frame(sock))
            model = name.decode("ascii", errors="replace").strip("\x00 ") if cmd == DISCOVERY_MODEL else None
        except (OSError, AmtError, FrameError):
            return None
    return {"host": host, "mac": ":".join(f"{b:02X}" for b in mac[:6]), "model": model}


def discover_network(network: str, port: int = DEFAULT_PORT, timeout: float = 1.0, workers: int = 64) -> list[dict]:
    """Probe every address of a network (at most 1024 hosts) in parallel."""
    hosts = [str(h) for h in ipaddress.ip_network(network, strict=False).hosts()]
    if len(hosts) > 1024:
        raise ValueError("network too large: scan at most 1024 addresses (e.g. a /22)")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        found = pool.map(lambda h: discover(h, port, timeout), hosts)
    return [f for f in found if f]


def e9_request(host: str, password: str, command: bytes, port: int = DEFAULT_PORT, timeout: float = 5.0) -> E9Reply:
    """Send one E9 ("ISECMobile") frame on its own connection and parse the reply.

    Panels on old firmware (e.g. AMT 1016 NET 2.6) only ever answer ``FE`` (ACK).
    """
    frame = build_e9(command, password)
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise AmtError(f"cannot connect to {host}:{port}: {exc}") from exc
    with sock:
        sock.settimeout(timeout)
        try:
            sock.sendall(frame)
            return parse_e9(_read_frame(sock))
        except socket.timeout as exc:
            raise PanelTimeout(f"no answer to E9 command 0x{command[0]:02X}") from exc
        except OSError as exc:
            raise AmtError(f"connection lost during E9 command 0x{command[0]:02X}: {exc}") from exc
