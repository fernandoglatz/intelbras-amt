from __future__ import annotations

import socket
import threading

import pytest

from intelbras_amt.protocol import build_frame, checksum, parse_frame

# Replies captured from a live AMT 1016 NET (firmware 2.6) on 2026-11-24.
LIVE = {
    "refresh": bytes.fromhex("05 e7 01 90 85 63 6a"),
    "identify": bytes.fromhex("05 e7 01 50 87 e3 28"),
    "status": bytes.fromhex(
        "1e e7 1a 97 61 26 03 00 00 00 00 00 00 00 00 00 00 00 00 08 03 d0 03 70 00 02 18 0b 1a ab e0 27"
    ),
    "problems": bytes.fromhex("14 e7 10 94 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1a 32 a0"),
    "siren": bytes.fromhex("06 e7 02 99 00 d6 21 72"),
    "bypassed": bytes.fromhex("0b e7 07 9d 00 00 00 00 00 00 64 c1 2c"),
    "config675": bytes.fromhex("06 e7 02 92 f9 6e 34 2d"),
    "hangup": bytes.fromhex("06 e7 02 95 48 ff 91 af"),
}
# Unauthenticated discovery reply (not an E7 frame), also live.
LIVE_MODEL_REPLY = bytes.fromhex("0c c2 41 4d 54 31 30 31 36 20 4e 45 54 10")

DUMMY_MAC = bytes.fromhex("020000000001")
LIVE_TAIL = parse_frame(LIVE["status"]).data[16:]  # unknown byte, voltages, clock


def status_data(armed_mask: int = 0x00, zones: bytes = bytes(12), model: int = 0x61) -> bytes:
    """STATUS answer data with the live voltages and clock."""
    return bytes([0x97, model, 0x26, armed_mask]) + zones + LIVE_TAIL


def _bitmap(zones, size: int) -> bytes:
    out = bytearray(size)
    for zone in zones:
        out[(zone - 1) // 8] |= 1 << ((zone - 1) % 8)
    return bytes(out)


CLOSE = object()


class FakePanel:
    """Minimal panel on 127.0.0.1.

    By default each request is parsed as an E7 frame and ``handler(data)``
    returns the reply frame. With ``raw=True`` the handler gets the raw request
    bytes instead (discovery and E9 frames). The handler returns None to stay
    silent or ``CLOSE`` to drop the connection. Accepts several connections
    one after another.
    """

    def __init__(self, handler, raw: bool = False):
        self.handler = handler
        self.raw = raw
        self.requests: list[bytes] = []
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(4)
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                if self._session(conn) is CLOSE:
                    continue

    def _session(self, conn):
        buf = b""
        while True:
            try:
                chunk = conn.recv(512)
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
            while buf and len(buf) >= buf[0] + 2:
                raw, buf = buf[: buf[0] + 2], buf[buf[0] + 2 :]
                data = raw if self.raw else parse_frame(raw).data
                self.requests.append(data)
                reply = self.handler(data)
                if reply is CLOSE:
                    return CLOSE
                if reply is not None:
                    conn.sendall(reply)

    def close(self) -> None:
        self.server.close()


class PanelState:
    """Stateful handler emulating the E7 command set.

    ``model`` 0x61 (AMT 1016 NET, default), 0x34 (AMT 2018 E Smart) or 0x41
    (AMT 4010 Smart, firmware 5.7). REMOTE_ARM and the PGM commands toggle,
    as on the real panels.
    """

    def __init__(self, armed_mask: int = 0x00, password: bytes = bytes([0x12, 0x34, 0x56]), model: int = 0x61):
        self.armed_mask = armed_mask
        self.stay_mask = 0x00
        self.password = password
        self.model = model
        self.open_zones = False
        self.ignore_arm = False
        self.pgm_flags = 0x00
        self.pgm_extra: set[int] = set()
        self.bypassed: set[int] = set()
        self.triggered_cleared = False
        self.clock: bytes | None = None
        self.eeprom: dict[int, int] = {675: 0xF9}
        self.eeprom.update({1776 + i: b for i, b in enumerate(DUMMY_MAC)})
        self.ignore_writes = False

    @property
    def smart(self) -> bool:
        return self.model in (0x34, 0x36)

    @property
    def is_4010(self) -> bool:
        return self.model == 0x41

    @property
    def zone_bytes(self) -> int:
        return 8 if self.is_4010 else 6

    def _status(self) -> bytes:
        if self.is_4010:
            byte = (self.stay_mask << 4 | self.armed_mask) & 0xFF
            return bytes([0x97, 0x41, 0x57, byte]) + bytes(16) + LIVE_TAIL
        return status_data(self.armed_mask, model=self.model)

    def _status_smart(self) -> bytes:
        head = bytes([0xA7, self.model, 0x18, self.armed_mask]) + bytes(12) + LIVE_TAIL
        ext = bytearray(64)
        ext[1:7] = _bitmap(self.bypassed, 6)
        ext[61], ext[62], ext[63] = self.stay_mask, 1, 0x18
        return head + bytes(ext)

    def _arm(self, mask: int) -> None:
        whole = 0x0F if self.is_4010 else 0x03
        if mask & 0xF0:
            self.stay_mask ^= (mask >> 4) & whole if mask != 0xF0 else whole
        else:
            self.armed_mask ^= mask or whole

    def __call__(self, data: bytes) -> bytes | None:
        cmd = data[0]
        if cmd == 0x10:
            return LIVE["refresh"]
        if cmd == 0x11:
            ok = data[1:-1] == self.password
            return build_frame(bytes([0x50 if ok else 0x45]))
        if cmd == 0x17:
            return build_frame(self._status())
        if cmd == 0x27 and self.smart:
            return build_frame(self._status_smart())
        if cmd == 0x16:
            if self.open_zones:
                return build_frame(bytes([0x96, 0x80]))
            if not self.ignore_arm:
                self._arm(data[1])
            return build_frame(bytes([0x96, self.armed_mask]))
        if cmd == 0x1D:
            return build_frame(bytes([0x9D]) + _bitmap(self.bypassed, self.zone_bytes))
        if cmd == 0x1B:
            if not self.ignore_writes:
                self.bypassed = {
                    i + 1 for i in range(self.zone_bytes * 8) if data[1 + i // 8] & (1 << (i % 8))
                }
            return build_frame(bytes([0x9B]))
        if cmd == 0x1C:
            self.triggered_cleared = True
            return build_frame(bytes([0x9C]))
        if cmd == 0x14:
            return LIVE["problems"]
        if cmd == 0x34 and self.smart:
            return build_frame(bytes([0xB4]) + bytes(27))
        if cmd == 0x19:
            if data[1] == 0x10:
                return build_frame(bytes([0x99, self.pgm_flags]))
            toggles = {0x60: 0x40, 0x80: 0x20, 0xC0: 0x10}
            if data[1] in toggles and not self.ignore_writes:
                self.pgm_flags ^= toggles[data[1]]
            return build_frame(bytes([0x99, self.pgm_flags]))
        if cmd == 0x1E and self.is_4010:
            self.pgm_extra ^= {data[1]}
            return build_frame(bytes([0x9E]))
        if cmd == 0x18:
            self.clock = bytes(data[1:])
            return build_frame(bytes([0x98]))
        if cmd == 0x12:
            address, count = data[1] << 8 | data[2], data[3]
            return build_frame(bytes([0x92]) + bytes(self.eeprom.get(address + i, i) for i in range(count)))
        if cmd == 0x13:
            address = data[1] << 8 | data[2]
            if not self.ignore_writes:
                for i, b in enumerate(data[4 : 4 + data[3]]):
                    self.eeprom[address + i] = b
            return build_frame(bytes([0x93, data[1], data[2]]))
        if cmd == 0x22 and self.is_4010:
            return build_frame(bytes([0xA2, 0x00]))
        if cmd == 0x23 and (self.is_4010 or self.smart):
            return build_frame(bytes([0xA3, 0x11]))
        if cmd == 0x30 and self.smart:
            return build_frame(bytes([0xB0, 0x02, 0x05]))
        if cmd == 0x31 and self.smart:
            return build_frame(bytes([0xB1, 192, 168, 1, 50]) + bytes(16) + DUMMY_MAC)
        if cmd == 0x32 and self.smart:
            return build_frame(bytes([0xB2, 0x03, 20, 1, 3]) + b"8955" + bytes(16) + b"35" + bytes(13))
        if cmd == 0x36 and self.smart:
            sensors = bytearray([0xB6]) + bytes(47)
            sensors[1], sensors[4], sensors[24] = 0x01, 0x01, 7
            return build_frame(bytes(sensors))
        if cmd == 0x15:
            return LIVE["hangup"]
        return None


def discovery_handler(raw: bytes) -> bytes | None:
    """Unauthenticated discovery probes, as answered by the live panel."""
    if raw == bytes.fromhex("01 c4 3a"):
        body = bytes([0x07, 0xC4]) + DUMMY_MAC
        return body + bytes([checksum(body)])
    if raw == bytes.fromhex("01 c2 3c"):
        return LIVE_MODEL_REPLY
    return None


@pytest.fixture
def panel_state():
    return PanelState()


@pytest.fixture
def fake_panel(panel_state):
    panel = FakePanel(panel_state)
    yield panel
    panel.close()
