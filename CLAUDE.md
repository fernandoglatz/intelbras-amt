# intelbras-amt

Local client for Intelbras alarm panels over TCP 9009: ISECNet v1 (AMT 1016 NET, 2018 family, Smart, 4010)
and ISECNet v2 (AMT 8000 family, ANM 24 NET). Protocol references: `docs/PROTOCOL.md` (v1),
`docs/PROTOCOL-V2.md` (v2), `docs/CLOUD.md` (Intelbras cloud).

- `src/intelbras_amt/protocol.py`: 0xE7 framing, CRC table, command codes.
- `src/intelbras_amt/decode.py`: reply decoders (offsets = app raw index - 3).
- `src/intelbras_amt/client.py`: session (refresh, identify, hang up), reads, state-checked arm/disarm.
- `src/intelbras_amt/protocol_v2.py`, `decode_v2.py`, `client_v2.py`: v2 framing, INFO/status decoding,
  `AmtV2Client` and `open_panel()` (family detection from the refresh answer: 0x90 v1, 0x80 v2).
- `src/intelbras_amt/cli.py`: `intelbras-amt` CLI; write commands exit 2 without `--yes`; `--protocol auto|v1|v2`.

Rules:
- The real panel is on the LAN (`.env`, gitignored, holds the password; never print it).
- Arm/disarm/silence and every other write change a real alarm: confirm with the user before running them live.
- Never send a command the panel's model does not support (see the Models column in README / docs/PROTOCOL.md).
  On 2026-11-24 the Smart-only `0x30` sent to the AMT 1016 NET went unanswered and the panel then stopped
  answering TCP 9009 and ping. At the first unanswered command, stop all traffic; never retry in a loop.
- Never send one family's commands to the other (v1 E7 vs v2). Only the v1 refresh is sent before the family is known.
- No v2 panel has been tested: v2 code is built from the apps' code only. Say so when describing it.
- Never run `eeprom-write` / WRITE_EEPROM (0x13) live without the user's explicit OK, and never touch `http://<panel>/mpfsupload`.
- Always hang up (context manager); an unclosed session blocks the port for ~30 s.
- Tests: `python3 -m pytest`. Fixtures are live captures; keep the password and MAC out of them.
