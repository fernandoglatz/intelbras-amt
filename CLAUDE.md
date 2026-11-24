# intelbras-amt

Local client for Intelbras AMT 2018-family alarm panels (AMT 1016 NET) over TCP 9009.
Protocol reference: `docs/PROTOCOL.md` (reverse-engineered from the AMT Remoto Mobile app).

- `src/intelbras_amt/protocol.py`: 0xE7 framing, CRC table, command codes.
- `src/intelbras_amt/decode.py`: reply decoders (offsets = app raw index - 3).
- `src/intelbras_amt/client.py`: session (refresh, identify, hang up), reads, state-checked arm/disarm.
- `src/intelbras_amt/cli.py`: `intelbras-amt` CLI; write commands exit 2 without `--yes`.

Rules:
- The real panel is on the LAN (`.env`, gitignored, holds the password; never print it).
- Arm/disarm/silence and every other write change a real alarm: confirm with the user before running them live.
- Never send a command the panel's model does not support (see the Models column in README / docs/PROTOCOL.md).
  On 2026-11-24 the Smart-only `0x30` sent to the AMT 1016 NET went unanswered and the panel then stopped
  answering TCP 9009 and ping. At the first unanswered command, stop all traffic; never retry in a loop.
- Never run `eeprom-write` / WRITE_EEPROM (0x13) live without the user's explicit OK, and never touch `http://<panel>/mpfsupload`.
- Always hang up (context manager); an unclosed session blocks the port for ~30 s.
- Tests: `python3 -m pytest`. Fixtures are live captures; keep the password and MAC out of them.
