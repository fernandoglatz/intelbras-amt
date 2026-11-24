# intelbras-amt

Local, cloud-free control of **Intelbras AMT 2018-family alarm panels**
(AMT 1016 NET, AMT 2018 E/EG, AMT 2118 EG, AMT 2016/2018 E3G) from Python or
the command line.

It talks straight to the panel over your LAN (TCP 9009), using the same `0xE7`
protocol as Intelbras' **AMT Remoto Mobile** app. No Intelbras account, no
cloud relay and no extra hardware. Pure Python 3.10+, no runtime dependencies.

```console
$ intelbras-amt status
Model:      AMT 1016 NET (firmware 2.6)
Armed:      yes (mask 0x03)
  Partition A: armed
  Partition B: armed
Partitioned: yes
Alarm firing: no
Open zones: none
Triggered:  none
Bypassed:   none
AC supply:  14.50 V
Battery:    13.10 V
Clock:      2026-11-24 00:08
PGM:        PGM1=off, PGM2=off, PGM3=off
Problems:   none
```

> **Unofficial project.** Not affiliated with, endorsed by or supported by
> Intelbras. "Intelbras", "AMT" and model names are trademarks of their owner.
> An alarm is a safety device: read [Safety](#safety) before using the write
> commands, and use this at your own risk.

## Contents

- [Why](#why)
- [Supported panels](#supported-panels)
- [Features](#features)
- [Panel requirements](#panel-requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Command line](#command-line)
- [Python API](#python-api)
- [Safety](#safety)
- [Troubleshooting](#troubleshooting)
- [How it works](#how-it-works)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Why

Intelbras' current apps (AMT Mobile V3, Guardian) reach 2018-family panels only
through Intelbras' cloud relay. Older firmware does not support them at all,
and, according to the apps' code, the relay has no TLS, so the panel password
travels in plain text (details in [docs/CLOUD.md](docs/CLOUD.md)). AMT Remoto Mobile does talk to the panel
directly, but it is a closed app.

This project documents that local protocol and wraps it in a small library and
CLI, so you can read the panel from scripts, monitoring or home automation
without depending on the cloud.

## Supported panels

Every Intelbras model found in the three official apps' code, with what this
client does with it today. The **code** is the model byte the panel reports
(status reply byte 1 on this protocol; Guardian uses the same values).

### ISECNet v1 panels (the family this client speaks)

| Model | Code | Zones / partitions / PGMs | Status layout | Discovery name | Min. firmware for Guardian (main / Ethernet) | This client |
|-------|------|---------------------------|---------------|----------------|----------------------------------------------|-------------|
| **AMT 1016 NET** | `0x61` (97) | 48 / 2 / 2 | `0x17`, 2018 layout | `AMT1016 NET` | 4.1 / 3.0 | **Supported, tested live** (fw 2.6) |
| AMT 2018 E/EG | `0x1E` (30) | 48 / 2 / 2 | `0x17`, 2018 layout | `AMT2018E/EG` | 7.7 / 4.0 | Supported, untested |
| AMT 2118 EG | `0x2E` (46) | 48 / 2 / 2 | `0x17`, 2018 layout | `AMT2118E/EG` | any | Supported, untested |
| AMT 2016 E3G | `0x31` (49) | 48 / 2 / 2 | `0x17`, 2018 layout | `AMT2016 E3G` | any | Supported, untested |
| AMT 2018 E3G | `0x32` (50) | 48 / 2 / 2 | `0x17`, 2018 layout | `AMT2018 E3G` | any | Supported, untested |
| AMT 2018 E Smart | `0x34` (52) | 48 / 2 / 2 | `0x27`, Smart layout (adds stay, wireless sensors) | `AMT2018E SMART` | 1.8 / any | Supported, untested |
| AMT 1000 Smart | `0x36` (54) | 48 / none / 2 | `0x27`, Smart layout | `AMT 1000 SMART` | 1.8 / any | Supported, untested |
| AMT 4010 Smart | `0x41` (65) | 64 / 4 / 19 | `0x17`, 4010 layout (8 zone pairs, stay per partition from fw 5.7 per AMT Remoto, 5.0 per Guardian) | `XEG 4000 Smart` | 3.2 / 2.0 | Supported, untested |
| ANM 24 NET | `0x24` (36)¹ | 24 / none / 1 | own layout (`Read24NetStatus`) | `ANM24NET` | 3.0 / any | Not supported |
| ANM 24 NET G2 | `0x25` (37) | 24 / none / 1 | own layout | `ANM24NETG2` | any | Not supported |

"Supported, untested" means the client decodes the layout exactly as the
official app does, but nobody has confirmed it on that hardware yet. The Smart
and 4010 layouts are decoded from the app's code alone.

¹ AMT Remoto Mobile lists ANM 24 NET as code 2; Guardian and AMT Mobile V3 use 36.

### Other families (not supported: different protocol)

| Model | Code | Zones / partitions / PGMs | Protocol |
|-------|------|---------------------------|----------|
| AMT 8000 | `0x01` (1) | 64 / 16 / 16 | ISECNet v2 (found by UDP multicast) |
| AMT 8000 PRO | `0x8A` (138) | 64 / 16 / 16 | ISECNet v2 |
| AMT 8000 LITE | `0x8B` (139) | 64 / 16 / 16 | ISECNet v2 |
| AMT 9000 | `0x90` (144) | 244 / 8 / 26 | ISECNet v2 |
| ELC 6012 NET (electric fence) | `0x35` (53) | 8 / 2 / 2 | ISECNet v2 |
| ELC 6012 IND (electric fence) | `0x39` (57) | 8 / 2 / 2 | ISECNet v2 |
| 4G communicator (Wi-Fi) | `0x38` (56) | – | own layout (AMT Remoto only) |

### Legacy models (named only in AMT Mobile V3)

Older models with a code in AMT Mobile V3's table but no parser in the newer
apps: GPRS 1000 UN (`0x04`), AMT 2008 RF (`0x08`), AMT 2010 (`0x10`), AMT 2018
(`0x18`, the original, pre-E/EG), AMT 2110 (`0x20`), AMT 3010 (`0x30`).
Nothing is known about their protocol beyond the code.

According to the official app, the session (login, problems, EEPROM reads,
arm/disarm, hang-up) is common to the whole v1 family and only the status
layout differs. If you own one of the untested or undecoded models, see
[Contributing](#contributing): a single captured status frame is enough to add
it.

## Features

Read-only:

- Armed and stay state per partition (A–D), open / triggered / bypassed zones
  (48, or 64 on the 4010 Smart)
- AC supply and battery voltage, panel clock, firmware and model
- Siren and PGM state
- Active problems decoded into text (216 problem bits): AC loss, low battery,
  wireless-sensor low battery per zone, keypad/receiver/expander faults, zone
  and keypad tamper, siren wire cut, phone line, communication failure
- MAC address and raw EEPROM reads
- Smart models: enabled, stay and wireless zones, network and cellular
  details, per-sensor battery/tamper/signal
- Discovery of panels on the network without a password

Write (each one needs `--yes`; state-checked where the panel reports the
state):

- Arm / disarm the whole panel or partition A–D, stay mode where supported
- PGM outputs, zone bypass, clearing triggered zones, setting the clock
- Silence a firing alarm
- EEPROM write (refuses protected areas, verified by reading back)

Low level: any `E7` command (`raw`) and single `E9` frames (`e9`).

Output as human-readable text or JSON. See [Command line](#command-line) for
which commands each model supports; sending one a model does not support can
hang it.

## Panel requirements

- The panel's **Ethernet port is connected to your LAN**, and you know its IP
  address. A DHCP reservation on your router helps.
- The **remote-access password** ("senha de acesso remoto", the one AMT Mobile
  and AMT Remoto ask for). The factory default is `878787`: change it.
- TCP **9009** reachable from where you run the client. Port 80 on these panels
  is an empty built-in web server and is not used.
- The panel serves few sessions at once, so close AMT Mobile / AMT Remoto while
  using this client.

## Installation

From a clone:

```bash
git clone https://github.com/fernandoglatz/intelbras-amt.git
cd intelbras-amt
pip install .            # or: pip install -e '.[test]' for development
```

This installs the `intelbras-amt` command. Without installing:

```bash
PYTHONPATH=src python3 -m intelbras_amt status
```

## Configuration

Settings come from command-line flags first, then `AMT_*` environment
variables, then a `.env` file in the current directory (or `--env-file PATH`).

```bash
cp .env.example .env
```

```ini
AMT_HOST=192.168.1.50   # panel IP
AMT_PORT=9009           # optional, default 9009
AMT_PASSWORD=           # remote-access password, 4 or 6 digits
```

`.env` is in `.gitignore`. Prefer it (or the environment) over `--password`,
which leaves the password in your shell history.

## Command line

> **Warning: only send a command your panel model supports.** On 2026-11-24 an
> AMT 1016 NET (firmware 2.6) was sent the Smart-only command `0x30`
> (`connections`). It did not answer, ignored the hang-up that followed, and
> then its network interface stopped responding entirely: TCP 9009 refused
> connections and the panel stopped answering ping for at least 8 minutes.
> Treat model-specific commands, `raw` and `e9` as able to hang a panel that
> does not know them. The "Models" column below is taken from the official
> apps' code; nothing outside "Tested live" has been run on real hardware.

| Command | What it does | Models | Writes | Tested live |
|---------|--------------|--------|--------|-------------|
| `status [--quick]` | Armed state, zones, voltages, clock, siren, PGMs, problems | all v1 | – | yes (1016 NET) |
| `problems` | Active problems | all v1 | – | yes |
| `mac` | MAC address (EEPROM read) | all v1 | – | yes |
| `pgm-state` | Siren and PGM 1–3 state | all v1 | – | yes |
| `eeprom ADDR COUNT` | Raw EEPROM read | all v1 | – | yes |
| `discover [IP or CIDR]` | MAC and model, no password | all v1 | – | yes |
| `arm` / `disarm [--partition A-D] [--stay]` | Arm/disarm, state-checked | all v1; `--stay` only Smart models and 4010 Smart fw 5.7+ | yes | no |
| `silence` | Silence a firing alarm | all v1 | yes | no |
| `pgm N on\|off\|toggle` | PGM 1–3 on/off (state-checked); 4–19 toggle | 1–3 all v1; 4–19 only 4010 Smart | yes | no |
| `bypass --add/--remove/--set ZONES \| --clear` | Bypass zones, verified by reading back | all v1 | yes | no |
| `clear-triggered` | Clear the triggered-zone memory | all v1 | yes | no |
| `set-clock [--time 'YYYY-MM-DD HH:MM']` | Set the panel clock | all v1 | yes | no |
| `eeprom-write ADDR HEX` | Write configuration memory (protected areas refused, verified) | all v1 | yes | no |
| `connections` | Ethernet/cellular links to monitoring and cloud | **Smart only** | – | **hung a 1016 NET** |
| `network` | IP, mask, gateway, DNS, MAC | **Smart only** | – | no |
| `cell` | Cellular module, signal, SIM, carrier, ICCID, IMEI | **Smart only** | – | no |
| `wireless` | Per-sensor battery, tamper, supervision, signal | **Smart only**, fw 1.80+ | – | no |
| `bus-devices` | Keypads and receivers on the bus | **4010 Smart, Smart** | – | no |
| `bus-search` | Make the panel scan its bus | **4010 Smart only** | yes | no |
| `raw HEX` | Any E7 command | depends on the command | `--yes` unless it is a read every model supports (`10 12 14 15 17 1D`, `19 10`) | `17` only |
| `e9 HEX` | One E9 frame (the cloud apps' format) | panels with newer firmware | if not a read | `5A` (ACK only) |

"All v1" means the AMT 1016 NET, 2018 E/EG, 2118 EG, 2016/2018 E3G, 2018 E
Smart, 1000 Smart and 4010 Smart. The client does **not** yet refuse a
model-specific command on the wrong model, so check the table first.

Examples:

```bash
intelbras-amt status
intelbras-amt --format json status
intelbras-amt discover 192.168.1.0/24
intelbras-amt arm --partition A --yes
intelbras-amt pgm 1 on --yes
intelbras-amt bypass --add 3,5-7 --yes
intelbras-amt set-clock --yes
```

Global options (before the command): `--host`, `--port`, `--password`,
`--env-file`, `--format text|json`.

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error: connection, wrong password, unsupported model, refused command |
| 2 | Write command run without `--yes` (nothing was sent) |

JSON output from `status` contains `model`, `firmware`, `armed`,
`armed_mask`, `stay_armed`, `partitions`, `open_zones`, `triggered_zones`,
`bypassed_zones`, `ac_voltage`, `battery_voltage`, `clock`, `partitioned`,
`alarm_firing`, `pgm` and `problems` (Smart models add `enabled_zones`,
`stay_zones`, `wireless_zones` and `zone_partitions`), which makes it easy to
feed into Home Assistant (`command_line` sensor), Node-RED, n8n or a
monitoring check.

## Python API

```python
from intelbras_amt import AmtClient, AuthError, OpenZonesError

with AmtClient("192.168.1.50", "123456") as panel:
    st = panel.status()
    print(st.model, st.firmware)
    print("armed:", st.armed, [p.armed for p in st.partitions])
    print("open zones:", st.open_zones)
    print("battery:", st.battery_voltage, "V")
    for problem in st.problems:
        print("problem:", problem)

    # Writes are state-checked: nothing is sent if already in that state.
    try:
        panel.set_armed(True, partition=1)
    except OpenZonesError:
        print("cannot arm: zones open")
```

| Call | Returns |
|------|---------|
| `status(full=True)` | `Status` dataclass (`.to_dict()` for JSON) |
| `problems()` | list of problem descriptions |
| `mac()` | `"AA:BB:CC:DD:EE:FF"` |
| `read_eeprom(address, count)` | `bytes` |
| `set_armed(armed, partition=None)` | `Status` after the change |
| `silence_alarm()` | `None` |

Exceptions: `AuthError` (wrong password), `PanelTimeout`, `CommandError`
(state did not change, invalid partition), `OpenZonesError`, `AmtError` (base
class: connection, wrong panel family).

Always use the context manager (or call `close()`). It sends `HANG_UP`;
without it the panel keeps the session busy for about 30 seconds.

## Safety

- **Arm/disarm is a toggle on the panel.** The official app sends the same
  packet both ways, so the client reads the status first, sends only when the
  state would change, and re-reads it afterwards to confirm. A whole-panel
  toggle is refused while only one partition is armed.
- Write commands do nothing without `--yes`. Test them while you are next to
  the keypad.
- **Commands a model does not support can hang the panel's network
  interface.** An AMT 1016 NET sent a Smart-only command stopped answering
  TCP 9009 and ping (see [Command line](#command-line)). Check the "Models"
  column before running a model-specific command, `raw` or `e9`, and stop at
  the first command that gets no answer instead of retrying.
- `eeprom-write` changes the panel's programming. It refuses the address
  ranges the official app refuses and checks the result by reading it back,
  but a wrong value can still change how your alarm behaves. Note the previous
  value it prints so you can write it back.
- The client never touches `http://<panel>/mpfsupload`, which rewrites the
  panel's web image.
- If a monitoring company watches your alarm, remote arm/disarm events reach
  them like any other app's.
- Keep the panel off the internet. Port 9009 should only be reachable on your
  LAN or over a VPN.

## Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| `cannot connect` / timeouts right after a previous run | The panel still holds the old session (~30 s) or AMT Mobile/Remoto is connected. Wait, or close the other app. The client retries 4 times, 10 s apart. |
| `password rejected` | Wrong remote-access password. It is not the keypad user code. |
| `not an AMT 2018-family panel` | The device answered in another protocol (e.g. AMT 8000). |
| `status layout for … is not supported` | Model detected but not decoded yet. See [Supported panels](#supported-panels). |
| `panel refused: there are open zones` | Close or bypass the zones, then arm again. |
| Other apps' `E9` frames get only `02 E9 FE EA` | Expected on older firmware: that frame family is for the cloud apps. This client uses `E7`. |
| `… not supported by this panel (no answer)`, then the panel stops accepting connections and stops answering ping | The panel was sent a command its model does not know. Stop sending anything to it. Check the alarm still works from the keypad. The network side may recover on its own; if it does not, power-cycle the panel (mains and battery), telling your monitoring company first. Do not repeat that command on that model. |

## How it works

All frames on port 9009 look like:

```
[len] E7 [n] [data…] [CRC-16, little-endian] [checksum]
```

A session is: refresh (`10`) → identify with the password (`11 …`) →
commands → hang up (`15`). The full protocol (frame format, CRC table, every
command, the status byte map, EEPROM addresses, the problem bitmap and the
unauthenticated discovery probes) is in [docs/PROTOCOL.md](docs/PROTOCOL.md).
How Intelbras' own apps use the cloud relay and REST API, plus the security
observations, is in [docs/CLOUD.md](docs/CLOUD.md).

Everything was worked out by decompiling Intelbras' Android apps (AMT Remoto
Mobile, AMT Mobile V3, Guardian) for interoperability, then confirmed against
a real AMT 1016 NET. No firmware was modified and no Intelbras servers were
probed.

## Development

```bash
pip install -e '.[test]'
python3 -m pytest
```

```
src/intelbras_amt/
  protocol.py   framing, CRC table, command codes
  decode.py     reply decoders (status, problems, siren, EEPROM, ...)
  client.py     TCP session, reads, state-checked writes
  config.py     flags > environment > .env
  cli.py        command line
tests/          live-captured frames + a threaded fake panel
docs/           PROTOCOL.md, CLOUD.md
```

The test fixtures are real frames captured from an AMT 1016 NET, with the
password and MAC removed. A threaded fake panel drives the client and CLI
tests, so the suite needs no hardware.

## Contributing

The most useful contributions are captures from **models other than the AMT
1016 NET**. To add one:

1. Run `intelbras-amt --format json status --quick` and note the error, or
   capture the raw reply to `0x17` (or `0x27` on Smart models).
2. Open an issue with the model, firmware version and the reply bytes.
   **Remove your password and MAC first.**
3. Or send a pull request: add the layout to `decode.py`, the frame to
   `tests/conftest.py`, and a test in `tests/test_decode.py`.

Bug reports with the exact command, output and panel model/firmware are
welcome. Every change ships with tests (`python3 -m pytest` must pass).

## License

[MIT](LICENSE). Not affiliated with Intelbras; see the note at the top.
