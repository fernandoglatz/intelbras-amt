# ISECNet v2 (AMT 8000 family, ANM 24 NET)

The second Intelbras protocol family, used locally on TCP 9009 by the AMT 8000,
AMT 8000 PRO, AMT 8000 LITE, the ANM 24 NET (+ G2), the AMT 9000 and the ELC
6012 electric fence controllers. Reconstructed from:

* **AMT Remoto Mobile** (`Amt2k.Core.DotnetStandard`): `LoginRepository.OpenAmt8000`
  (local login), `Packet(CommandTypesAmt8000, …)`, `CommandTypesAmt8000` (349
  commands), `OnlineAmt8000DataSource`, `OnlineInterpreter.Read8000Status`,
  `Read8000StatusFull`, `Read24NetStatus`, `Converters.TranslateAmt8000`.
* **Guardian** (`devices.amt.sdk`): `ISECNetV2Protocol`, `ISECNetV2ServerProtocol`,
  `ISECNetV2SDK`, `helpers.ISECNetV2ParseHelper`, `enums.ISECNetV2*`.
* Cross-checked against independent projects (caarlos0/homekit-amt8000,
  fdaneluzzi/homeassistant-amt8000), noting where they disagree.

**Nothing here was tested on a real v2 panel.** Example frames were produced by
this project's code; replies marked *inferred* follow the apps' parsers.

## Telling the families apart

A local session always starts with the **v1 refresh** frame (`E7`, command
`10`). AMT Remoto sends exactly this to every panel and checks the answer:

| Answer data | Family |
|-------------|--------|
| `90` | v1 (AMT 1016 NET, 2018 family, Smart, 4010) |
| `80` | v2 (AMT 8000 family, ANM 24 NET) |

```
→ 05 E7 01 10 06 60 6A          refresh (the only command sent before the family is known)
← 05 E7 01 80 05 00 99          v2 panel (inferred: TranslateAmt8000 checks answer[3] == 0x80)
```

This client never sends anything else until it knows the family, and refuses a
command of the other family right there (see the README).

## Frame

```
[dest 2] [source 2] [length 2] [command 2] [payload …] [checksum]
dest     00 00
source   00 F1 for a local client (AMT Remoto); the cloud relay assigns one
length   2 + payload length (big-endian)
checksum XOR of all preceding bytes, XOR FF (same as v1)
```

```
00 00 00 F1 00 02 0B 4A 4D       STATUS (full), no payload
│     │     │     │     └─ checksum
│     │     │     └─ command 0x0B4A
│     │     └─ length 2
│     └─ source 00 F1
└─ dest 00 00
```

Replies have the same shape. `ACK` is command `F0FE`, `NACK` is `F0FD` with the
reason in payload byte 0.

## Session

| Step | Command | Payload | Reply |
|------|---------|---------|-------|
| Family probe | v1 refresh | | `80` |
| Login | `F0F0` AUTH | `01 <6 digits> 10 00` | `F0F0`, payload `[0]` result |
| Model / firmware | `0060` INFO | | `0060`, see below |
| Keep-alive | `F0F7` | | `ACK` |
| Logout | `F0F1` DISCONNECT | | `ACK` |

**Login payload.** AMT Remoto (local): `01`, the six password digits each in
its own byte (`0` → `00`, shorter passwords padded with `00`), then `10 00`.
Guardian, through the cloud relay, sends `03 <digits> 00 01` with digit `0` as
`0A`; caarlos0's local client sends `00 <digits> 10` with `0` as `0A`. This
client follows AMT Remoto. If a panel rejects a password containing `0`, the
`0A` encoding is the first thing to try.

```
→ 00 00 00 F1 00 0B F0 F0 01 01 02 03 04 05 06 10 00 13     AUTH "123456"
← 00 00 00 00 00 04 F0 F0 00 01 FA                           accepted (inferred)
```

AUTH results: `0` accepted (AMT Remoto also accepts `12`), `1` wrong password,
`2` wrong software version, `3` panel will call back, `4` waiting for user
permission.

## Commands

| Command | Name | Payload | Models | Writes |
|---------|------|---------|--------|--------|
| `0060` | INFO | – | all v2 | – |
| `0B4A` | Full status | – | AMT 8000 / PRO / LITE (**not** ANM) | – |
| `0B01` | Basic status | – | all v2; the only status AMT Remoto uses for the ANM | – |
| `0B7A` | Full status G2 | – | 8000 PRO/LITE fw ≥ 3.2.6 (not decoded here) | – |
| `401E` | Arm / disarm | `<partition 1-16 or FF> <op>`; op `0` disarm, `1` arm, `2` stay, `3` force arm | all v2 (ANM: `FF` only) | yes |
| `4019` | Siren off | `FF` | AMT 8000 family | yes |
| `401A` | Panic | `0` silent, `1` audible, `2` fire, `3` medical | AMT 8000 family | yes |
| `401F` | Bypass | pairs `<zone − 1> <1 bypass / 0 restore>` | AMT 8000 family | yes |
| `45AF` | PGM on/off | `<pgm − 1> <1 / 0>` (AMT 9000: index + 1) | AMT 8000 family | yes |
| `0B70` | PGM status | – | AMT 8000 family | – |
| `0B71` | Connection mode | – | all v2 | – |
| `0B73` | Wireless signal levels | `<device type>` | AMT 8000 family | – |
| `3FAA` | MAC address | `00` | all v2 | – |
| `33E0` / `32E0` / `35E0` | Zone / user / PGM names | index list | AMT 8000 family | – |
| `3A10` / `3A20` | Zones per partition / zones with stay | `FF` | AMT 8000 family | – |
| `0BB0` | Sensor picture | event, picture, fragment | AMT 8000 with camera sensors | – |

v2 writes are **explicit**: unlike v1's toggle, arm/disarm, PGM and bypass name
the wanted state. This client still reads the status before and after.

Examples (generated):

```
00 00 00 F1 00 04 40 1E FF 01 AA        arm everything
00 00 00 F1 00 04 40 1E 02 02 54        stay-arm partition 2
00 00 00 F1 00 04 40 1E 01 00 55        disarm partition 1
00 00 00 F1 00 06 40 1F 02 01 3F 01 6A  bypass zones 3 and 64
00 00 00 F1 00 04 45 AF 03 01 E2        PGM 4 on
00 00 00 F1 00 03 40 19 FF AB           siren off
00 00 00 F1 00 03 40 1A 01 56           audible panic
00 00 00 F1 00 02 F0 F1 0D              disconnect

00 00 00 00 00 02 F0 FE F3              ACK
00 00 00 00 00 03 F0 FD 27 D6           NACK, reason 39 = open zones
```

### NACK reasons (`ISECNetV2ErrorResponse`)

`23` wrong number of digits · `24` wrong number of password digits · `25`
wrong password · `26` partition does not exist · `27` no permission for this
partition · `30` disarming not allowed · `32` partition has no zones · `33`
command denied · `34` user has no partitions · `35` event has no picture ·
`36` invalid picture index · `37` invalid fragment index · `38` panel is not
partitioned · `39` open zones · `40` picture still recording · `41` mobile
access disabled · `42` not allowed · `45` repeated password · `46`
arming/disarming failed · `47` stay arming denied · `48` panel must be
disarmed first · `52` panel not connected · `54` partition has no stay zones ·
`55` bypass denied · `56` corrupted firmware · `63` panel has no zones · `FE`
invalid command.

## INFO reply (`0060`)

| Payload byte | Meaning |
|--------------|---------|
| `[0]` | model (below) |
| `[1..3]` | firmware `a.b.c`; ANM with `[1] = 0`: `(b >> 4).(b & 0F).[1]` from byte `[2]` |
| `[4]` | bit `0x10` = partitioned |
| `[6]` | ANM 24 NET G2 only: `0` dev build, `1` beta build |

| Model byte | Model |
|------------|-------|
| `01` | AMT 8000 |
| `8A` | AMT 8000 PRO |
| `8B` | AMT 8000 LITE |
| `02` (AMT Remoto) / `24` (Guardian) | ANM 24 NET |
| `25` | ANM 24 NET G2 |
| `90` | AMT 9000 |
| `35` / `39` | ELC 6012 NET / IND (electric fence) |
| `38` | 4G communicator |

## Full status (`0B4A`), AMT 8000 family

Offsets into the reply payload (AMT Remoto's raw index = payload index + 8).

| Payload | Meaning |
|---------|---------|
| `[0]` | model |
| `[1..3]` | firmware `a.b.c` |
| `[4]` | bit `0x10` partitioned |
| `[20]` | general state: `0x20`+`0x40` armed, `0x20` alone partial, `0x80` stay (when not disarmed), `0x02` firing |
| `[22..37]` | partitions 1–16: `0x80` enabled, `0x01` armed, `0x02` stay, `0x04` firing |
| `[38..45]` | open zones 1–64 |
| `[46..53]` | violated (triggered) zones |
| `[54..61]` | bypassed zones |
| `[64..69]` | clock: day, month, year, hour, minute, second |
| `[73..80]` | zones with a communication (supervision) error |
| `[87..88]` | PGMs with a communication error |
| `[89..96]` | zones with tamper |
| `[105..112]` | zones with a low battery |
| `[119..120]` | PGMs with a low battery |
| `[134]` | panel battery: `1` missing, `2` low, `3` medium, `4` high |
| `[137..138]` | PGM 1–16 on |

Bitmaps are LSB first. Two disagreements between sources:

* **Stay bit of a partition.** Guardian and AMT Remoto both use `0x02`; an
  independent project documented `0x40`. This client uses `0x02`.
* **Clock encoding.** AMT Remoto prints the bytes as hex (BCD); Guardian parses
  them as plain integers. This client decodes BCD and also returns the raw
  bytes (`clock_raw`).

## Basic status (`0B01`), ANM 24 NET

| Payload | Meaning |
|---------|---------|
| `[0]` | state: `0x20`+`0x40` without `0x80` armed; partial = `0x80` (firmware ≥ 6.0.0) or `0x20` without `0x40` (older); `0x02` firing |
| `[17..19]` | 24-zone bitmap: **open** on the G2, **triggered** on the first generation |
| `[25..27]` | 24-zone bitmap: **triggered** on the G2, **open** on the first generation |
| `[33..35]` | bypassed zones |
| `[43..48]` | clock: day, month, year, hour, minute, second |

The ANM has no partitions; AMT Remoto arms it with `401E FF <op>` and never
sends it the full status `0B4A`. This client only sends the ANM INFO, the basic
status and arm/disarm; bypass, PGM, siren and panic are refused for it.

## Discovery

AMT 8000 panels are found by UDP multicast (`AMTSearcher.searchAMT8000Devices`):
the app listens on port 17765 for announcements answering a request on 17764
(payload encrypted with a fixed XOR key and checked with a CRC). Not
implemented here. The TCP probe in PROTOCOL.md (`01 C4 3A`) is what Guardian
sends to every host on 9009, including v2 panels.

## Cloud relay

Guardian reaches v2 panels through `amt8000.intelbras.com.br` (port 9009, then
two fallbacks): `CONNECT` (`30F6`) for the one-byte key, `APP_CONNECT` (`FFF1`)
with the alarm name XORed with it, then AUTH with the source ID the relay
assigns. Details and security notes in [CLOUD.md](CLOUD.md).

## Not implemented

AMT 9000 status (paged, `0B4B`), ELC 6012 fences, G2 full status (`0B7A`), names,
pictures, programming commands (most of the 349 in `CommandTypesAmt8000` read
or write configuration).
