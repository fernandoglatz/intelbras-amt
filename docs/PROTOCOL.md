# AMT 2018-family local protocol (AMT 1016 NET)

How the panel is reached locally, reverse-engineered from the AMT Remoto Mobile
app (`br.com.intelbras.amtremotomobile`, Xamarin/.NET, signed by
`CN=Intelbras AMT`) and confirmed against a live AMT 1016 NET, firmware 2.6, on
2026-11-24.

## Where the "API" is

| Port | What | Notes |
|------|------|-------|
| 80/tcp | Microchip TCP/IP stack HTTP server | No pages in flash: every path returns `404: File not found … MPFS Upload`. **Do not use `/mpfsupload`**: it writes the web image into the panel's EEPROM. |
| 9009/tcp | ISECNet, binary | The only real interface. AMT Mobile, AMT Remoto and this client all use it. |

The panel serves few sessions at a time. A session closed without `HANG_UP`
keeps the port busy for roughly 30 s, so always hang up.

## Frame

```
[len] E7 [n] [data … n bytes] [crc16 lo] [crc16 hi] [chk]
len = n + 4             (0xE7 + n + data + crc)  → whole frame = len + 2 bytes
crc = table CRC-16 over [n] + data, little-endian (table in protocol.py, copied
      from Amt2k.Protocol.DotnetStandard.Crc)
chk = XOR of all preceding bytes, XOR 0xFF
```

`data[0]` is the command; the reply carries `command | 0x80`. Built by
`Amt2k.Core.DotnetStandard.Packet(CommandTypes.CMD_IP_COMMUNICATION = 0xE7, data)`.

This differs from the `E9` "ISECMobile" frames (`[len] E9 21 <password ASCII>
<cmd> 21 <chk>`) documented by other open-source projects. The 1016 NET answers
those frames with a bare ACK `02 e9 fe ea` and returns no data.

## Session

| Step | Request data | Reply data | Source |
|------|--------------|------------|--------|
| Refresh / probe | `10` | `90` = 2018 family (AMT 8000 answers in its own `00 00 …` format) | `LoginRepository.LocalIpLogin` |
| Identify | `11 <pw bytes> 34` | `50` OK, `4D` OK as master connection, anything else = rejected | `LoginRepository.SendIdentify` |
| Keep-alive | `10` | `90` | `KeepAliveService` |
| Hang up | `15` | `95 48` | `Converters.Translate(CMD_LOCAL_HANG_UP)` |

Password bytes: each digit pair is parsed as a hex byte, so `"246810"` becomes
`24 68 10` and a 4-digit password gives two bytes (`Converters.GetPartsInBytes`).

## Commands

> **Warning:** a panel can stop responding when sent a command its model does
> not support. See [Unsupported commands](#unsupported-commands-can-hang-the-panel)
> below. "Models" is taken from the official app's code (which data source
> sends each command); "Live" means confirmed on a real AMT 1016 NET, fw 2.6.

| Cmd | Name | Request | Reply | Models | Live |
|-----|------|---------|-------|--------|------|
| `10` | Refresh / keep-alive | `10` | `90` | all v1 | yes |
| `11` | Identify (login) | `11 <pw> 34` | `50` / `4D` | all v1 | yes |
| `15` | Hang up | `15` | `95 48` | all v1 | yes |
| `17` | Status | `17` | `97` + 25 bytes (2018 layout) or 29 bytes (4010 layout) | all v1 (Smart models: model byte only, use `27`) | yes |
| `27` | Smart status | `27` | `A7` + 89 bytes | **2018 E Smart, 1000 Smart** | no |
| `14` | Problems | `14` | `94` + problem bitmap (216 bits in the app; the 1016 NET sends 15 bytes) | all except Smart | yes |
| `34` | Problems (new) | `34` | `B4` + same bitmap | **Smart** | no |
| `1D` | Bypassed zones | `1D` | `9D` + 6-byte bitmap (8 bytes, 64 zones, on the 4010) | all except Smart (in `A7`) | yes |
| `19 10` | Siren / PGM state | `19 10` | `99 <flags>`: `0x04` alarm firing, `0x40` PGM1, `0x20` PGM2, `0x10` PGM3 | all v1 | yes |
| `19 40` | Silence alarm | `19 40` | `99 …` (`CreateDisableAlarmPacket`) | all v1 | no |
| `19 60/80/C0` | Toggle PGM 1/2/3 | `19 xx` | `99 <flags>` with the new state | all v1 | no |
| `1E <n> 00` | Toggle PGM 4–19 | `1E n 00` | `9E` | **4010 Smart** | no |
| `16 <mask>` | Arm/disarm **toggle** | `16 mask` | `96 <b>`; `b & 0xF0 == 0x80` = refused, open zones | all v1 | no |
| `1B <8 bytes>` | Set bypassed zones (full set) | `1B` + bitmap | `9B` | all v1 | no |
| `1C` | Clear triggered-zone memory | `1C` | `9C` | all v1 | no |
| `18 YY MM DD hh mm 00` | Set clock (BCD) | | `98` | all v1 | no |
| `12 hi lo n` | Read EEPROM | | `92` + n bytes | all v1 | yes |
| `13 hi lo n …` | Write EEPROM | | `93 hi lo` | all v1 | no |
| `23` | Bus devices | `23` | `A3 <flags>`: bits 0–3 keypads 1–4, bits 4–7 receivers 1–4 | **4010 Smart, Smart** | no |
| `22` | Search bus devices | `22` | `A2 00` = started | **4010 Smart** | no |
| `30` | Connection status | `30` | `B0 <module> <links>` | **Smart only** | **hung a 1016 NET** |
| `31` | Network card | `31` | `B1` + IP, mask, gateway, DNS1, DNS2 (4 bytes each), MAC | **Smart only** | no |
| `32` | Cellular card | `32` | `B2` + module, signal 0–31, SIM, carrier, ICCID (20 ASCII), IMEI (15 ASCII) | **Smart only** | no |
| `36` | Wireless sensors | `36` | `B6` + bitmaps for zones 25–48 and a signal byte per zone | **Smart only**, fw 1.80+ | no |

Arm mask (`OnlineAmt2018DataSource.ActivatePanel`): `00` whole panel, `01`
partition A, `02` partition B; stay shifts it left 4 bits (`F0` = whole panel
stay). The app sends the same packet to arm and to disarm, so the client reads
the status first and only sends when the state would change.

### Unsupported commands can hang the panel

Observed on an AMT 1016 NET, firmware 2.6, on 2026-11-24 around 01:47 local
time. The sequence, all within about a minute:

1. A one-shot `E9` partial-status frame (`5A`) on its own connection, answered
   with the usual bare ACK `02 E9 FE EA`. That connection carries no session,
   so it was closed without a hang-up.
2. A new `E7` session: refresh and identify answered normally, then `30`
   (connection status, Smart models only) got **no answer** within 5 s. The
   hang-up sent after it got no answer either.
3. From then on the panel **refused TCP 9009** and stopped **answering ping**
   (100 % loss), for at least the 8 minutes it was watched. Before this, the
   same panel had answered every request that night and always freed a
   session about 30 s after an unclean close.

It is not proven which step caused it (the unsupported `30`, the missed
hang-up, or the combination), so treat all of these as risky on a model that
does not list them:

* any command marked for other models in the table above;
* `raw` commands you have not seen the official app send to your model;
* `E9` frames on firmware that only ACKs them.

If a command gets no answer, stop: do not retry and do not hammer the port.
Check the alarm from its keypad. The network side may recover on its own; a
power cycle (mains and battery) resets it.

### Commands not implemented

* `20 <type> <id> <index>` (add wireless device, reply `A0 <result>`): sent by
  the Smart models' pairing flow, which also rewrites the panel's wireless
  device tables in EEPROM. Not reproduced here.
* `1A` (write custom codes), `21` (delete wireless device), `24`/`25` (start
  firmware update, update status) and `39` (reset options): named in AMT
  Remoto's `CommandTypes` table, but no payload for them is built anywhere in
  the app, so their format is unknown. Do not guess at them on a real panel:
  `39` and `24` in particular could reset or reflash it.

### Status reply (`97`)

Offsets into the reply data (`data[0] = 0x97`). The app's `Read2018Status`
indexes the raw frame, which is these offsets + 3.

| Offset | Meaning |
|--------|---------|
| 1 | Model: `0x61` AMT 1016 NET, `0x1E` 2018 E/EG, `0x2E` 2118 EG, `0x31` 2016 E3G, `0x32` 2018 E3G, `0x34` 2018 E Smart, `0x36` 1000 Smart, `0x41` 4010 Smart |
| 2 | Firmware, nibbles (`0x26` = 2.6) |
| 3 | Armed partitions: bit0 A, bit1 B; whole panel armed when `& 3 == 3` |
| 4–15 | Six pairs `(open, triggered)`, each a bitmap of 8 zones (1–48) |
| 16 | Not parsed by the app (`0x08` on the live panel) |
| 17–18 | AC supply, big-endian, ÷ 67 = volts |
| 19–20 | Battery, big-endian, ÷ 67 = volts |
| 21–25 | hour, minute, day, month, year − 2000 (binary) |

The Smart models (`0x34`, `0x36`) use command `27`/`A7` with a longer layout,
and the 4010 has its own parser (`Read4010Status`). Neither is decoded here.

### EEPROM addresses (`RegionToRead`)

| Address | Content |
|---------|---------|
| 675 | Config byte 1, bit 0 = partitioned |
| 677 | Blocks byte (`BITS_CONFIG_BYTE_3`, `GeneralBlock2018DataSource`): bit 5 = **block** wireless (SF) low-battery detection, so 0 means detection is on. Read as `0x00` on the live panel. |
| 1776 | MAC address (6 bytes) |
| 256 / 264 | Zones in partition A / B. The live 1016 NET returns bytes that do not decode as clean zone bitmaps, so this client exposes them raw only. |

Addresses 976–1023 and 5888–8191 are marked forbidden in `EEPROM.ForbiddenAddress`.

### Problem bitmap

Bit n (LSB first from the first data byte after `94`): 0 AC failure, 1 low
battery, 2 battery missing/reversed, 3 battery short, 4 aux overload, 8–11
keypad 1–4, 12–15 receiver 1–4, 16–19 PGM expander 1–4, 20–25 zone expander
1–6, 28–31 keypad tamper 1–4, 32 siren wire cut, 33 siren short, 34 phone line
cut, 35 event communication failure, 40–87 wireless low battery zones 17–64,
88–151 zone tamper 1–64, 152–215 zone short circuit 1–64 (`Core.Problems`).

## Worked examples (`E7`, binary)

All frames below were produced by this project's `build_frame()` and pass
`parse_frame()`. Requests without a password and all replies marked *live*
are byte-for-byte what a real AMT 1016 NET (firmware 2.6) sent or accepted.
Examples use the dummy password `123456` and the dummy MAC `02:00:00:AB:CD:EF`.

### Anatomy of one frame

```
05 E7 01 10 06 60 6A        refresh request
│  │  │  │  └──┴── CRC-16 over [01 10], little-endian → 0x6006
│  │  │  └──────── data: command 0x10 (REFRESH)
│  │  └─────────── n = 1 data byte
│  └────────────── header 0xE7
└───────────────── len = 5 → whole frame is len + 2 = 7 bytes
                   last byte 6A = XOR(05 E7 01 10 06 60) XOR FF
```

CRC and checksum in Python (the full 257-entry table is in `protocol.py`):

```python
def crc16(payload):                  # payload = [n] + data
    v = 0
    for b in payload:
        v = (v >> 8) ^ CRC_TABLE[(v ^ b) & 0xFF]
    return v.to_bytes(2, "little")   # crc16(b"\x01\x10") == b"\x06\x60"

def checksum(frame_without_last_byte):
    c = 0
    for b in frame_without_last_byte:
        c ^= b
    return c ^ 0xFF
```

### A complete read-only session

```
→ 05 E7 01 10 06 60 6A                      REFRESH
← 05 E7 01 90 85 63 6A                      0x90: 2018 family           (live)

→ 09 E7 05 11 12 34 56 34 80 D5 14          IDENTIFY: 11 <12 34 56> 34  ("123456")
← 05 E7 01 50 87 E3 28                      0x50: password accepted     (live)
                                            (05 E7 01 4D 87 AD 7B = accepted as master)

→ 05 E7 01 17 86 71 FC                      STATUS
← 1E E7 1A 97 61 26 03 00 00 00 00 00 00
   00 00 00 00 00 00 08 03 D0 03 70 00 02
   18 0B 1A AB E0 27                        see breakdown below          (live)

→ 05 E7 01 14 86 7B F5                      PROBLEMS
← 14 E7 10 94 00 00 00 00 00 00 00 00 00
   00 00 00 00 00 00 1A 32 A0               no bits set → no problems    (live)

→ 05 E7 01 1D 86 4D CA                      BYPASSED ZONES
← 0B E7 07 9D 00 00 00 00 00 00 64 C1 2C    none bypassed                (live)

→ 06 E7 02 19 10 D6 4B 88                   SIREN / PGM STATE
← 06 E7 02 99 00 D6 21 72                   nothing firing, PGMs off     (live)

→ 08 E7 04 12 02 A3 01 A3 C2 C7             READ EEPROM 0x02A3 (675), 1 byte
← 06 E7 02 92 F9 6E 34 2D                   0xF9: bit0 = partitioned,
                                            bit5 clear (wireless low-battery detection on)   (live)

→ 08 E7 04 12 06 F0 06 C9 85 BA             READ EEPROM 0x06F0 (1776), 6 bytes = MAC
← 0B E7 07 92 02 00 00 AB CD EF BF 40 F2    MAC 02:00:00:AB:CD:EF (dummy)

→ 05 E7 01 15 06 7E 71                      HANG UP
← 06 E7 02 95 48 FF 91 AF                   95 48 = bye                  (live)
```

### STATUS reply, byte by byte (live)

```
1E E7 1A                 len 30, header, n = 26
97                       answer to 0x17
61                       model 0x61 = AMT 1016 NET
26                       firmware 2.6 (nibbles)
03                       armed partitions: bit0 A, bit1 B → both armed
00 00                    zones 1–8:   open, triggered
00 00                    zones 9–16:  open, triggered
00 00 00 00 00 00 00 00  zones 17–48 (four more pairs)
08                       not parsed by the app (see note)
03 D0                    AC supply  0x03D0 = 976 / 67 = 14.57 V
03 70                    battery    0x0370 = 880 / 67 = 13.13 V
00 02                    clock 00:02
18 0B 1A                 date 24/11/(20)26
AB E0                    CRC-16
27                       checksum
```

Note on byte 16 (`08`): AMT Remoto ignores it. In the `E9` status replies,
Guardian reads a battery-level byte where `0x08` means "high"
(`0x04` medium, `0x02` low, `0x01`/`0x10` no battery). The same meaning here is
plausible but unconfirmed.

Zone bits are LSB first: in a pair `05 04`, zones 1 and 3 are open and zone 3
is triggered.

### Writes (state-checked by the client)

```
→ 06 E7 02 16 00 74 28 56     REMOTE_ARM mask 00 = whole panel (toggle!)
→ 06 E7 02 16 01 F4 2D D2     mask 01 = partition A
→ 06 E7 02 16 02 F4 27 DB     mask 02 = partition B
→ 06 E7 02 16 F0 76 08 84     mask F0 = whole panel, stay
← 06 E7 02 96 03 F4 2B 56     accepted (byte after 96 = new armed mask)
← 06 E7 02 96 80 77 22 5F     refused: high nibble 0x8 = open zones

→ 06 E7 02 19 40 D7 AB 39     silence a firing alarm
← 06 E7 02 99 44 D7 B9 AF     example SIREN/PGM reply: 0x04 firing + 0x40 PGM1 on
```

Bypassed-zones bitmap example: `0B E7 07 9D 01 00 00 00 00 80 1F C1 D6` →
zones 1 and 48 bypassed.

### The other frame family (`E9`), for comparison

Used by AMT Mobile V3 and Guardian through the cloud. Password `1234` sent as
ASCII (`31 32 33 34`), no CRC, `21` delimiters:

```
08 E9 21 31 32 33 34 5A 21 40        partial status
08 E9 21 31 32 33 34 5B 21 41        complete status
08 E9 21 31 32 33 34 41 21 5B        arm all
09 E9 21 31 32 33 34 41 41 21 1B     arm partition A
09 E9 21 31 32 33 34 41 50 21 0A     arm stay
08 E9 21 31 32 33 34 44 21 5E        disarm
09 E9 21 31 32 33 34 45 01 21 5F     panic, audible
0A E9 21 31 32 33 34 50 4C 31 21 35  PGM 1 on
08 E9 21 31 32 33 34 63 21 79        siren off

02 E9 FE EA    ACK (all the 1016 NET on fw 2.6 ever returns)   (live)
02 E9 E1 F5    wrong password
02 E9 E4 F0    open zones
```

Status replies in this family, raw offsets (`raw[0]` = length byte), from
Guardian's `ISECNetParserHelper` and confirmed by independent projects:

| Field | `5A` partial | `5B` complete |
|-------|--------------|---------------|
| Model | raw[20] | raw[26] |
| Firmware | raw[21] | raw[27] |
| Clock (h, m, d, M, y) | raw[25..29] | raw[32..36] |
| Battery level | raw[32] | raw[42] |
| PGM 1–3 | raw[39] | raw[47] |
| PGM 4–19 | raw[54..55] if present | raw[54..55] |
| Minimum length | – | 57 bytes |

## Unauthenticated discovery (from the Guardian app)

Guardian's `AMTSearcher` scans the subnet by opening TCP 9009 on every address
and sending two bare frames (`[len] [cmd] [chk]`, same XOR-then-invert
checksum). Neither needs a password. Both were confirmed on the live 1016 NET.

| Request | Reply |
|---------|-------|
| `01 C4 3A` (discovery) | `07 C4 <MAC, 6 bytes> <chk>`, e.g. `07 C4 02 00 00 AB CD EF B7` (dummy MAC) |
| `01 C2 3C` (model) | `0C C2 41 4D 54 31 30 31 36 20 4E 45 54 10` = `"AMT1016 NET"` (live) (ASCII; other names: `AMT2018E/EG`, `AMT2018E SMART`, `XEG 4000 Smart` = 4010, …) |

The AMT 8000 family is found instead by UDP multicast (request port 17764,
responses on 17765).

## Guardian app (`br.com.intelbras.guardian` 2.25.9)

Kotlin SDK in `br.com.intelbras.guardianrefactor.devices.amt.sdk`
(`ISECNetSDK` for this family, `ISECNetV2SDK` for the AMT 8000).

* **No local control for this family.** After discovery, every session goes to
  `amt.intelbras.com.br:9015` (`global.amt.intelbras.com.br` for Spanish), or
  to a monitoring company's IP receiver. Steps: get a key byte (`01 <cmd>
  <chk>`), send an encrypted `CONNECT` with type `GUARDIAN (5)`, device ID,
  panel MAC and the path (`E` = Ethernet, then `G` = SIM01 when the panel is
  not reachable over Ethernet). The panel keeps an outgoing connection to that
  server, which relays the app's frames.
* **Commands use the `E9` "ISECMobile" frame**, not `E7`:
  `[len] E9 21 <password ASCII> <cmd…> 21 <chk>`. Commands: `5A` partial
  status, `5B` complete status (≥ 57 bytes), `5D` complete info (≥ 96 bytes),
  `41 [A-D] [50=stay]` arm, `44 [A-D]` disarm, `42 <bitmap>` bypass,
  `45 <0 silent | 1 audible | 2 medical | 3 fire>` panic, `43`/`63` siren on/off,
  `50 4C|44 <31…43>` PGM on/off, `5C <hi> <lo> <n>` read EEPROM (MAC at 1776).
* Firmware 2.60 only answers these frames with a bare ACK (`02 E9 FE EA`).
  The changelog says Guardian needs main CPU 4.10 + Ethernet CPU 4.00.
* The default remote password in the app is `878787`.

## AMT Mobile V3 app (`br.com.amt.v2` 4.2.2)

Java app (package `br.com.amt.v2`, label "Intelbras AMT Mobile V3", APK signed
`CN=Live ideas`). Panel logic in `br.com.amt.v2.paineis.*`, framing in
`br.com.amt.v2.protocolo.*`. It confirms the `E9` frame independently of
Guardian:

* **Also cloud-only for this family.** `connectSocket` targets
  `amt.intelbras.com.br:9016` (`global.amt.intelbras.com.br` abroad), or an IP
  receiver (`Receptor.ipdns:porta`). The LAN scan (`SearchPanelOnNetworkTask`)
  only probes AMT 8000 (TCP 9009); there is no direct-to-panel path for the
  2018 family. The `SocketController.PORT = 9010` / `IPDNS = 192.168.1.10`
  constants are unused defaults.
* **`E9` frame, password as ASCII** (`ProtocoloReceptorIP.montaMyHome`):
  `[len] E9 21 <password ASCII> <cmd…> 21 <chk>`, with `len =
  cmd.length + password.length + 3` and the same XOR-then-`0xFF` checksum. This
  is byte-for-byte the frame the test panel only ACKs on firmware 2.60.
* **Commands match** what this client already decodes: status `5A` (data at the
  same offsets — zones openers at list index 2–7, violated 8–13, bypassed
  14–19, battery byte at index **32**), bypass `42 <6-byte zone bitmap>`,
  PGM protocol commands `49`/`50` (PGM1/PGM2). Cloud wrapping adds a XOR-key
  request (`01 FB 05`) and a `CONNECT` (`0xE5`) XORed with that key; the `E9`
  frames after it are sent unencrypted. Full details in [CLOUD.md](CLOUD.md).
* `isPanelUsing5c()` enables the `5C` block-read only on a 1016 NET at firmware
  ≥ 65 — another feature gate this panel (2.60) does not meet.

### Why AMT Remoto works locally but AMT Mobile V3 / Guardian do not

Same panel, two different "ISECMobile" headers:

| App | Header | Password | Transport | Works on fw 2.60? |
|-----|--------|----------|-----------|-------------------|
| AMT Remoto Mobile | `E7` (231) | hex-packed (`"1234"`→`12 34`) | **direct TCP 9009** | **yes** (this client) |
| AMT Mobile V3 | `E9` (233) | ASCII | cloud `:9016` / IP receiver | no (bare ACK) |
| Guardian | `E9` via SDK | ASCII | cloud `:9015` / IP receiver | no (needs fw 4.10) |

So this client follows the AMT Remoto `E7`/direct path on purpose: it is the
only one the panel answers locally.

## Other connection paths in the app (not implemented)

* Cloud: TCP to Intelbras' cloud, `CMD_CLOUD_CONNECT (0xE5)` with the panel MAC,
  then the same `E7` session (relay details in [CLOUD.md](CLOUD.md)).
* IP receiver: `0xE0` account inform, `0xE3` status with `E/G/H<account>`,
  `0xE4` link set, then the same `E7` session.

## How it was extracted

1. Downloaded the APK (via apkeep/APKPure), checked the signing certificate.
2. Unpacked `assemblies/assemblies.blob` (Xamarin `XABA` v1 store, LZ4 `XALZ`
   entries) into 118 DLLs.
3. Decompiled `Amt2k.Core.DotnetStandard.dll` with `ilspycmd`.
4. Key classes: `Infra.Repositories.Login.LoginRepository`, `Packet`,
   `CommandTypes`, `Protocol.Crc`, `Core.Checksum`,
   `Infra.Datasources.Online.OnlineAmt2018DataSource`,
   `Infra.Datasources.Online.OnlineInterpreter`, `InterpreterInformation`,
   `Domain.Builders.PacketBuilder`, `Protocol.EEPROM`, `Protocol.RegionToRead`.

Two more apps were decompiled with `jadx` for cross-checking (not the basis of
this client, which follows AMT Remoto's local `E7` path):

* **Guardian** (`br.com.intelbras.guardian` 2.25.9, Kotlin): classes under
  `…guardianrefactor.devices.amt.sdk` — `ISECNetProtocol`, `ISECNetSDK`,
  `ISECNetServerProtocol`, `AMTSearcher`. Source of the discovery probes and
  the `E9` command table above.
* **AMT Mobile V3** (`br.com.amt.v2` 4.2.2, Java): `paineis.Amt2018`,
  `protocolo.ProtocoloReceptorIP` (`montaMyHome`), `protocolo.SocketController`,
  `protocolo.ProtocoloServidorAMT`. Confirms the `E9`/ASCII frame and the
  cloud-only transport for this family.
