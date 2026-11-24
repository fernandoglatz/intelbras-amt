# Intelbras cloud (AMT 2018 family)

How Intelbras' own apps reach a panel through Intelbras' servers instead of the
LAN. Reverse-engineered **statically** from two apps:

* Guardian `br.com.intelbras.guardian` 2.25.9 (Kotlin):
  `devices.amt.sdk.ISECNetSDK`, `protocol.ISECNetServerProtocol`,
  `enums.ISECNetServerResponse`, `utils.network.clients.GuardianClient`.
* AMT Mobile V3 `br.com.amt.v2` 4.2.2 (Java):
  `protocolo.ProtocoloServidorAMT`, `protocolo.SocketController`,
  `view.LoginActivity`.

Nothing here was sent to Intelbras' servers. Byte layouts come from the code,
not from captures, so treat them as unverified until seen on the wire. This
client does not use the cloud. See [PROTOCOL.md](PROTOCOL.md) for the local
`E7` path it does use.

## Hosts

| Host | Port | Used by | Purpose |
|------|------|---------|---------|
| `amt.intelbras.com.br` (`global.amt.intelbras.com.br` for Spanish) | 9015 | Guardian | Relay for 2018-family panels |
| same | 9016 | AMT Mobile V3 | Relay for 2018-family panels |
| `amt8000.intelbras.com.br` (`global.…`) | 9009, then two fallbacks (one is 80) | both | Relay for AMT 8000 (ISECNet v2) |
| `api-guardian.intelbras.com.br` | 8443 (HTTPS) | Guardian | Account REST API: devices, events, settings |
| `api.conta.intelbras.com/auth/` | 443 | Guardian | Intelbras account login (WSO2, OpenID Connect) |

The relay sockets are plain `java.net.Socket`s. **There is no TLS** on 9015/9016.

## Relay protocol (2018 family)

The panel keeps an outgoing connection to the relay (enabled in its "cloud"
monitoring settings). The app connects to the same relay, names the panel, and
the relay forwards bytes between the two.

Server frames are `[len] [cmd] [payload…] [chk]`, with `len` counting the
bytes between itself and the checksum, and `chk` the usual XOR of all
preceding bytes, XOR `0xFF`.

### 1. Get the session key

```
app → 01 FB 05            (len 1, cmd 0xFB)
app ← ?? KK …             KK = one-byte XOR key (response byte 1)
```

### 2. Connect to the panel (`cmd 0xE5`)

The whole packet is XORed with `KK`. Nothing after it is.

Guardian (`ISECNetServerProtocol.assembleConnectionCommand`):

```
12 E5 05 <device id: 8 bytes> <panel MAC: 6 bytes> 00 <path> <chk>    ^ KK
   │  └─ client type: 5 = Guardian (2 = old Android)
   └─ len 18
path: 0x45 'E' = Ethernet, 0x47 'G' = SIM 1 (AMT Mobile also has 0x48 'H' = SIM 2)
```

AMT Mobile V3 (`ProtocoloServidorAMT.montaPacoteConexao`):

```
LL E5 06 <app UUID: 8 bytes> <panel MAC: 6 bytes> <chk of token>
      <path> 00 00 00 00 03 <language id> <Firebase push token, ASCII…> <chk>   ^ KK
```

The push token registers the phone for event notifications. The connect packet
carries **no password and no account credential**. The relay identifies the
panel by MAC only.

If the Ethernet path answers "panel not connected", both apps retry with the
SIM path.

### 3. Relay answer (byte 0)

| Byte | Meaning (`ISECNetServerResponse`) |
|------|-----------------------------------|
| `FE` | connected |
| `45` | connected via Ethernet |
| `47` | connected via GPRS |
| `E4` | panel not connected to the relay |
| `E6` | checksum mismatch |
| `E8` | panel busy with another client |

### 4. Talk to the panel

After `FE`/`45`/`47`, the app sends normal `E9` "ISECMobile" frames through the
relay, **unencrypted**:

```
[len] E9 21 <panel password, ASCII> <cmd…> 21 <chk>
```

The command table is in PROTOCOL.md (Guardian section). The panel answers
`FE` (ok) or one of:

| Byte | Meaning (`ISECNetResponse`) |
|------|-----------------------------|
| `E0` | invalid packet |
| `E1` | wrong password |
| `E2` | invalid command |
| `E3` | panel has no partitions |
| `E4` | open zones |
| `E5` | command deprecated |
| `E6` | bypass not allowed |
| `E7` | deactivation not allowed |
| `E8` | bypass not allowed while armed |
| `FF` | invalid model |

A single-byte reply `E8` from the relay means another client holds the panel.

### Worked example (Guardian, illustrative values)

Device ID `00 11 22 33 44 55 66 77`, panel MAC `02:00:00:AB:CD:EF`, relay key
`0x5A`, panel password `1234`. Frames generated with the same checksum code as
the client; the key and reply bytes are made up, since nothing was captured
from the real relay.

```
→ 01 FB 05                                   key request (always these 3 bytes)
← .. 5A ..                                   key = response byte 1 → 0x5A

  12 E5 05 00 11 22 33 44 55 66 77            connect, before XOR:
  02 00 00 AB CD EF 00 45 C3                    len 18, E5, type 05 (Guardian),
                                                device id, MAC, 00, path 'E', chk
→ 48 BF 5F 5A 4B 78 69 1E 0F 3C 2D 58         the same packet XOR 0x5A, as sent
  5A 5A F1 97 B5 5A 1F 99
← 45                                         connected via Ethernet

→ 08 E9 21 31 32 33 34 5B 21 41              complete status, password in clear
← 39 E9 …                                    ≥ 57-byte status (layout in PROTOCOL.md)
```

Through a monitoring company's IP receiver (account `1234`), no XOR:

```
→ 02 E0 01 1C                                get-byte
→ 06 E4 45 31 32 33 34 5C                    connect via Ethernet, account "1234"
← .. .. 01 ..                                byte 2 = 01 → connected
```

### Other relay commands (AMT Mobile V3)

| Cmd | Packet | Purpose |
|-----|--------|---------|
| `E8` | `0F E8 <Android ID: 8 bytes> <MAC: 6 bytes> <chk>` | Unregister this phone's push token for a panel |
| `C1` | `11 C1 <Android ID, 16 ASCII> <chk>` | Unregister all tokens of this phone (first start) |
| `C6` | `12 C6 <0/1> <8 bytes> <chk>` | Record terms-of-use choice |
| `F1` | `13 F1 <type> <index> <name, 16 bytes, 00-padded> <chk>` | Sync display names. Type 1 zones, 2 users, 3 devices, 4 panel, 5 PGM (PGM adds the Android ID) |

### Via a monitoring company's IP receiver instead

Same idea, without the XOR step:

```
app → 02 E0 01 <chk>                          get-byte
app → 06 E4 <path E|G> <account, 4 ASCII> <chk>   connect (account = monitoring account)
app ← byte 2 == 01 → connected
```

then the same `E9` frames.

## AMT 8000 relay (ISECNet v2, summary)

`ISECNetV2ServerProtocol`: server-connect, app-connect (alarm name, MAC, path),
then the panel's own v2 auth frame (`0xF0F0` with the password digits) and v2
commands. The XOR key step and plain TCP are the same. Port 9009 first, then
two fallbacks (one is 80). The LAN finds these panels by UDP multicast
(17764 → 17765).

## Guardian REST API (`https://api-guardian.intelbras.com.br:8443/`)

There is no public OpenAPI/Swagger description of this API: none is referenced
in the apps, and none is published on Intelbras' site (searched 2026-11-24).
Intelbras sells a separate IoT API subscription ("GDI", *Gestão de
Dispositivos IoT*); whether it covers alarm panels is unknown. The unofficial
[guardian-api-intelbras](https://github.com/bobaoapae/guardian-api-intelbras)
project wraps this API and also uses an event stream (server-sent events) not
covered here. Everything below is reconstructed from the app's Retrofit
interface and Moshi models.

Login: OpenID Connect against the Intelbras account (WSO2,
redirect `br.com.intelbras.guardian:/oauth2redirect`), then
`POST api/v2/auth/mobile/login/`. Other session calls:
`POST api/v1/auth/mobile/logged/`, `POST api/v2/auth/mobile/logout/`,
`POST api/v2/auth/mobile/{mobileId}/refresh-firebase-token`.

Alarm-related endpoints (`GuardianClient`):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `api/v2/alarm-centrals` | Panels saved on the account |
| POST | `api/v2/alarm-centrals` | Save a panel |
| PATCH | `api/v2/alarm-centrals/{id}` | Update a saved panel |
| DELETE | `api/v2/alarm-centrals/{id}` | Remove a panel |
| POST | `api/v2/alarm-centrals/temp/add-modules/{id}` | Add modules |
| GET | `api/v2/events`, `api/v2/events/history`, `api/v2/events/notifications` | Event and push history (paginated: `offset`, `limit`) |
| GET/PUT | `api/v1/guardian/mobile/settings/` | App settings |
| GET/POST/… | `api/v2/devices/groups…`, `api/v2/devices-association/camera-to-zones…` | Groups, camera-to-zone links |

The other ~50 endpoints cover cameras, cloud recording, access control and
reseller branding.

Panel JSON (`AlarmDeviceModel` / `AlarmRequestModel`, Moshi names):

```
id, central_mac, alarm_model, password, description, zones, pgms,
connections, ip_receiver_server_addr, ip_receiver_server_port,
ip_receiver_server_account, ip, remote_password, partitions, group,
permissions
```

`password` and `remote_password` are **not** marked transient, so saving a
panel in Guardian uploads both passwords to the account backend (over HTTPS).

### Requests and responses

Shapes come from the app's Moshi models (`@Json` names); values are
illustrative. JSON field names are snake_case. Every call carries the access
token from the Intelbras account login in an `Authorization` header (the app
stores the full header value; no prefix is added by the client code).

**Token refresh** (`POST https://api.conta.intelbras.com/auth/token`,
form-encoded):

```
refresh_token=<refresh token>&client_id=<app client id>&grant_type=refresh_token
```
```json
{ "access_token": "…" }
```

**Register the phone** after the account login (`POST api/v2/auth/mobile/login/`;
`POST api/v1/auth/mobile/logged/` takes the same body; both return no content):

```json
{
  "mobile_id": "a1b2c3d4e5f60718",
  "firebase_id": "<Firebase push token>",
  "mobile_name": "My phone",
  "mobile_model": "Pixel 8"
}
```

`POST api/v2/auth/mobile/logout/` → `{ "mobile_id": "…" }`.
`POST api/v2/auth/mobile/{mobile_id}/refresh-firebase-token` → `{ "firebase_id": "…" }`.

**List / save panels** (`GET` / `POST api/v2/alarm-centrals`,
`PATCH api/v2/alarm-centrals/{id}`): requests and responses use the panel
object; `GET`, `POST` and `PATCH` all return a list of them.

```json
[
  {
    "id": 42,
    "central_mac": "020000ABCDEF",
    "alarm_model": 97,
    "description": "Home",
    "password": "1234",
    "remote_password": "878787",
    "ip": "127.0.0.1",
    "connections": {
      "is_cloud_enabled": true,
      "is_ip_receiver_server_enabled": false
    },
    "ip_receiver_server_addr": "",
    "ip_receiver_server_port": "",
    "ip_receiver_server_account": "",
    "zones":      [ { "id": 1, "index": 0, "position": 0, "name": "Zone 1", "friendly_name": "Front door" } ],
    "partitions": [ { "id": 1, "index": 0, "name": "A", "friendly_name": "House" } ],
    "pgms":       [ { "id": 1, "index": 0, "name": "PGM 1", "friendly_name": "Gate" } ],
    "group": null,
    "permissions": { "active": true, "zones": [ … ], "partitions": [ … ], "pgms": [ … ] }
  }
]
```

`alarm_model` is the model code from the README table (`0x61` = 97 for the
AMT 1016 NET). `PATCH` takes the same object without `central_mac`
(`AlarmRequestModel`). `DELETE api/v2/alarm-centrals/{id}` returns no content.

**Event history** (`GET api/v2/events?offset=0&limit=250`), paginated:

```json
{
  "count": 1,
  "next": null,
  "previous": null,
  "results": [
    {
      "id": 1001,
      "event": { … },
      "timestamp": "2026-11-24T00:02:00Z",
      "event_real_time": "…",
      "alarm_central": 42,
      "alarm_partition": 1,
      "alarm_user": 3,
      "zone": 5,
      "zone_code": "…",
      "event_index": 17,
      "notification": { … },
      "camera": null,
      "video_device_id": null,
      "dvr_time": null,
      "url_thumb": null,
      "num_pictures": 0,
      "created": "2026-11-24T00:02:01Z"
    }
  ]
}
```

The same `count`/`next`/`previous`/`results` envelope is used by
`api/v2/events/history` (`offset`, `limit`, `device_type`) and
`api/v2/devices/groups`. `api/v2/events/notifications` adds `start_time` and
`end_time` and defaults to `limit=200`.

**Settings** (`GET`/`PUT api/v1/guardian/mobile/settings/`):
`{ "client_id": "…", "data": { … } }`, where `data` is a free-form app
settings object.

**Errors**: `{ "code": 4007, "message": "…" }`. On HTTP 401 the app refreshes
the token and retries once. With error code `4007` it logs the user out
instead of refreshing.

## Security observations

* **No TLS on the relay.** Every `E9` frame carries the panel password in
  plain ASCII across the internet. The only "encryption" is a one-byte XOR on
  the connect packet, with the key sent in clear just before.
* **Panel passwords are stored in the Guardian account** (`password`,
  `remote_password` fields above).
* The relay identifies panels by MAC, and anyone on the LAN can read the MAC
  with the unauthenticated discovery probe (PROTOCOL.md). Commands still need
  the panel password, which is the real protection: keep it non-default
  (`878787` is the app default and the siren-short reset value).
* Both apps ship hardcoded credentials for Intelbras' camera P2P services.
  They are not reproduced here.

Using the local `E7` client instead of the cloud avoids all of the above, as
long as the panel's "cloud" connection stays disabled.
