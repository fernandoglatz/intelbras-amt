"""Command line interface: ``intelbras-amt <command>`` / ``python -m intelbras_amt``.

Only send a command your panel model supports: an AMT 1016 NET sent the
Smart-only "connections" command stopped answering on the network.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from . import protocol_v2 as p2
from .client import AmtClient, AmtError, discover, discover_network, e9_request
from .client_v2 import AmtV2Client, open_panel
from .config import ConfigError, load_settings
from .decode import OpenZonesError, Status
from .decode_v2 import StatusV2
from .protocol import E9_READ_ONLY, MENU_SIREN_STATUS, UNIVERSAL_READS, Cmd, FrameError
from .protocol_v2 import V2CommandError

EXIT_OK, EXIT_ERROR, EXIT_NEEDS_CONFIRMATION = 0, 1, 2
NOT_READ = "not read (--quick)"

# Commands that change the panel: each one needs --yes.
WRITE_COMMANDS = {
    "arm", "disarm", "silence", "pgm", "bypass", "clear-triggered",
    "set-clock", "eeprom-write", "bus-search", "panic",
}

# Which protocol family each command belongs to. A command is never sent to a
# panel of the other family: with --protocol it is refused before connecting,
# with "auto" right after the refresh that identifies the family.
V1_ONLY = {
    "problems", "mac", "pgm-state", "eeprom", "bus-devices", "connections", "network",
    "cell", "wireless", "clear-triggered", "set-clock", "eeprom-write", "bus-search", "raw", "e9",
}
V2_ONLY = {"info", "panic", "raw2"}


def command_families(command: str) -> set[str]:
    if command in V1_ONLY:
        return {"v1"}
    if command in V2_ONLY:
        return {"v2"}
    return {"v1", "v2"}


def _partition(value: str) -> int:
    letters = {"a": 1, "b": 2, "c": 3, "d": 4}
    if value.lower() in letters:
        return letters[value.lower()]
    if value.isdigit() and 1 <= int(value) <= 16:
        return int(value)
    raise argparse.ArgumentTypeError("partition must be A-D or 1-16 (1-16 on ISECNet v2)")


def _v2_command(value: str) -> int:
    try:
        code = int(value, 16)
    except ValueError:
        code = -1
    if not 0 <= code <= 0xFFFF:
        raise argparse.ArgumentTypeError("v2 command must be hex 0000-FFFF, e.g. 0b4a")
    return code


def _int(value: str) -> int:
    return int(value, 0)


def _hex(value: str) -> bytes:
    try:
        data = bytes.fromhex(value.replace(":", " "))
    except ValueError:
        raise argparse.ArgumentTypeError("expected hex bytes, e.g. '17' or '12 02 a3 01'") from None
    if not data:
        raise argparse.ArgumentTypeError("expected at least one byte")
    return data


def parse_zones(text: str) -> list[int]:
    """'1,3,5-8' -> [1, 3, 5, 6, 7, 8]."""
    zones: set[int] = set()
    for part in filter(None, (p.strip() for p in text.split(","))):
        if "-" in part:
            low, high = (int(x) for x in part.split("-", 1))
            if low > high:
                raise ValueError(f"bad zone range {part}")
            zones.update(range(low, high + 1))
        else:
            zones.add(int(part))
    return sorted(zones)


def _zones_arg(value: str) -> list[int]:
    try:
        return parse_zones(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"bad zone list: {exc}") from None


def _when(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M")
    except ValueError:
        raise argparse.ArgumentTypeError("time must look like '2026-11-24 13:05'") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="intelbras-amt", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", help="panel IP (env AMT_HOST)")
    parser.add_argument("--port", type=int, help="panel port (env AMT_PORT, default 9009)")
    parser.add_argument("--password", help="remote-access password (prefer env AMT_PASSWORD)")
    parser.add_argument("--env-file", type=Path, help="settings file (default ./.env)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--protocol", choices=("auto", "v1", "v2"),
        help="panel family (env AMT_PROTOCOL, default auto): v1 = AMT 1016/2018/Smart/4010, v2 = AMT 8000/ANM 24 NET",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def write(name: str, help_text: str) -> argparse.ArgumentParser:
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("--yes", action="store_true", help="really send the command")
        return cmd

    # reads
    status = sub.add_parser("status", help="armed state, zones, voltages, problems")
    status.add_argument("--quick", action="store_true", help="only the status request")
    sub.add_parser("problems", help="active problems")
    sub.add_parser("mac", help="panel MAC address")
    sub.add_parser("pgm-state", help="siren and PGM 1-3 state")
    eeprom = sub.add_parser("eeprom", help="read raw EEPROM bytes")
    eeprom.add_argument("address", type=_int)
    eeprom.add_argument("count", type=_int)
    sub.add_parser("bus-devices", help="keypads and receivers on the bus (4010 Smart and Smart models ONLY)")
    sub.add_parser("connections", help="links to monitoring and cloud (Smart models ONLY: hung an AMT 1016 NET)")
    sub.add_parser("network", help="IP, mask, gateway, DNS and MAC (Smart models ONLY)")
    sub.add_parser("cell", help="cellular module, signal, SIM, carrier, ICCID, IMEI (Smart models ONLY)")
    sub.add_parser("wireless", help="wireless sensors: battery, tamper, signal (Smart models ONLY, fw 1.80+)")
    disc = sub.add_parser("discover", help="find panels without a password (host or network, e.g. 192.168.1.0/24)")
    disc.add_argument("target", nargs="?", help="IP or CIDR network (default: AMT_HOST)")
    disc.add_argument("--timeout", type=float, default=1.0)

    # writes
    for name, help_text in (("arm", "arm the panel or one partition"), ("disarm", "disarm the panel or one partition")):
        cmd = write(name, help_text)
        cmd.add_argument("--partition", type=_partition, help="A-D, or 1-16 on v2 (default: whole panel)")
        cmd.add_argument("--stay", action="store_true", help="stay mode (Smart models, 4010 Smart fw 5.7+)")
    write("silence", "silence a firing alarm (siren off)")
    pgm = write("pgm", "switch a PGM output: 1-3 on/off (checked), 4-19 toggle (4010 Smart)")
    pgm.add_argument("number", type=int, choices=range(1, 20), metavar="N")
    pgm.add_argument("action", choices=("on", "off", "toggle"))
    bypass = write("bypass", "change bypassed zones")
    group = bypass.add_mutually_exclusive_group(required=True)
    group.add_argument("--add", type=_zones_arg, metavar="ZONES", help="bypass these zones too, e.g. 3,5-7")
    group.add_argument("--remove", type=_zones_arg, metavar="ZONES", help="stop bypassing these zones")
    group.add_argument("--set", type=_zones_arg, metavar="ZONES", help="bypass exactly these zones")
    group.add_argument("--clear", action="store_true", help="bypass no zones")
    write("clear-triggered", "clear the triggered-zone memory")
    clock = write("set-clock", "set the panel clock (default: this computer's time)")
    clock.add_argument("--time", type=_when, help="'YYYY-MM-DD HH:MM'")
    ewrite = write("eeprom-write", "write configuration memory (protected areas refused, verified)")
    ewrite.add_argument("address", type=_int)
    ewrite.add_argument("data", type=_hex, help="hex bytes, e.g. '00' or '01 02'")
    write("bus-search", "make the panel scan its keypad/receiver bus (4010 Smart ONLY)")

    # low level
    raw = sub.add_parser("raw", help="send any E7 command (hex, command byte first); unknown commands can hang the panel")
    raw.add_argument("data", type=_hex)
    raw.add_argument("--yes", action="store_true", help="needed unless it is a read every model supports")
    e9 = sub.add_parser("e9", help="send one E9 frame (the cloud apps' format); old firmware only ACKs it")
    e9.add_argument("data", type=_hex, help="command bytes, e.g. '5a' (partial status)")
    e9.add_argument("--yes", action="store_true", help="needed unless the command only reads")

    # ISECNet v2 only (AMT 8000 family, ANM 24 NET)
    sub.add_parser("info", help="v2: model and firmware (INFO)")
    panic = write("panic", "v2: trigger a panic alarm (AMT 8000 family)")
    panic.add_argument("kind", choices=tuple(p2.PANIC_TYPES))
    raw2 = sub.add_parser("raw2", help="v2: send any v2 command (command hex, optional payload hex)")
    raw2.add_argument("command_code", type=_v2_command, metavar="COMMAND", help="e.g. 0b4a")
    raw2.add_argument("payload", type=_hex, nargs="?", default=b"", help="payload hex, e.g. 'ff 01'")
    raw2.add_argument("--yes", action="store_true", help="needed unless the command only reads")
    return parser


def format_status(st: Status) -> str:
    def zones(values) -> str:
        return ", ".join(map(str, values)) or "none"

    def stay(value) -> str:
        return "" if value is None else (" (stay)" if value else "")

    armed_text = "yes" if st.armed else "partial" if any(p.armed for p in st.partitions) else "no"
    lines = [
        f"Model:      {st.model} (firmware {st.firmware})",
        f"Armed:      {armed_text}{stay(st.stay_armed)} (mask 0x{st.armed_mask:02X})",
    ]
    lines += [f"  {p.name}: {'armed' if p.armed else 'disarmed'}{stay(p.stay_armed)}" for p in st.partitions]
    if st.partitioned is not None:
        lines.append(f"Partitioned: {'yes' if st.partitioned else 'no'}")
    if st.alarm_firing is not None:
        lines.append(f"Alarm firing: {'YES' if st.alarm_firing else 'no'}")
    lines += [
        f"Open zones: {zones(st.open_zones)}",
        f"Triggered:  {zones(st.triggered_zones)}",
        f"Bypassed:   {NOT_READ if st.bypassed_zones is None else zones(st.bypassed_zones)}",
    ]
    if st.enabled_zones is not None:
        lines.append(f"Enabled:    {zones(st.enabled_zones)}")
        lines.append(f"Stay zones: {zones(st.stay_zones)}")
        lines.append(f"Wireless:   {zones(st.wireless_zones)}")
    lines += [
        f"AC supply:  {st.ac_voltage:.2f} V",
        f"Battery:    {st.battery_voltage:.2f} V",
        f"Clock:      {st.clock or 'invalid'}",
    ]
    if st.pgm:
        lines.append("PGM:        " + ", ".join(f"{k}={'on' if v else 'off'}" for k, v in st.pgm.items()))
    if st.problems is None:
        lines.append(f"Problems:   {NOT_READ}")
    else:
        lines.append("Problems:   " + ("; ".join(st.problems) or "none"))
    return "\n".join(lines)


def _emit(args: argparse.Namespace, payload, text: str) -> None:
    print(json.dumps(payload, indent=2) if args.format == "json" else text)


def _kv(data: dict) -> str:
    return "\n".join(f"{k}: {v}" for k, v in data.items())


def _describe(args: argparse.Namespace) -> str:
    """What a write command would do, for the confirmation message."""
    if args.command in ("arm", "disarm"):
        target = f"partition {'ABCD'[args.partition - 1]}" if args.partition else "the whole panel"
        return f"{args.command} {target}{' in stay mode' if args.stay else ''}"
    if args.command == "pgm":
        return f"switch PGM {args.number} {args.action}"
    if args.command == "bypass":
        mode, zones = next(
            ((m, z) for m, z in (("add", args.add), ("remove", args.remove), ("set", args.set)) if z is not None),
            ("set", []),
        )
        if args.clear or (mode == "set" and not zones):
            return "un-bypass every zone"
        return f"{mode} bypass for zones {', '.join(map(str, zones)) or 'none'}"
    if args.command == "set-clock":
        return f"set the clock to {(args.time or datetime.now()).strftime('%Y-%m-%d %H:%M')}"
    if args.command == "eeprom-write":
        return f"write {args.data.hex(' ')} at EEPROM {args.address}"
    if args.command in ("raw", "e9"):
        return f"send {args.command.upper()} command {args.data.hex(' ')}"
    if args.command == "raw2":
        return f"send v2 command 0x{args.command_code:04X} {args.payload.hex(' ')}".rstrip()
    if args.command == "panic":
        return f"trigger a {args.kind} panic alarm"
    return {
        "silence": "silence the alarm",
        "clear-triggered": "clear the triggered-zone memory",
        "bus-search": "start a bus device search",
    }[args.command]


def _needs_confirmation(args: argparse.Namespace) -> bool:
    if args.command in WRITE_COMMANDS:
        return not args.yes
    if args.command == "raw":
        # Only reads every model supports go without --yes; model-specific
        # reads can hang a panel that does not know them.
        safe = args.data[0] in UNIVERSAL_READS or args.data[:2] == bytes([Cmd.MENU_FUNCTIONS, MENU_SIREN_STATUS])
        return not safe and not args.yes
    if args.command == "e9":
        return args.data[0] not in E9_READ_ONLY and not args.yes
    if args.command == "raw2":
        return args.command_code not in p2.READ_ONLY and not args.yes
    return False


def _run_discover(args: argparse.Namespace) -> int:
    settings = load_settings(args.host, args.port, None, args.env_file, require_host=False, require_password=False)
    target = args.target or settings.host
    if not target:
        raise ConfigError("give an IP or network to scan, or set AMT_HOST")
    if "/" in target:
        found = discover_network(target, port=settings.port, timeout=args.timeout)
    else:
        one = discover(target, port=settings.port, timeout=args.timeout)
        found = [one] if one else []
    text = "\n".join(f"{f['host']}  {f['mac']}  {f['model'] or '?'}" for f in found) or "no panel found"
    _emit(args, found, text)
    return EXIT_OK


def run(args: argparse.Namespace) -> int:
    if _needs_confirmation(args):
        print(f"Would {_describe(args)}. Re-run with --yes to send it.", file=sys.stderr)
        return EXIT_NEEDS_CONFIRMATION
    if args.command == "discover":
        return _run_discover(args)

    settings = load_settings(args.host, args.port, args.password, args.env_file, protocol=args.protocol)
    families = command_families(args.command)
    if settings.protocol != "auto" and settings.protocol not in families:
        raise ConfigError(
            f"'{args.command}' is an ISECNet {'/'.join(sorted(families))} command, "
            f"but the panel is set to {settings.protocol}; nothing sent"
        )
    if args.command == "e9":
        if settings.protocol != "v1":
            raise ConfigError("e9 sends v1 cloud frames on its own connection; pass --protocol v1 to confirm the family")
        reply = e9_request(settings.host, settings.password, args.data, port=settings.port)
        payload = {"code": f"{reply.code:02X}", "error": reply.error, "body": reply.body.hex(" ")}
        _emit(args, payload, reply.error or ("ACK" if not reply.body else reply.body.hex(" ")))
        return EXIT_ERROR if reply.error else EXIT_OK

    client = open_panel(settings.host, settings.password, port=settings.port, protocol=settings.protocol, families=families)
    with client:
        if isinstance(client, AmtV2Client):
            return _run_session_v2(args, client)
        return _run_session(args, client)


def _run_session(args: argparse.Namespace, client: AmtClient) -> int:
    c = args.command
    if c == "status":
        st = client.status(full=not args.quick)
        _emit(args, st.to_dict(), format_status(st))
    elif c == "problems":
        problems = client.problems()
        _emit(args, problems, "\n".join(problems) or "no problems")
    elif c == "mac":
        mac = client.mac()
        _emit(args, {"mac": mac}, mac)
    elif c == "pgm-state":
        state = client.pgm_state()
        _emit(args, state, _kv({k: "on" if v else "off" for k, v in state.items()}))
    elif c == "eeprom":
        data = client.read_eeprom(args.address, args.count)
        _emit(args, {"address": args.address, "hex": data.hex(" ")}, data.hex(" "))
    elif c == "bus-devices":
        devices = client.bus_devices()
        _emit(args, devices, _kv(devices))
    elif c == "connections":
        info = client.connections()
        _emit(args, info, _kv(info))
    elif c == "network":
        info = client.network_card()
        _emit(args, info, _kv(info))
    elif c == "cell":
        info = client.cell_card()
        _emit(args, info, _kv(info))
    elif c == "wireless":
        sensors = client.wireless_sensors()
        _emit(args, sensors, "\n".join(_kv(s).replace("\n", ", ") for s in sensors) or "no wireless sensors")
    elif c in ("arm", "disarm"):
        st = client.set_armed(c == "arm", args.partition, stay=args.stay)
        _emit(args, st.to_dict(), format_status(st))
    elif c == "silence":
        client.silence_alarm()
        _emit(args, {"silenced": True}, "alarm silenced")
    elif c == "pgm":
        if args.action == "toggle" or args.number > 3:
            if args.action != "toggle":
                raise ValueError("PGM 4-19 cannot report their state: use 'toggle'")
            client.toggle_pgm(args.number)
            _emit(args, {"pgm": args.number, "toggled": True}, f"PGM {args.number} toggled")
        else:
            state = client.set_pgm(args.number, args.action == "on")
            _emit(args, state, _kv({k: "on" if v else "off" for k, v in state.items()}))
    elif c == "bypass":
        current = set(client.bypassed_zones())
        if args.clear:
            wanted = set()
        elif args.set is not None:
            wanted = set(args.set)
        elif args.add is not None:
            wanted = current | set(args.add)
        else:
            wanted = current - set(args.remove)
        now = client.set_bypassed(wanted)
        _emit(args, {"bypassed_zones": now}, "bypassed: " + (", ".join(map(str, now)) or "none"))
    elif c == "clear-triggered":
        client.clear_triggered()
        _emit(args, {"cleared": True}, "triggered-zone memory cleared")
    elif c == "set-clock":
        when = client.set_clock(args.time)
        _emit(args, {"clock": when.strftime("%Y-%m-%d %H:%M")}, f"clock set to {when:%Y-%m-%d %H:%M}")
    elif c == "eeprom-write":
        before = client.write_eeprom(args.address, args.data)
        payload = {"address": args.address, "before": before.hex(" "), "after": args.data.hex(" ")}
        _emit(args, payload, f"{args.address}: {before.hex(' ')} -> {args.data.hex(' ')}")
    elif c == "bus-search":
        ok = client.search_bus()
        _emit(args, {"started": ok}, "bus search started" if ok else "panel refused the bus search")
        return EXIT_OK if ok else EXIT_ERROR
    elif c == "raw":
        frame = client.raw(args.data)
        _emit(args, {"answer": f"{frame.command:02X}", "data": frame.data.hex(" ")}, frame.data.hex(" "))
    return EXIT_OK


def format_status_v2(st: StatusV2) -> str:
    def zones(values) -> str:
        return ", ".join(map(str, values)) or "none"

    lines = [
        f"Model:      {st.model} (firmware {st.firmware})",
        f"State:      {st.state}",
    ]
    lines += [
        f"  Partition {p.id}: {'stay' if p.stay else 'armed' if p.armed else 'disarmed'}{' FIRING' if p.firing else ''}"
        for p in st.partitions
    ]
    lines += [
        f"Partitioned: {'yes' if st.partitioned else 'no'}",
        f"Alarm firing: {'YES' if st.firing else 'no'}",
        f"Open zones: {zones(st.open_zones)}",
        f"Triggered:  {zones(st.violated_zones)}",
        f"Bypassed:   {zones(st.bypassed_zones)}",
    ]
    if st.tamper_zones or st.low_battery_zones or st.communication_error_zones:
        lines += [
            f"Tamper:     {zones(st.tamper_zones)}",
            f"Low battery zones: {zones(st.low_battery_zones)}",
            f"Comm. errors: {zones(st.communication_error_zones)}",
        ]
    lines.append(f"Clock:      {st.clock or 'unknown'} (raw {st.clock_raw})")
    if st.battery:
        lines.append(f"Battery:    {st.battery}")
    if st.pgm:
        on = [str(n) for n, v in st.pgm.items() if v]
        lines.append(f"PGM on:     {', '.join(on) or 'none'}")
    return "\n".join(lines)


def _run_session_v2(args: argparse.Namespace, client: AmtV2Client) -> int:
    c = args.command
    if c == "info":
        info = client.info()
        _emit(args, info.to_dict(), _kv(info.to_dict()))
    elif c == "status":
        st = client.status()
        _emit(args, st.to_dict(), format_status_v2(st))
    elif c in ("arm", "disarm"):
        st = client.set_armed(c == "arm", args.partition, stay=args.stay)
        _emit(args, st.to_dict(), format_status_v2(st))
    elif c == "silence":
        client.silence_alarm()
        _emit(args, {"silenced": True}, "siren off")
    elif c == "panic":
        client.panic(args.kind)
        _emit(args, {"panic": args.kind}, f"{args.kind} panic triggered")
    elif c == "pgm":
        if args.action == "toggle":
            raise ValueError("v2 PGMs are switched on/off explicitly: use 'on' or 'off'")
        state = client.set_pgm(args.number, args.action == "on")
        _emit(args, {str(k): v for k, v in state.items()}, f"PGM {args.number} {args.action}")
    elif c == "bypass":
        current = set(client.status().bypassed_zones)
        if args.clear:
            wanted = set()
        elif args.set is not None:
            wanted = set(args.set)
        elif args.add is not None:
            wanted = current | set(args.add)
        else:
            wanted = current - set(args.remove)
        now = sorted(current)
        if wanted - current:
            now = client.set_bypass(wanted - current, True)
        if current - wanted:
            now = client.set_bypass(current - wanted, False)
        _emit(args, {"bypassed_zones": now}, "bypassed: " + (", ".join(map(str, now)) or "none"))
    elif c == "raw2":
        frame = client.raw(args.command_code, args.payload)
        payload = {"command": f"{frame.command:04X}", "payload": frame.payload.hex(" ")}
        _emit(args, payload, f"{frame.command:04X} {frame.payload.hex(' ')}".rstrip())
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except (ConfigError, AmtError, FrameError, OpenZonesError, V2CommandError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
