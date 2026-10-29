"""Numeric OS observations; commands use fixed paths/arguments and the existing bounded runner."""
import ipaddress
import json
import os
import platform
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from .core import ScannerError, run_bounded
from .lan import MAX_BYTES, Stopped, check


def command(paths, args, deadline, cancel):
    check(deadline, cancel)
    binary = next((p for p in paths if Path(p).is_file()), None)
    if binary is None:
        raise NotImplementedError
    try:
        code, out, err = run_bounded([binary, *args], max(0.001, deadline - time.monotonic()), MAX_BYTES, cancel=cancel)
    except ScannerError:
        check(deadline, cancel)  # the runner stopped for a cancel or the deadline: report that, not a failed read
        raise
    check(deadline, cancel)
    if code or err or len(out.encode("utf-8")) >= MAX_BYTES:
        raise ScannerError("LAN OS observations could not be read completely")
    return out


def snapshot(interface, deadline, cancel):
    system = platform.system()
    if system == "Linux":
        ip = ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip")
        links = json.loads(command(ip, ["-j", "-d", "link", "show", "dev", interface], deadline, cancel))
        addresses = json.loads(command(ip, ["-j", "addr", "show", "dev", interface], deadline, cancel))
        routes = []
        for family in ("-4", "-6"):
            routes += json.loads(command(ip, ["-j", family, "route", "show", "dev", interface], deadline, cancel))
        link = links[0]
        facts = [a for obj in addresses for a in obj["addr_info"] if a.get("family") in {"inet", "inet6"}]
        # A physical device backing the interface is required; bridges/tunnels have no device.
        physical = (Path("/sys/class/net", interface, "device").exists()
                    and link.get("link_type") == "ether" and not link.get("linkinfo", {}).get("info_kind"))
        return {"physical": physical, "up": "UP" in link.get("flags", []) and "LOWER_UP" in link.get("flags", []),
                "index": link["ifindex"], "addresses": sorted(a["local"] for a in facts),
                "onlink": sorted({r["dst"] for r in routes if r.get("dst") not in (None, "default")
                    and not r.get("gateway") and r.get("type", "unicast") == "unicast"}), "mac": link.get("address")}
    if system == "Darwin":
        out = command(("/sbin/ifconfig",), [interface], deadline, cancel)
        return darwin_snapshot(interface, out, socket.if_nametoindex(interface))
    if system == "Windows":
        info = windows(deadline, cancel)
        link = next((a for a in info["adapters"] if str(a["InterfaceGuid"]).strip("{}").lower() == interface.strip("{}").lower()), None)
        if not link:
            raise ScannerError("Configured LAN adapter GUID was not found")
        index = link["ifIndex"]
        ips = [a for a in info["addresses"] if a["InterfaceIndex"] == index and a["AddressState"] in (4, "Preferred")]
        routes = [r for r in info["routes"] if r["InterfaceIndex"] == index and r["NextHop"] in ("0.0.0.0", "::")]
        return {"physical": bool(link["HardwareInterface"]) and link["InterfaceType"] in (6, 71),
                "up": link["Status"] in ("Up", 2), "index": index,
                "addresses": sorted(a["IPAddress"].split("%")[0] for a in ips),
                "onlink": sorted(r["DestinationPrefix"] for r in routes if r["DestinationPrefix"] not in ("0.0.0.0/0", "::/0")),
                "mac": link.get("MacAddress")}
    raise NotImplementedError


def darwin_snapshot(interface, out, index):
    # ifconfig reports connected address/netmask pairs; no route lookup can turn them into a remote range.
    first = out.splitlines()[0]
    ips, nets = [], []
    for line in out.splitlines()[1:]:
        fields = line.split()
        if fields and fields[0] == "inet" and len(fields) >= 4 and fields[2] == "netmask":
            bits = int(fields[3], 16)
            mask = f"{bits:032b}"
            if "01" in mask:
                raise ValueError("Noncontiguous netmask")
            ip = ipaddress.ip_address(fields[1]); ips.append(str(ip))
            nets.append(str(ipaddress.ip_network(f"{ip}/{mask.count('1')}", strict=False)))
        if fields and fields[0] == "inet6" and "prefixlen" in fields:
            ip = ipaddress.ip_address(fields[1].split("%")[0]); ips.append(str(ip))
            nets.append(str(ipaddress.ip_network(f"{ip}/{fields[fields.index('prefixlen') + 1]}", strict=False)))
    return {"physical": bool(re.fullmatch(r"en[0-9]+", interface)) and "ether " in out
            and "media:" in out and not re.search(r"\b(?:bridge|member|tunnel):", out),
            "up": "<UP," in first and "status: active" in out,
            "index": index, "addresses": sorted(ips), "onlink": sorted(nets),
            "mac": next((line.split()[1] for line in out.splitlines() if line.strip().startswith("ether ")), None)}


# No user/network text is interpolated into this fixed script. All objects are filtered in Python.
WINDOWS_SCRIPT = """$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new();
$v=@{adapters=@(Get-NetAdapter -Physical | Select-Object InterfaceGuid,ifIndex,HardwareInterface,InterfaceType,Status,MacAddress);
addresses=@(Get-NetIPAddress | Select-Object InterfaceIndex,IPAddress,AddressState);
routes=@(Get-NetRoute | Select-Object InterfaceIndex,DestinationPrefix,NextHop);
neighbors=@(Get-NetNeighbor | Select-Object InterfaceIndex,IPAddress,LinkLayerAddress,State)};
ConvertTo-Json -InputObject $v -Depth 4 -Compress"""


def windows(deadline, cancel):
    # Never trust PATH or an environment-specified SystemRoot for selecting an executable.
    import ctypes
    buf = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buf, len(buf))
    if not 0 < length < len(buf):
        raise OSError
    binary = str(Path(buf.value) / "WindowsPowerShell/v1.0/powershell.exe")
    return json.loads(command((binary,), ["-NoProfile", "-NonInteractive", "-Command", WINDOWS_SCRIPT], deadline, cancel).lstrip("\ufeff"))


def mac(value):
    try:
        parts = value.replace("-", ":").lower().split(":")
        if len(parts) != 6 or any(not re.fullmatch("[0-9a-f]{1,2}", p) for p in parts):
            return None
        return ":".join(p.zfill(2) for p in parts)
    except AttributeError:
        return None


def neighbors(interface, snapshot, deadline, cancel):
    system, rows = platform.system(), []
    if system == "Linux":
        out = command(("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"),
                      ["-j", "neigh", "show", "dev", interface], deadline, cancel)
        for item in json.loads(out):
            states = item.get("state", [])
            if isinstance(states, str):
                states = [states]
            if set(s.upper() for s in states) & {"FAILED", "INCOMPLETE", "NOARP", "NONE"}:
                continue
            rows.append({"ip": item["dst"].split("%")[0], "mac": mac(item.get("lladdr")), "state": ",".join(states).lower()})
    elif system == "Darwin":
        arp = command(("/usr/sbin/arp",), ["-an"], deadline, cancel)
        ndp = command(("/usr/sbin/ndp",), ["-an"], deadline, cancel)
        rows = darwin_neighbors(interface, arp, ndp)
    elif system == "Windows":
        for item in windows(deadline, cancel)["neighbors"]:
            if item["InterfaceIndex"] != snapshot["index"] or item["State"] in (0, 1, "Unreachable", "Incomplete"):
                continue
            rows.append({"ip": item["IPAddress"].split("%")[0], "mac": mac(item.get("LinkLayerAddress")),
                         "state": str(item["State"]).lower()})
    else:
        raise NotImplementedError
    if len(rows) > 4096:
        raise ScannerError("Neighbor cache limit reached")
    now = datetime.now(timezone.utc).isoformat()
    return [{**row, "method": "neighbor_cache", "observed_at": now, "expires_at": None} for row in rows]


def darwin_neighbors(interface, arp, ndp):
    rows = []
    for line in arp.splitlines():
        match = re.fullmatch(r".*?\(([^)]+)\) at ([0-9a-fA-F:]+) on (\S+)(?: .*)?", line)
        if line.strip() and match is None and not re.fullmatch(r".*?\([^)]+\) at \(incomplete\) on \S+(?: .*)?", line):
            raise ScannerError("Unrecognized numeric ARP output")
        if match and match[3] == interface and mac(match[2]):
            rows.append({"ip": match[1], "mac": mac(match[2]), "state": "cached_unknown_age"})
    lines = ndp.splitlines()
    if lines and not ("Neighbor" in lines[0] and "Netif" in lines[0]):
        raise ScannerError("Unrecognized numeric neighbor output")
    for line in lines[1:]:
        fields = line.split()
        if fields and len(fields) < 5:
            raise ScannerError("Unrecognized numeric neighbor row")
        if len(fields) < 5 or fields[2] != interface or not mac(fields[1]) or fields[4] in {"I", "N"}:
            continue
        rows.append({"ip": fields[0].split("%")[0], "mac": mac(fields[1]), "state": fields[4]})
    return rows
