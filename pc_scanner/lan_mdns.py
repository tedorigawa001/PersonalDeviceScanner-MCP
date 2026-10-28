"""Bounded, interface-scoped multicast DNS observations."""
from __future__ import annotations

import ipaddress
import platform
import select
import socket
import struct
import time
from datetime import datetime, timezone

from .lan import MAX_BYTES, Stopped, address, in_scope

META = (b"_services", b"_dns-sd", b"_udp", b"local")
MAX_PACKETS, MAX_QUERIES, MAX_RECORDS, MAX_SERVICES = 2048, 256, 2048, 512


def name_at(packet, offset):
    """DNS compression is bounded, backward only, and never executes peer-provided names."""
    labels, end, jumps, length = [], None, 0, 0
    while True:
        if offset >= len(packet):
            raise ValueError("Truncated DNS name")
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Truncated pointer")
            pointer = ((size & 0x3F) << 8) | packet[offset + 1]
            if pointer >= offset or jumps >= 32:
                raise ValueError("Invalid DNS compression")
            if end is None:
                end = offset + 2
            offset, jumps = pointer, jumps + 1
            continue
        if size & 0xC0 or size > 63:
            raise ValueError("Invalid DNS label")
        offset += 1
        if size == 0:
            return tuple(labels), end if end is not None else offset
        if offset + size > len(packet):
            raise ValueError("Truncated DNS label")
        labels.append(packet[offset:offset + size].lower())
        length += size + 1
        if length > 254:
            raise ValueError("DNS name too long")
        offset += size


def records(packet):
    if len(packet) < 12:
        raise ValueError("Short DNS header")
    _, flags, qd, an, ns, ar = struct.unpack_from("!6H", packet)
    if not flags & 0x8000 or flags & 0x7A0F or qd > 128 or an + ns + ar > 512:
        raise ValueError("Not a complete mDNS answer")
    offset, found = 12, []
    for _ in range(qd):
        _, offset = name_at(packet, offset)
        offset += 4
        if offset > len(packet):
            raise ValueError("Truncated question")
    for _ in range(an + ns + ar):
        name, offset = name_at(packet, offset)
        typ, cls, ttl, size = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        end = offset + size
        if end > len(packet):
            raise ValueError("Truncated resource record")
        value = None
        if cls & 0x7FFF == 1 and name and name[-1] == b"local":
            if typ in (1, 28) and size == (4 if typ == 1 else 16):
                value = str(ipaddress.ip_address(packet[offset:end]))
            elif typ == 12:
                value, used = name_at(packet, offset)
                if used != end:
                    raise ValueError("Invalid PTR length")
            elif typ == 33 and size >= 7:
                port = struct.unpack_from("!H", packet, offset + 4)[0]
                target, used = name_at(packet, offset + 6)
                if used != end:
                    raise ValueError("Invalid SRV length")
                value = (port, target)
        if value is not None:
            found.append((name, typ, min(ttl, 86400), value, bool(cls & 0x8000)))
        offset = end
    if offset != len(packet):
        raise ValueError("Unexpected DNS trailing bytes")
    return found


def wire(name):
    if not name or any(not 1 <= len(label) <= 63 for label in name) or sum(len(x) + 1 for x in name) > 254:
        raise ValueError("Invalid query name")
    return b"".join(bytes([len(label)]) + label for label in name) + b"\0"


def query(name, typ):
    # Standard multicast question. No arbitrary hostnames, TXT, unicast DNS, or service connections.
    return struct.pack("!6H", 0, 0, 1, 0, 0, 0) + wire(name) + struct.pack("!HH", typ, 1)


def service_type(name):
    return (len(name) == 3 and name[2] == b"local" and name[1] in (b"_tcp", b"_udp")
            and 2 <= len(name[0]) <= 63 and name[0].startswith(b"_")
            and all(c in b"abcdefghijklmnopqrstuvwxyz0123456789_-" for c in name[0]))


def display(name):
    return ".".join(label.decode("utf-8", "backslashreplace") for label in name)


class Answers:
    """Only linked PTR→SRV→address evidence becomes output; TXT and unrelated additionals never do."""
    def __init__(self):
        self.values = {}

    def add(self, incoming, now):
        flush = {(n, t) for n, t, ttl, v, f in incoming if f and ttl}
        for key in list(self.values):
            if (key[0], key[1]) in flush or self.values[key][0] <= now:
                self.values.pop(key)
        for name, typ, ttl, value, _ in incoming:
            key = (name, typ, value)
            if ttl == 0:
                self.values.pop(key, None)
            elif key in self.values or len(self.values) < MAX_RECORDS:
                self.values[key] = (now + ttl, now)
            else:
                raise Stopped("record_limit")

    def live(self, now):
        for key in list(self.values):
            if self.values[key][0] <= now:
                self.values.pop(key)
        return self.values

    def wanted(self, now):
        values = self.live(now)
        types = {v for (n, t, v) in values if n == META and t == 12 and service_type(v)}
        if len(types) > 32:
            raise Stopped("service_limit")
        instances = {(n, v) for n, t, v in values if t == 12 and n in types and len(v) == 4 and v[1:] == n}
        if len(instances) > MAX_SERVICES:
            raise Stopped("service_limit")
        wanted = {(META, 12)} | {(n, 12) for n in types} | {(v, 33) for _, v in instances}
        instance_names = {v for _, v in instances}
        for n, t, value in values:
            if t == 33 and n in instance_names:
                _, host = value
                if host and host[-1] == b"local":
                    wanted |= {(host, 1), (host, 28)}
        return wanted, instances

    def rows(self, spec, now):
        values = self.live(now)
        _, instances = self.wanted(now)
        rows, srv, ips = [], {}, {}
        for (owner, kind, value), times in values.items():
            if kind == 33:
                srv.setdefault(owner, []).append((value, times))
            elif kind in (1, 28) and in_scope(address(value), spec):
                ips.setdefault(owner, []).append((value, times))
        for typ, instance in sorted(instances):
            for value, (expires, received) in srv.get(instance, []):
                port, host = value
                if not port or not host or host[-1] != b"local":
                    continue
                for ip, (until, seen) in ips.get(host, []):
                    if len(rows) >= 4096:
                        raise Stopped("record_limit")
                    # Preserve the oldest piece of the relationship, not just the newest address.
                    ptr = self.values[(typ, 12, instance)]
                    rows.append({"ip": ip, "name": display(host), "method": "mdns", "state": "advertised",
                        "observed_at": datetime.fromtimestamp(min(received, seen, ptr[1]), timezone.utc).isoformat(),
                        "expires_at": datetime.fromtimestamp(min(expires, until, ptr[0]), timezone.utc).isoformat(),
                        "services": [{"type": display(typ), "instance": display(instance), "port": port}]})
        return rows


def open_socket(ip, index):
    """Require receive-interface ancillary data; never silently fall back to all interfaces."""
    system = platform.system()
    if system not in {"Darwin", "Linux", "Windows"} or (system != "Windows" and not hasattr(socket.socket, "recvmsg")):
        raise NotImplementedError("Scoped mDNS receive backend is unavailable")
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    s = socket.socket(family, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if system == "Darwin":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        if ip.version == 4:
            recv_if, recv_ttl = {"Darwin": (20, 24), "Linux": (8, 12), "Windows": (19, 21)}[system]
            s.setsockopt(socket.IPPROTO_IP, recv_if, 1)
            s.setsockopt(socket.IPPROTO_IP, recv_ttl, 1)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, ip.packed)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            if system == "Darwin":
                s.setsockopt(socket.IPPROTO_IP, 25, index)  # IP_BOUND_IF: egress is fixed, including unicast
            elif system == "Linux":
                # ip_mreqn includes the interface index, not only an address shared by multiple NICs.
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, struct.pack("=4s4si", b"\0" * 4, ip.packed, index))
            else:
                s.setsockopt(socket.IPPROTO_IP, 31, struct.pack("!I", index))  # IP_UNICAST_IF
                s.setsockopt(socket.IPPROTO_IP, 28, 1)  # IP_IFLIST (receive only on the allowlist)
                s.setsockopt(socket.IPPROTO_IP, 29, index)  # IP_ADD_IFLIST (DWORD in host byte order)
            s.bind(("", 5353))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                         socket.inet_aton("224.0.0.251") + ip.packed)
            destination = ("224.0.0.251", 5353)
        else:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.setsockopt(socket.IPPROTO_IPV6, 19 if system == "Windows" else socket.IPV6_RECVPKTINFO, 1)
            s.setsockopt(socket.IPPROTO_IPV6, 21 if system == "Windows" else socket.IPV6_RECVHOPLIMIT, 1)
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
            s.bind(("::", 5353))
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, socket.inet_pton(socket.AF_INET6, "ff02::fb") + struct.pack("=I", index))
            destination = ("ff02::fb", 5353, 0, index)
        s.setblocking(False)
        if system == "Windows":
            from .lan_windows import Receiver
            return Receiver(s), destination
        return s, destination
    except BaseException:
        s.close()
        raise


def receiving_interface(ancillary, version):
    index, ttl = None, None
    for level, kind, data in ancillary:
        if version == 4 and level == socket.IPPROTO_IP:
            if platform.system() == "Darwin" and kind == 20 and len(data) >= 4:
                index = struct.unpack_from("=H", data, 2)[0]  # sockaddr_dl.sdl_index
            elif platform.system() == "Linux" and kind == 8 and len(data) >= 12:
                index = struct.unpack_from("=I", data)[0]
            elif platform.system() == "Windows" and kind == 19 and len(data) >= 8:
                index = struct.unpack_from("=I", data, 4)[0]  # IN_PKTINFO
            if kind in (getattr(socket, "IP_TTL", 2), 24, 21) and data:
                ttl = struct.unpack("=i", data[:4])[0] if len(data) >= 4 else data[0]
        elif version == 6 and level == socket.IPPROTO_IPV6:
            if kind == (19 if platform.system() == "Windows" else socket.IPV6_PKTINFO) and len(data) >= 20:
                index = struct.unpack_from("=I", data, 16)[0]
            if kind == (21 if platform.system() == "Windows" else socket.IPV6_HOPLIMIT) and len(data) >= 4:
                ttl = struct.unpack_from("=i", data)[0]
    return index, ttl


def collect(spec, snapshot, deadline, cancel, guard, output, progress=None):
    # Small standard-library transport instead of an unbounded background resolver. Every packet is counted.
    sockets, answers, sent, received, size, valid = [], Answers(), set(), 0, 0, 0
    start_rows = len(output)
    pending = {(META, 12)}
    until = min(time.monotonic() + 5.0, deadline - 1.0)  # reserve the final authorization check
    if until <= time.monotonic():
        raise Stopped("timeout")
    try:
        for version in sorted({a.version for a in spec["addresses"]}):
            ip = next(a for a in spec["addresses"] if a.version == version)
            s, dest = open_socket(ip, snapshot["index"])
            sockets.append((s, dest, version))
        next_send, queries = 0.0, 0
        while time.monotonic() < until:
            guard()
            if pending and time.monotonic() >= next_send:
                question = min(pending)
                pending.remove(question)
                packet = query(*question)
                for s, dest, version in sockets:
                    if queries >= MAX_QUERIES:
                        raise Stopped("query_limit")
                    if version == 6:
                        source = next(a for a in spec["addresses"] if a.version == 6)
                        pktinfo = source.packed + struct.pack("=I", snapshot["index"])
                        s.sendmsg([packet], [(socket.IPPROTO_IPV6, 19 if platform.system() == "Windows" else socket.IPV6_PKTINFO, pktinfo)], 0, dest)
                    else:
                        s.sendto(packet, dest)
                    queries += 1
                sent.add(question)
                next_send = time.monotonic() + len(sockets) / 20
            ready, _, _ = select.select([s for s, _, _ in sockets], [], [], 0.05)
            for s in ready:
                version = next(v for item, _, v in sockets if item is s)
                try:
                    packet, ancillary, flags, peer = s.recvmsg(9000, 256)
                except BlockingIOError:
                    continue
                received, size = received + 1, size + len(packet)
                if received > MAX_PACKETS:
                    raise Stopped("packet_limit")
                if size > MAX_BYTES:
                    raise Stopped("byte_limit")
                if flags & (getattr(socket, "MSG_TRUNC", 0x0100) | getattr(socket, "MSG_CTRUNC", 0x0200)):
                    raise Stopped("byte_limit")
                index, ttl = receiving_interface(ancillary, version)
                if index != snapshot["index"] or ttl != 255 or peer[1] != 5353:
                    continue
                try:
                    sender = address(peer[0].split("%")[0])
                    # Link-local senders may describe an authorized ULA service; the sender itself must
                    # still be explicitly allowed, per this stage's authorization policy.
                    if not in_scope(sender, spec):
                        continue
                    incoming = records(packet)
                except (ValueError, struct.error):
                    continue
                valid += 1
                answers.add(incoming, time.time())
                wanted, _ = answers.wanted(time.time())
                pending |= wanted - sent
                output[start_rows:] = answers.rows(spec, time.time())
                if progress:
                    progress.update(observed_records=len(output))
        output[start_rows:] = answers.rows(spec, time.time())
        return {"received_packets": received, "validated_packets": valid, "sent_queries": queries,
                "receive_path": "observed" if valid else "unverified"}
    finally:
        for s, _, _ in sockets:
            s.close()
