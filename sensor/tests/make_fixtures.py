#!/usr/bin/env python3
"""Generate the deterministic pcap fixtures used by sentinel-capture's tests.

Pure standard library. Re-running produces byte-identical files.

Addresses: 192.168.1.x are local hosts; 203.0.113.x and 198.51.100.x are
RFC 5737 documentation ranges standing in for remote hosts. MACs are locally
administered (02:...) and made up. All traffic starts at T0, a 10 s boundary,
so window boundaries in the tests are exact.

    python3 sensor/tests/make_fixtures.py            # writes sensor/tests/fixtures/
    python3 sensor/tests/make_fixtures.py --out DIR
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import struct
from dataclasses import dataclass
from pathlib import Path

T0 = 1761370750  # 2025-10-25T05:39:10Z, a multiple of 10
SNAPLEN = 128     # matches the sensor's live snaplen: payload bytes are not stored

GATEWAY_MAC = "02:00:5e:00:00:fe"

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass(frozen=True)
class Host:
    mac: str
    ip: str
    vlan: int | None = None


def _mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


class Frame:
    """Builds Ethernet/IPv4 frames with correct IP, TCP and UDP checksums."""

    _ip_id = 0

    @classmethod
    def _ipv4(cls, src: str, dst: str, proto: int, payload: bytes) -> bytes:
        cls._ip_id = (cls._ip_id + 1) & 0xFFFF
        header = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), cls._ip_id, 0x4000, 64, proto, 0,
            ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed,
        )
        header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
        return header + payload

    @staticmethod
    def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
        return (ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed
                + struct.pack("!BBH", 0, proto, length))

    @staticmethod
    def _ethernet(src_mac: str, dst_mac: str, vlan: int | None, payload: bytes) -> bytes:
        header = _mac(dst_mac) + _mac(src_mac)
        if vlan is not None:
            header += struct.pack("!HH", 0x8100, vlan)
        return header + struct.pack("!H", 0x0800) + payload

    @classmethod
    def tcp(cls, src_mac, dst_mac, src, sport, dst, dport, flags, payload_len=0,
            seq=0, ack=0, vlan=None) -> bytes:
        payload = bytes(payload_len)
        segment = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                              64240, 0, 0) + payload
        csum = _checksum(cls._pseudo(src, dst, 6, len(segment)) + segment)
        segment = segment[:16] + struct.pack("!H", csum) + segment[18:]
        return cls._ethernet(src_mac, dst_mac, vlan, cls._ipv4(src, dst, 6, segment))

    @classmethod
    def udp(cls, src_mac, dst_mac, src, sport, dst, dport, payload_len, vlan=None) -> bytes:
        payload = bytes(payload_len)
        datagram = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        csum = _checksum(cls._pseudo(src, dst, 17, len(datagram)) + datagram) or 0xFFFF
        datagram = datagram[:6] + struct.pack("!H", csum) + datagram[8:]
        return cls._ethernet(src_mac, dst_mac, vlan, cls._ipv4(src, dst, 17, datagram))

    @classmethod
    def icmp_echo(cls, src_mac, dst_mac, src, dst, reply: bool, ident: int, seq: int) -> bytes:
        body = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, ident, seq) + bytes(56)
        body = body[:2] + struct.pack("!H", _checksum(body)) + body[4:]
        return cls._ethernet(src_mac, dst_mac, None, cls._ipv4(src, dst, 1, body))


class PcapWriter:
    """Classic libpcap format, microsecond timestamps, LINKTYPE_ETHERNET."""

    def __init__(self) -> None:
        self.records: list[tuple[float, bytes]] = []

    def add(self, ts: float, frame: bytes) -> None:
        self.records.append((ts, frame))

    def write(self, path: Path) -> None:
        out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, 1))
        for ts, frame in sorted(self.records, key=lambda r: r[0]):
            usec_total = round(ts * 1_000_000)
            sec, usec = divmod(usec_total, 1_000_000)
            captured = frame[:SNAPLEN]
            out += struct.pack("<IIII", sec, usec, len(captured), len(frame)) + captured
        path.write_bytes(bytes(out))


def port_scan() -> PcapWriter:
    """Window T0: an inbound scan of 100 ports and an outbound scan of 50 ports."""
    pcap = PcapWriter()
    victim = Host("02:00:5e:00:00:14", "192.168.1.20")
    scanner = Host("02:00:5e:00:00:1e", "192.168.1.30")
    inbound_attacker, outbound_target = "203.0.113.9", "198.51.100.7"

    # Remote scanner probes 100 distinct ports on the victim; a host firewall drops them.
    for i in range(100):
        pcap.add(T0 + 0.5 + i * 0.04,
                 Frame.tcp(GATEWAY_MAC, victim.mac, inbound_attacker, 41000, victim.ip,
                           1 + i * 10, TCP_SYN, seq=1000 + i))

    # Local host scans 50 ports on a remote; two are open (SYN-ACK), the rest RST.
    open_ports = {22, 443}
    ports = [22, 443] + [1000 + i for i in range(48)]
    for i, port in enumerate(ports):
        ts = T0 + 5.0 + i * 0.05
        pcap.add(ts, Frame.tcp(scanner.mac, GATEWAY_MAC, scanner.ip, 52000, outbound_target,
                               port, TCP_SYN, seq=5000 + i))
        reply = TCP_SYN | TCP_ACK if port in open_ports else TCP_RST | TCP_ACK
        pcap.add(ts + 0.01, Frame.tcp(GATEWAY_MAC, scanner.mac, outbound_target, port,
                                      scanner.ip, 52000, reply, seq=9000 + i, ack=5001 + i))
    return pcap


def syn_flood() -> PcapWriter:
    """Window T0: 800 SYNs from one remote to one local host's port 80, no ACKs."""
    pcap = PcapWriter()
    victim = Host("02:00:5e:00:00:28", "192.168.1.40")
    attacker = "203.0.113.50"
    rng = random.Random(800)  # fixed seed: deterministic source ports
    for i in range(800):
        pcap.add(T0 + 0.1 + i * 0.012,
                 Frame.tcp(GATEWAY_MAC, victim.mac, attacker, rng.randint(1024, 65535),
                           victim.ip, 80, TCP_SYN, seq=rng.getrandbits(32)))
    return pcap


def benign() -> PcapWriter:
    """60 s, 3 hosts. Each window, each host does one DNS lookup and one short
    HTTPS session; host A pings host B (local-to-local). Host C is on VLAN 10."""
    pcap = PcapWriter()
    hosts = [
        Host("02:00:5e:00:00:0a", "192.168.1.10"),
        Host("02:00:5e:00:00:0b", "192.168.1.11"),
        Host("02:00:5e:00:00:0c", "192.168.1.12", vlan=10),
    ]
    resolver = "198.51.100.53"

    for w in range(6):
        for h, host in enumerate(hosts):
            t = T0 + w * 10 + 1.0 + h * 0.5
            step = 0.01
            dport = 53000 + w * 10 + h
            cport = 50000 + w * 10 + h
            server = f"203.0.113.{100 + h}"

            def out(flags, host=host, cport=cport, server=server, **kw):
                return Frame.tcp(host.mac, GATEWAY_MAC, host.ip, cport, server, 443, flags,
                                 vlan=host.vlan, **kw)

            def inn(flags, host=host, cport=cport, server=server, **kw):
                return Frame.tcp(GATEWAY_MAC, host.mac, server, 443, host.ip, cport, flags,
                                 vlan=host.vlan, **kw)

            frames = [
                Frame.udp(host.mac, GATEWAY_MAC, host.ip, dport, resolver, 53, 32, vlan=host.vlan),
                Frame.udp(GATEWAY_MAC, host.mac, resolver, 53, host.ip, dport, 64, vlan=host.vlan),
                out(TCP_SYN, seq=1),
                inn(TCP_SYN | TCP_ACK, seq=7, ack=2),
                out(TCP_ACK, seq=2, ack=8),
            ]
            for r in range(3):
                frames.append(out(TCP_PSH | TCP_ACK, payload_len=200, seq=2 + r * 200, ack=8))
                frames.append(inn(TCP_PSH | TCP_ACK, payload_len=1200, seq=8 + r * 1200, ack=2))
            frames += [
                out(TCP_FIN | TCP_ACK, seq=602, ack=3608),
                inn(TCP_FIN | TCP_ACK, seq=3608, ack=603),
                out(TCP_ACK, seq=603, ack=3609),
            ]
            for i, frame in enumerate(frames):
                pcap.add(t + i * step, frame)

        a, b = hosts[0], hosts[1]
        t = T0 + w * 10 + 5.0
        pcap.add(t, Frame.icmp_echo(a.mac, b.mac, a.ip, b.ip, reply=False, ident=7, seq=w))
        pcap.add(t + 0.001, Frame.icmp_echo(b.mac, a.mac, b.ip, a.ip, reply=True, ident=7, seq=w))
    return pcap


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "fixtures")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, build in (("port_scan", port_scan), ("syn_flood", syn_flood), ("benign", benign)):
        Frame._ip_id = 0  # each file is independent of generation order
        path = args.out / f"{name}.pcap"
        build().write(path)
        print(f"wrote {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
