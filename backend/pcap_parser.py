"""
HTC NetFlow Analyzer Pro — High-Performance PCAP/PCAPng Ingestion Engine
========================================================================
Parses raw PCAP/PCAPng network traffic and NetFlow v5 UDP collector dumps.
Supports automatic time-shifting to anchor historical datasets directly
into the active real-time 4-hour window for live compliance testing.
"""

import dpkt
import socket
import struct
import os
from datetime import datetime, timezone, timedelta
from database import get_connection, get_lock
from nexthop import NextHopResolver, NO_NEXTHOP, fmt_mac

# ── NetFlow v5 Struct Definitions ─────────────────────────────────────────────
HEADER_FORMAT = '!HHIIIIBBH'
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)   # 24 bytes
RECORD_FORMAT = '!IIIHHIIIIHHBBBBHHBBh'
RECORD_SIZE   = struct.calcsize(RECORD_FORMAT)   # 48 bytes

INSERT_SQL = """
    INSERT INTO flows (
        id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
        packets, bytes, first_switched, last_switched,
        src_port, dst_port, tcp_flags, protocol, tos,
        src_as, dst_as, src_mask, dst_mask, timestamp
    ) VALUES (nextval('flow_id_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

def _open_pcap(path):
    """Detect PCAP format and data link type."""
    with open(path, 'rb') as f:
        try:
            r = dpkt.pcap.Reader(f)
            return 'pcap', r.datalink()
        except Exception:
            pass
    with open(path, 'rb') as f:
        try:
            r = dpkt.pcapng.Reader(f)
            return 'pcapng', 1
        except Exception:
            raise ValueError("Unsupported or corrupted PCAP file format.")


def _iter_frames(path):
    """
    Yield (timestamp, src_mac, dst_mac, payload) for each IP or ARP frame.
    Handles Ethernet (1), Linux Cooked SLL (113), and Raw IP (228, 101).
    MACs are None when the link type carries no Ethernet header.
    """
    fmt, linktype = _open_pcap(path)

    with open(path, 'rb') as f:
        pcap = dpkt.pcapng.Reader(f) if fmt == 'pcapng' else dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                src_mac = dst_mac = None
                payload = None
                if linktype == 113:
                    sll = dpkt.sll.SLL(buf)
                    src_mac = fmt_mac(sll.hdr[:6]) if sll.hlen == 6 else None
                    payload = sll.data
                elif linktype in (228, 101):
                    payload = dpkt.ip.IP(buf)
                else:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        src_mac, dst_mac = fmt_mac(eth.src), fmt_mac(eth.dst)
                        payload = eth.data
                    except Exception:
                        payload = dpkt.ip.IP(buf) if linktype != 1 else None

                if isinstance(payload, (dpkt.ip.IP, dpkt.arp.ARP)):
                    yield float(ts), src_mac, dst_mac, payload
            except Exception:
                continue


def _iter_ip_packets(path):
    """Yield (timestamp, src_ip, dst_ip, ip_obj, src_mac, dst_mac) for each IP packet."""
    for ts, src_mac, dst_mac, payload in _iter_frames(path):
        if isinstance(payload, dpkt.ip.IP):
            yield ts, socket.inet_ntoa(payload.src), socket.inet_ntoa(payload.dst), payload, src_mac, dst_mac


def build_nexthop_resolver(path):
    """First pass over a raw capture: learn router MACs from ARP and IP traffic."""
    resolver = NextHopResolver()
    for ts, src_mac, dst_mac, payload in _iter_frames(path):
        if isinstance(payload, dpkt.arp.ARP):
            if len(payload.spa) == 4:
                resolver.learn_arp(fmt_mac(payload.sha), socket.inet_ntoa(payload.spa))
        else:
            resolver.learn_packet(src_mac, dst_mac,
                                  socket.inet_ntoa(payload.src), socket.inet_ntoa(payload.dst))
    return resolver


def _is_netflow_pcap(path):
    """Peek at initial IP packets to check for NetFlow UDP port 2055/9996."""
    for i, (ts, src, dst, ip, _smac, _dmac) in enumerate(_iter_ip_packets(path)):
        if i >= 60:
            break
        if ip.p == 17:
            try:
                udp = ip.data
                if isinstance(udp, dpkt.udp.UDP) and udp.dport in (2055, 9996):
                    return True
            except Exception:
                pass
    return False


def aggregate_raw_pcap(pcap_path):
    """
    Aggregate a raw packet capture into unidirectional 5-tuple flows.
    The nexthop of each outbound flow is derived from the Ethernet destination
    MAC (see nexthop.py), so gateway and NAT detection come from the capture
    itself rather than from preset IP lists.

    Returns (flows, resolver); each flow is a dict with epoch-second first/last.
    """
    resolver = build_nexthop_resolver(pcap_path)
    flows = {}

    for ts, src_ip, dst_ip, ip, src_mac, dst_mac in _iter_ip_packets(pcap_path):
        proto_num = ip.p
        src_port = dst_port = tcp_flags = 0
        l4 = ip.data
        if proto_num == 6 and isinstance(l4, dpkt.tcp.TCP):
            src_port, dst_port, tcp_flags = l4.sport, l4.dport, l4.flags
        elif proto_num == 17 and isinstance(l4, dpkt.udp.UDP):
            src_port, dst_port = l4.sport, l4.dport

        nexthop = resolver.nexthop(src_mac, dst_mac, src_ip, dst_ip)
        key = (src_ip, dst_ip, src_port, dst_port, proto_num, nexthop)
        fd = flows.get(key)
        if fd is None:
            fd = flows[key] = {
                'src_ip': src_ip, 'dst_ip': dst_ip, 'nexthop': nexthop,
                'src_port': src_port, 'dst_port': dst_port, 'protocol': proto_num,
                'packets': 0, 'bytes': 0, 'tcp_flags': 0, 'first': ts, 'last': ts,
            }
        fd['packets']   += 1
        fd['bytes']     += len(ip)
        fd['tcp_flags'] |= tcp_flags
        fd['first']      = min(fd['first'], ts)
        fd['last']       = max(fd['last'], ts)

    return list(flows.values()), resolver


def _parse_netflow_records(pcap_path):
    records = []
    for ts, src_ip, dst_ip, ip, _smac, _dmac in _iter_ip_packets(pcap_path):
        if ip.p != 17:
            continue
        try:
            udp = ip.data
            if not isinstance(udp, dpkt.udp.UDP) or udp.dport not in (2055, 9996):
                continue
            payload = bytes(udp.data)
            if len(payload) < HEADER_SIZE:
                continue
            hdr = struct.unpack(HEADER_FORMAT, payload[:HEADER_SIZE])
            version, count = hdr[0], hdr[1]
            unix_secs = hdr[3]
            if version != 5:
                continue
            offset = HEADER_SIZE
            for _ in range(count):
                if offset + RECORD_SIZE > len(payload):
                    break
                rec = struct.unpack(RECORD_FORMAT, payload[offset:offset + RECORD_SIZE])
                offset += RECORD_SIZE
                records.append({
                    'src':       socket.inet_ntoa(struct.pack('!I', rec[0])),
                    'dst':       socket.inet_ntoa(struct.pack('!I', rec[1])),
                    'nexthop':   socket.inet_ntoa(struct.pack('!I', rec[2])),
                    'input':     rec[3],
                    'output':    rec[4],
                    'packets':   rec[5],
                    'bytes':     rec[6],
                    'first':     rec[7],
                    'last':      rec[8],
                    'sport':     rec[9],
                    'dport':     rec[10],
                    'flags':     rec[12],
                    'proto':     rec[13],
                    'tos':       rec[14],
                    'src_as':    rec[15],
                    'dst_as':    rec[16],
                    'src_mask':  rec[17],
                    'dst_mask':  rec[18],
                    'ts':        float(unix_secs),
                })
        except Exception:
            continue
    return records


def _utc_str(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def parse_pcap_file(pcap_path, shift_to_now=True):
    """
    Parse a PCAP or PCAPng file.
    If shift_to_now=True, automatically adjusts packet timestamps so the
    dataset populates the current 4-hour real-time analytics window.
    """
    try:
        is_netflow = _is_netflow_pcap(pcap_path)
    except ValueError as e:
        return 0, str(e)

    now_epoch = datetime.now(timezone.utc).timestamp()
    netflow_records = []
    note = ""

    if is_netflow:
        raw = _parse_netflow_records(pcap_path)
        # Shift so the last export lands at (now - 60 seconds)
        offset = (now_epoch - 60.0) - max(r['ts'] for r in raw) if (shift_to_now and raw) else 0.0
        for r in raw:
            netflow_records.append((
                r['src'], r['dst'], r['nexthop'],
                r['input'], r['output'],
                r['packets'], r['bytes'],
                r['first'], r['last'],
                r['sport'], r['dport'],
                r['flags'], r['proto'], r['tos'],
                r['src_as'], r['dst_as'], r['src_mask'], r['dst_mask'],
                _utc_str(r['ts'] + offset)
            ))
    else:
        flows, resolver = aggregate_raw_pcap(pcap_path)
        offset = (now_epoch - 60.0) - max(f['last'] for f in flows) if (shift_to_now and flows) else 0.0
        for f in flows:
            first, last = f['first'] + offset, f['last'] + offset
            netflow_records.append((
                f['src_ip'], f['dst_ip'], f['nexthop'], 0, 0,
                f['packets'], f['bytes'],
                int(first * 1000), int(last * 1000),
                f['src_port'], f['dst_port'],
                f['tcp_flags'], f['protocol'], 0,
                0, 0, 0, 0,
                _utc_str(first)
            ))
        hops = sorted({f['nexthop'] for f in flows if f['nexthop'] != NO_NEXTHOP})
        note = f" Egress next hops derived from Layer-2 data: {', '.join(hops) or 'none (no Ethernet/ARP data)'}."

    if not netflow_records:
        return 0, "No parseable IP flows found in the PCAP file."

    # Batch insert into DuckDB
    lock = get_lock()
    conn = get_connection()
    with lock:
        try:
            conn.executemany(INSERT_SQL, netflow_records)
            conn.commit()
            inserted = len(netflow_records)
        except Exception as e:
            return 0, f"Database insertion error: {e}"

    kind = "NetFlow v5 UDP" if is_netflow else "Raw Packet Capture"
    time_note = " (Normalized to active 4h real-time window)" if shift_to_now else ""
    return inserted, f"Successfully parsed {kind} PCAP. Inserted {inserted} flow records{time_note}.{note}"
