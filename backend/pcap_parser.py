# import dpkt
# import socket
# import struct
# import os
# from datetime import datetime
# from database import get_connection

# HEADER_FORMAT = '!HHIIIIBBH'
# HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
# RECORD_FORMAT = '!IIIIIIIIIIHHBBBBHHBBH'
# RECORD_SIZE = struct.calcsize(RECORD_FORMAT)

# # Configured gateway and NAT bypasses for simulation when reading raw packets
# PRIMARY_GATEWAY = "10.0.0.1"
# NAT_BYPASS_LIST = ["10.0.1.100", "10.0.1.101", "192.168.10.5"]

# def is_private_ip(ip_str):
#     try:
#         parts = list(map(int, ip_str.split('.')))
#         if len(parts) != 4:
#             return False
#         # 10.0.0.0/8
#         if parts[0] == 10:
#             return True
#         # 172.16.0.0/12
#         if parts[0] == 172 and 16 <= parts[1] <= 31:
#             return True
#         # 192.168.0.0/16
#         if parts[0] == 192 and parts[1] == 168:
#             return True
#         return False
#     except Exception:
#         return False

# def parse_pcap_file(pcap_path):
#     """
#     Parses a PCAP file. Automatically detects if it contains NetFlow v5 UDP packets or
#     raw network packets. Extracts flows and inserts them into DuckDB.
#     """
#     is_netflow = False
#     packet_count = 0
#     netflow_records = []
#     raw_packets = []
    
#     # Pre-read a few packets to detect type
#     with open(pcap_path, 'rb') as f:
#         try:
#             pcap = dpkt.pcap.Reader(f)
#         except ValueError:
#             # Try pcapng
#             f.seek(0)
#             try:
#                 pcap = dpkt.pcapng.Reader(f)
#             except Exception as e:
#                 print(f"Error reading PCAP format: {e}")
#                 return 0, "Unsupported or corrupted PCAP file format"
                
#         for i, (ts, buf) in enumerate(pcap):
#             packet_count += 1
#             if i >= 100:
#                 break
#             try:
#                 eth = dpkt.ethernet.Ethernet(buf)
#                 if isinstance(eth.data, dpkt.ip.IP):
#                     ip = eth.data
#                     if ip.p == 17: # UDP
#                         udp = ip.data
#                         if isinstance(udp, dpkt.udp.UDP) and (udp.dport == 2055 or udp.sport == 2055):
#                             is_netflow = True
#                             break
#             except Exception:
#                 continue

#     # Perform full parse based on detected type
#     with open(pcap_path, 'rb') as f:
#         try:
#             pcap = dpkt.pcap.Reader(f)
#         except ValueError:
#             f.seek(0)
#             pcap = dpkt.pcapng.Reader(f)
            
#         for ts, buf in pcap:
#             try:
#                 eth = dpkt.ethernet.Ethernet(buf)
#                 if not isinstance(eth.data, dpkt.ip.IP):
#                     continue
#                 ip = eth.data
#                 src_ip = socket.inet_ntoa(ip.src)
#                 dst_ip = socket.inet_ntoa(ip.dst)
                
#                 if is_netflow:
#                     # It's a NetFlow v5 capture file, parse the payload of UDP packets
#                     if ip.p == 17: # UDP
#                         udp = ip.data
#                         if isinstance(udp, dpkt.udp.UDP) and (udp.dport == 2055 or udp.sport == 2055):
#                             payload = udp.data
#                             if len(payload) >= HEADER_SIZE:
#                                 header = struct.unpack(HEADER_FORMAT, payload[:HEADER_SIZE])
#                                 version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, engine_type, engine_id, sampling = header
#                                 if version == 5:
#                                     offset = HEADER_SIZE
#                                     for _ in range(count):
#                                         if offset + RECORD_SIZE > len(payload):
#                                             break
#                                         record = struct.unpack(RECORD_FORMAT, payload[offset:offset+RECORD_SIZE])
#                                         offset += RECORD_SIZE
                                        
#                                         rec_src = socket.inet_ntoa(struct.pack('!I', record[0]))
#                                         rec_dst = socket.inet_ntoa(struct.pack('!I', record[1]))
#                                         rec_nh = socket.inet_ntoa(struct.pack('!I', record[2]))
                                        
#                                         netflow_records.append((
#                                             rec_src, rec_dst, rec_nh,
#                                             record[3], record[4], record[5], record[6], # input, output, pkts, bytes
#                                             record[7], record[8], record[9], record[10], # first, last switched, sport, dport
#                                             record[12], record[13], record[14], # tcpflags, proto, tos
#                                             record[15], record[16], record[17], record[18], # src_as, dst_as, src_mask, dst_mask
#                                             datetime.fromtimestamp(unix_secs)
#                                         ))
#                 else:
#                     # It's a raw IP traffic capture file, aggregate packets into flow records
#                     proto_num = ip.p
#                     src_port = 0
#                     dst_port = 0
#                     tcp_flags = 0
                    
#                     if proto_num == 6: # TCP
#                         tcp = ip.data
#                         if isinstance(tcp, dpkt.tcp.TCP):
#                             src_port = tcp.sport
#                             dst_port = tcp.dport
#                             tcp_flags = tcp.flags
#                     elif proto_num == 17: # UDP
#                         udp = ip.data
#                         if isinstance(udp, dpkt.udp.UDP):
#                             src_port = udp.sport
#                             dst_port = udp.dport
                            
#                     raw_packets.append({
#                         'src_ip': src_ip,
#                         'dst_ip': dst_ip,
#                         'src_port': src_port,
#                         'dst_port': dst_port,
#                         'protocol': proto_num,
#                         'bytes': len(buf),
#                         'tcp_flags': tcp_flags,
#                         'timestamp': ts
#                     })
#             except Exception as e:
#                 continue

#     conn = get_connection()
#     inserted_count = 0
    
#     try:
#         if is_netflow:
#             # Insert NetFlow records
#             if netflow_records:
#                 conn.executemany("""
#                     INSERT INTO flows (
#                         id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
#                         packets, bytes, first_switched, last_switched,
#                         src_port, dst_port, tcp_flags, protocol, tos,
#                         src_as, dst_as, src_mask, dst_mask, timestamp
#                     ) VALUES (nextval('flow_id_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
#                 """, netflow_records)
#                 inserted_count = len(netflow_records)
#         else:
#             # Aggregate raw packets into flows in memory
#             flows_dict = {}
#             for pkt in raw_packets:
#                 src = pkt['src_ip']
#                 dst = pkt['dst_ip']
#                 sport = pkt['src_port']
#                 dport = pkt['dst_port']
#                 proto = pkt['protocol']
                
#                 # Determine nexthop to simulate compliance logic
#                 nexthop = "0.0.0.0"
#                 if is_private_ip(src) and not is_private_ip(dst):
#                     if src in NAT_BYPASS_LIST:
#                         nexthop = "10.0.0.99" # Bypassing gateway
#                     else:
#                         nexthop = PRIMARY_GATEWAY # Going through primary gateway
                        
#                 key = (src, dst, sport, dport, proto, nexthop)
                
#                 if key not in flows_dict:
#                     flows_dict[key] = {
#                         'packets': 0,
#                         'bytes': 0,
#                         'first_switched': int(pkt['timestamp'] * 1000),
#                         'last_switched': int(pkt['timestamp'] * 1000),
#                         'tcp_flags': 0,
#                         'timestamp': datetime.fromtimestamp(pkt['timestamp'])
#                     }
                    
#                 flows_dict[key]['packets'] += 1
#                 flows_dict[key]['bytes'] += pkt['bytes']
#                 flows_dict[key]['last_switched'] = int(pkt['timestamp'] * 1000)
#                 flows_dict[key]['tcp_flags'] |= pkt['tcp_flags']
                
#             # Convert aggregated dict to database values
#             records_to_insert = []
#             for key, stats in flows_dict.items():
#                 src, dst, sport, dport, proto, nh = key
#                 records_to_insert.append((
#                     src, dst, nh,
#                     0, 0, # input, output SNMP
#                     stats['packets'], stats['bytes'],
#                     stats['first_switched'], stats['last_switched'],
#                     sport, dport,
#                     stats['tcp_flags'], proto, 0, # flags, proto, tos
#                     0, 0, 0, 0, # AS and masks
#                     stats['timestamp']
#                 ))
                
#             if records_to_insert:
#                 conn.executemany("""
#                     INSERT INTO flows (
#                         id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
#                         packets, bytes, first_switched, last_switched,
#                         src_port, dst_port, tcp_flags, protocol, tos,
#                         src_as, dst_as, src_mask, dst_mask, timestamp
#                     ) VALUES (nextval('flow_id_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
#                 """, records_to_insert)
#                 inserted_count = len(records_to_insert)
                
#         conn.commit()
#     except Exception as e:
#         print(f"Database insertion error: {e}")
#         return 0, f"Database insertion failed: {e}"
#     finally:
#         conn.close()
        
#     pcap_type = "NetFlow v5 UDP" if is_netflow else "Raw Packet Capture"
#     return inserted_count, f"Successfully parsed {pcap_type} PCAP. Inserted {inserted_count} flow records."


import dpkt
import socket
import struct
import os
from datetime import datetime
from database import get_connection, get_lock

# ── NetFlow v5 struct (fixed 48-byte record) ─────────────────────────────────
HEADER_FORMAT = '!HHIIIIBBH'
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)   # 24 bytes
RECORD_FORMAT = '!IIIHHIIIIHHBBBBHHBBh'
RECORD_SIZE   = struct.calcsize(RECORD_FORMAT)   # 48 bytes  (was 56 — fixed)

# ── NAT simulation config (mirrors generate_test_pcap.py topology) ───────────
PRIMARY_GATEWAY = "10.0.0.1"
NAT_BYPASS_IPS  = {"10.0.1.100", "10.0.1.101", "192.168.10.5"}
BYPASS_NEXTHOP  = "10.0.0.99"   # fake rogue gateway for bypass detection

INSERT_SQL = """
    INSERT INTO flows (
        id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
        packets, bytes, first_switched, last_switched,
        src_port, dst_port, tcp_flags, protocol, tos,
        src_as, dst_as, src_mask, dst_mask, timestamp
    ) VALUES (nextval('flow_id_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

def is_private_ip(ip_str):
    try:
        parts = list(map(int, ip_str.split('.')))
        if len(parts) != 4:
            return False
        p0, p1 = parts[0], parts[1]
        return (p0 == 10 or p0 == 127
                or (p0 == 172 and 16 <= p1 <= 31)
                or (p0 == 192 and p1 == 168))
    except Exception:
        return False


def _open_pcap(path):
    """Open PCAP or PCAPng, return (reader, linktype)."""
    with open(path, 'rb') as f:
        try:
            r = dpkt.pcap.Reader(f)
            lt = r.datalink()
            return 'pcap', lt
        except Exception:
            pass
    with open(path, 'rb') as f:
        try:
            r = dpkt.pcapng.Reader(f)
            return 'pcapng', 1   # PCAPng is usually Ethernet
        except Exception:
            raise ValueError("Unsupported or corrupted PCAP file")


def _iter_ip_packets(path):
    """
    Yield (timestamp, src_ip, dst_ip, ip_obj) for every IP packet in the PCAP.
    Handles both Ethernet (linktype 1) and Raw IP (linktype 228/101) automatically.
    FIX: original code always parsed as Ethernet, causing 0 results on Raw IP PCAPs.
    """
    fmt, linktype = _open_pcap(path)

    with open(path, 'rb') as f:
        if fmt == 'pcapng':
            pcap = dpkt.pcapng.Reader(f)
        else:
            pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            try:
                if linktype == 1:
                    # Ethernet frame
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                elif linktype in (228, 101):
                    # Raw IP (linktype 228 = LINKTYPE_IPV4, 101 = LINKTYPE_RAW)
                    ip = dpkt.ip.IP(buf)
                else:
                    # Best-effort: try Ethernet then raw IP
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        ip  = eth.data if isinstance(eth.data, dpkt.ip.IP) else None
                    except Exception:
                        ip = None
                    if ip is None:
                        try:
                            ip = dpkt.ip.IP(buf)
                        except Exception:
                            continue

                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                yield ts, src_ip, dst_ip, ip

            except Exception:
                continue


def _is_netflow_pcap(path):
    """Peek at first 100 IP packets to decide if this is a NetFlow UDP capture."""
    for i, (ts, src, dst, ip) in enumerate(_iter_ip_packets(path)):
        if i >= 100:
            break
        if ip.p == 17:
            try:
                udp = ip.data
                if isinstance(udp, dpkt.udp.UDP) and udp.dport in (2055, 9996):
                    return True
            except Exception:
                pass
    return False


def parse_pcap_file(pcap_path):
    """
    Parse a PCAP file — auto-detects NetFlow v5 UDP or raw packet capture.
    Returns (inserted_count, message).
    """
    try:
        is_netflow = _is_netflow_pcap(pcap_path)
    except ValueError as e:
        return 0, str(e)

    netflow_records = []
    raw_packets     = []

    for ts, src_ip, dst_ip, ip in _iter_ip_packets(pcap_path):
        if is_netflow:
            if ip.p != 17:
                continue
            try:
                udp = ip.data
                if not isinstance(udp, dpkt.udp.UDP) or udp.dport not in (2055, 9996):
                    continue
                payload = bytes(udp.data)
                if len(payload) < HEADER_SIZE:
                    continue
                hdr     = struct.unpack(HEADER_FORMAT, payload[:HEADER_SIZE])
                version, count = hdr[0], hdr[1]
                unix_secs      = hdr[3]
                if version != 5:
                    continue
                offset = HEADER_SIZE
                for _ in range(count):
                    if offset + RECORD_SIZE > len(payload):
                        break
                    rec = struct.unpack(RECORD_FORMAT, payload[offset:offset + RECORD_SIZE])
                    offset += RECORD_SIZE
                    netflow_records.append((
                        socket.inet_ntoa(struct.pack('!I', rec[0])),   # src_ip
                        socket.inet_ntoa(struct.pack('!I', rec[1])),   # dst_ip
                        socket.inet_ntoa(struct.pack('!I', rec[2])),   # nexthop
                        rec[3], rec[4],          # input_snmp, output_snmp
                        rec[5], rec[6],          # packets, bytes
                        rec[7], rec[8],          # first_switched, last_switched
                        rec[9], rec[10],         # src_port, dst_port
                        rec[12], rec[13], rec[14],   # tcp_flags, protocol, tos
                        rec[15], rec[16], rec[17], rec[18],  # AS + masks
                        datetime.fromtimestamp(unix_secs)
                    ))
            except Exception:
                continue
        else:
            # Raw packet capture — collect individual packet info
            proto_num = ip.p
            src_port = dst_port = tcp_flags = 0
            if proto_num == 6:     # TCP
                try:
                    tcp = ip.data
                    if isinstance(tcp, dpkt.tcp.TCP):
                        src_port  = tcp.sport
                        dst_port  = tcp.dport
                        tcp_flags = tcp.flags
                except Exception:
                    pass
            elif proto_num == 17:  # UDP
                try:
                    udp = ip.data
                    if isinstance(udp, dpkt.udp.UDP):
                        src_port = udp.sport
                        dst_port = udp.dport
                except Exception:
                    pass
            raw_packets.append({
                'src_ip':   src_ip,
                'dst_ip':   dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': proto_num,   # stored as INTEGER (fix: was string in live capture)
                'bytes':    len(ip),
                'tcp_flags':tcp_flags,
                'timestamp':ts,
            })

    # ── Aggregate raw packets into flows ────────────────────────────────────
    if not is_netflow and raw_packets:
        flows_dict = {}
        for pkt in raw_packets:
            src, dst = pkt['src_ip'], pkt['dst_ip']
            # Determine nexthop for NAT bypass compliance detection
            nexthop = "0.0.0.0"
            if is_private_ip(src) and not is_private_ip(dst):
                nexthop = BYPASS_NEXTHOP if src in NAT_BYPASS_IPS else PRIMARY_GATEWAY

            key = (src, dst, pkt['src_port'], pkt['dst_port'], pkt['protocol'], nexthop)
            if key not in flows_dict:
                flows_dict[key] = {
                    'packets':       0,
                    'bytes':         0,
                    'first_switched':int(pkt['timestamp'] * 1000),
                    'last_switched': int(pkt['timestamp'] * 1000),
                    'tcp_flags':     0,
                    'timestamp':     datetime.fromtimestamp(pkt['timestamp']),
                }
            fd = flows_dict[key]
            fd['packets']      += 1
            fd['bytes']        += pkt['bytes']
            fd['last_switched'] = int(pkt['timestamp'] * 1000)
            fd['tcp_flags']    |= pkt['tcp_flags']

        for key, fd in flows_dict.items():
            src, dst, sport, dport, proto, nh = key
            netflow_records.append((
                src, dst, nh, 0, 0,
                fd['packets'], fd['bytes'],
                fd['first_switched'], fd['last_switched'],
                sport, dport,
                fd['tcp_flags'], proto, 0,   # proto is INTEGER here (fix)
                0, 0, 0, 0,
                fd['timestamp']
            ))

    if not netflow_records:
        return 0, "No parseable IP flows found in the PCAP file."

    # ── Insert into DB ───────────────────────────────────────────────────────
    lock = get_lock()
    conn = get_connection()
    with lock:
        try:
            conn.executemany(INSERT_SQL, netflow_records)
            conn.commit()
            inserted = len(netflow_records)
        except Exception as e:
            return 0, f"Database insertion failed: {e}"

    kind = "NetFlow v5 UDP" if is_netflow else "Raw Packet Capture"
    return inserted, f"Successfully parsed {kind} PCAP. Inserted {inserted} flow records."
