import dpkt
import socket
import struct
import os
from datetime import datetime
from database import get_connection

HEADER_FORMAT = '!HHIIIIBBH'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
RECORD_FORMAT = '!IIIIIIIIIIHHBBBBHHBBH'
RECORD_SIZE = struct.calcsize(RECORD_FORMAT)

# Configured gateway and NAT bypasses for simulation when reading raw packets
PRIMARY_GATEWAY = "10.0.0.1"
NAT_BYPASS_LIST = ["10.0.1.100", "10.0.1.101", "192.168.10.5"]

def is_private_ip(ip_str):
    try:
        parts = list(map(int, ip_str.split('.')))
        if len(parts) != 4:
            return False
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        return False
    except Exception:
        return False

def parse_pcap_file(pcap_path):
    """
    Parses a PCAP file. Automatically detects if it contains NetFlow v5 UDP packets or
    raw network packets. Extracts flows and inserts them into DuckDB.
    """
    is_netflow = False
    packet_count = 0
    netflow_records = []
    raw_packets = []
    
    # Pre-read a few packets to detect type
    with open(pcap_path, 'rb') as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except ValueError:
            # Try pcapng
            f.seek(0)
            try:
                pcap = dpkt.pcapng.Reader(f)
            except Exception as e:
                print(f"Error reading PCAP format: {e}")
                return 0, "Unsupported or corrupted PCAP file format"
                
        for i, (ts, buf) in enumerate(pcap):
            packet_count += 1
            if i >= 100:
                break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    if ip.p == 17: # UDP
                        udp = ip.data
                        if isinstance(udp, dpkt.udp.UDP) and (udp.dport == 2055 or udp.sport == 2055):
                            is_netflow = True
                            break
            except Exception:
                continue

    # Perform full parse based on detected type
    with open(pcap_path, 'rb') as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)
            
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                
                if is_netflow:
                    # It's a NetFlow v5 capture file, parse the payload of UDP packets
                    if ip.p == 17: # UDP
                        udp = ip.data
                        if isinstance(udp, dpkt.udp.UDP) and (udp.dport == 2055 or udp.sport == 2055):
                            payload = udp.data
                            if len(payload) >= HEADER_SIZE:
                                header = struct.unpack(HEADER_FORMAT, payload[:HEADER_SIZE])
                                version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, engine_type, engine_id, sampling = header
                                if version == 5:
                                    offset = HEADER_SIZE
                                    for _ in range(count):
                                        if offset + RECORD_SIZE > len(payload):
                                            break
                                        record = struct.unpack(RECORD_FORMAT, payload[offset:offset+RECORD_SIZE])
                                        offset += RECORD_SIZE
                                        
                                        rec_src = socket.inet_ntoa(struct.pack('!I', record[0]))
                                        rec_dst = socket.inet_ntoa(struct.pack('!I', record[1]))
                                        rec_nh = socket.inet_ntoa(struct.pack('!I', record[2]))
                                        
                                        netflow_records.append((
                                            rec_src, rec_dst, rec_nh,
                                            record[3], record[4], record[5], record[6], # input, output, pkts, bytes
                                            record[7], record[8], record[9], record[10], # first, last switched, sport, dport
                                            record[12], record[13], record[14], # tcpflags, proto, tos
                                            record[15], record[16], record[17], record[18], # src_as, dst_as, src_mask, dst_mask
                                            datetime.fromtimestamp(unix_secs)
                                        ))
                else:
                    # It's a raw IP traffic capture file, aggregate packets into flow records
                    proto_num = ip.p
                    src_port = 0
                    dst_port = 0
                    tcp_flags = 0
                    
                    if proto_num == 6: # TCP
                        tcp = ip.data
                        if isinstance(tcp, dpkt.tcp.TCP):
                            src_port = tcp.sport
                            dst_port = tcp.dport
                            tcp_flags = tcp.flags
                    elif proto_num == 17: # UDP
                        udp = ip.data
                        if isinstance(udp, dpkt.udp.UDP):
                            src_port = udp.sport
                            dst_port = udp.dport
                            
                    raw_packets.append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': proto_num,
                        'bytes': len(buf),
                        'tcp_flags': tcp_flags,
                        'timestamp': ts
                    })
            except Exception as e:
                continue

    conn = get_connection()
    inserted_count = 0
    
    try:
        if is_netflow:
            # Insert NetFlow records
            if netflow_records:
                conn.executemany("""
                    INSERT INTO flows (
                        id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
                        packets, bytes, first_switched, last_switched,
                        src_port, dst_port, tcp_flags, protocol, tos,
                        src_as, dst_as, src_mask, dst_mask, timestamp
                    ) VALUES (nextval('flow_id_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, netflow_records)
                inserted_count = len(netflow_records)
        else:
            # Aggregate raw packets into flows in memory
            flows_dict = {}
            for pkt in raw_packets:
                src = pkt['src_ip']
                dst = pkt['dst_ip']
                sport = pkt['src_port']
                dport = pkt['dst_port']
                proto = pkt['protocol']
                
                # Determine nexthop to simulate compliance logic
                nexthop = "0.0.0.0"
                if is_private_ip(src) and not is_private_ip(dst):
                    if src in NAT_BYPASS_LIST:
                        nexthop = "10.0.0.99" # Bypassing gateway
                    else:
                        nexthop = PRIMARY_GATEWAY # Going through primary gateway
                        
                key = (src, dst, sport, dport, proto, nexthop)
                
                if key not in flows_dict:
                    flows_dict[key] = {
                        'packets': 0,
                        'bytes': 0,
                        'first_switched': int(pkt['timestamp'] * 1000),
                        'last_switched': int(pkt['timestamp'] * 1000),
                        'tcp_flags': 0,
                        'timestamp': datetime.fromtimestamp(pkt['timestamp'])
                    }
                    
                flows_dict[key]['packets'] += 1
                flows_dict[key]['bytes'] += pkt['bytes']
                flows_dict[key]['last_switched'] = int(pkt['timestamp'] * 1000)
                flows_dict[key]['tcp_flags'] |= pkt['tcp_flags']
                
            # Convert aggregated dict to database values
            records_to_insert = []
            for key, stats in flows_dict.items():
                src, dst, sport, dport, proto, nh = key
                records_to_insert.append((
                    src, dst, nh,
                    0, 0, # input, output SNMP
                    stats['packets'], stats['bytes'],
                    stats['first_switched'], stats['last_switched'],
                    sport, dport,
                    stats['tcp_flags'], proto, 0, # flags, proto, tos
                    0, 0, 0, 0, # AS and masks
                    stats['timestamp']
                ))
                
            if records_to_insert:
                conn.executemany("""
                    INSERT INTO flows (
                        id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
                        packets, bytes, first_switched, last_switched,
                        src_port, dst_port, tcp_flags, protocol, tos,
                        src_as, dst_as, src_mask, dst_mask, timestamp
                    ) VALUES (nextval('flow_id_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, records_to_insert)
                inserted_count = len(records_to_insert)
                
        conn.commit()
    except Exception as e:
        print(f"Database insertion error: {e}")
        return 0, f"Database insertion failed: {e}"
    finally:
        conn.close()
        
    pcap_type = "NetFlow v5 UDP" if is_netflow else "Raw Packet Capture"
    return inserted_count, f"Successfully parsed {pcap_type} PCAP. Inserted {inserted_count} flow records."
