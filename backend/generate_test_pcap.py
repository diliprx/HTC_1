
"""
Generate a realistic test PCAP for HTC NetFlow compliance dashboard.
FIX: Wraps all packets in Ether() to produce Ethernet linktype (1),
     so pcap_parser.py can parse them correctly (was Raw IP = linktype 228).
"""
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, wrpcap
import random

OUTPUT_FILE = "test_traffic.pcap"

INTERNAL = [
    "10.0.0.10",   # web-server-01
    "10.0.0.11",   # web-server-02
    "10.0.0.20",   # db-server-01
    "10.0.0.21",   # db-server-02
    "10.0.0.30",   # app-server-01
    "10.0.0.40",   # mail-server
    "10.0.0.50",   # file-server
    "10.0.1.100",  # workstation-A  (NAT bypass)
    "10.0.1.101",  # workstation-B  (NAT bypass)
    "10.0.1.102",  # workstation-C
    "192.168.10.5",# dev-machine    (NAT bypass)
]
NAT_BYPASS = {"10.0.1.100", "10.0.1.101", "192.168.10.5"}

PUBLIC = {
    "8.8.8.8":        {"port": 53,   "proto": "UDP"},
    "1.1.1.1":        {"port": 53,   "proto": "UDP"},
    "203.0.113.10":   {"port": 3306, "proto": "TCP"},
    "198.51.100.5":   {"port": 443,  "proto": "TCP"},
    "185.220.101.4":  {"port": 25,   "proto": "TCP"},
    "104.18.22.33":   {"port": 443,  "proto": "TCP"},
    "91.108.4.10":    {"port": 80,   "proto": "TCP"},
    "142.250.80.46":  {"port": 443,  "proto": "TCP"},
}

# Dummy MAC addresses for Ethernet header (required for linktype=1)
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"

packets = []
pkt_id  = 0
random.seed(42)

def eth_tcp(src, dst, sport, dport, payload="DATA", flags="PA"):
    global pkt_id; pkt_id += 1
    return (Ether(src=SRC_MAC, dst=DST_MAC) /
            IP(src=src, dst=dst, id=pkt_id) /
            TCP(sport=sport, dport=dport, flags=flags) /
            Raw(load=payload[:200].encode() if isinstance(payload, str) else payload[:200]))

def eth_udp(src, dst, sport, dport, payload=b"DATA"):
    global pkt_id; pkt_id += 1
    return (Ether(src=SRC_MAC, dst=DST_MAC) /
            IP(src=src, dst=dst, id=pkt_id) /
            UDP(sport=sport, dport=dport) /
            Raw(load=payload[:100] if isinstance(payload, bytes) else payload[:100].encode()))

def eth_icmp(src, dst):
    global pkt_id; pkt_id += 1
    return (Ether(src=SRC_MAC, dst=DST_MAC) /
            IP(src=src, dst=dst, id=pkt_id) /
            ICMP(type=8) / Raw(load=b"ping" * 8))

# 1. Web/HTTPS traffic
for _ in range(40):
    packets.append(eth_tcp("10.0.0.10", random.choice(["142.250.80.46","198.51.100.5","104.18.22.33"]),
                            random.randint(32000,65000), 443, "TLS_CLIENT_HELLO"))

# 2. DNS queries
for _ in range(60):
    packets.append(eth_udp(random.choice(["10.0.0.10","10.0.0.11","10.0.0.30","10.0.1.100","10.0.1.101"]),
                            random.choice(["8.8.8.8","1.1.1.1"]),
                            random.randint(1024,65000), 53, b"DNS_QUERY"))

# 3. MySQL (internal + external vendor)
for _ in range(30):
    src = "10.0.0.30"
    dst = random.choice(["10.0.0.20","10.0.0.21","203.0.113.10"])
    packets.append(eth_tcp(src, dst, random.randint(32000,65000), 3306, "SELECT * FROM users;"))

# 4. PostgreSQL
for _ in range(18):
    packets.append(eth_tcp("10.0.0.30", random.choice(["10.0.0.20","10.0.0.21"]),
                            random.randint(32000,65000), 5432, "SELECT version();"))

# 5. SSH management
for _ in range(20):
    src = random.choice(["10.0.0.10","10.0.0.20","10.0.0.50"])
    dst = random.choice(["10.0.0.20","10.0.0.50"])
    packets.append(eth_tcp(src, dst, random.randint(1024,65000), 22, "SSH-2.0-OpenSSH_8.9"))

# 6. SMTP to Tor exit (HIGH RISK)
for _ in range(15):
    packets.append(eth_tcp("10.0.0.40", "185.220.101.4",
                            random.randint(1024,65000), 25, "EHLO mail.example.com"))

# 7. SMB file sharing
for _ in range(25):
    src = random.choice(["10.0.0.50","10.0.1.100","10.0.1.101","10.0.1.102"])
    dst = "10.0.0.50" if src != "10.0.0.50" else "10.0.1.100"
    packets.append(eth_tcp(src, dst, random.randint(1024,65000), 445, "SMB2_NEGOTIATE"))

# 8. NTP
for _ in range(10):
    packets.append(eth_udp(random.choice(["10.0.0.10","10.0.0.20"]),
                            "8.8.8.8", random.randint(1024,65000), 123, b"\x1b" + b"\x00"*47))

# 9. ICMP ping
for _ in range(20):
    src = random.choice(["10.0.0.10","10.0.0.20","10.0.0.1"])
    dst = random.choice(["10.0.0.11","10.0.0.30","8.8.8.8"])
    packets.append(eth_icmp(src, dst))

# 10. HTTP-Alt (8080)
for _ in range(12):
    packets.append(eth_tcp(random.choice(["10.0.0.30","10.0.1.100"]),
                            "104.18.22.33", random.randint(1024,65000), 8080, "GET /api/health"))

# 11. SNMP
for _ in range(8):
    packets.append(eth_udp(random.choice(["10.0.0.1","10.0.0.2"]),
                            random.choice(INTERNAL[:6]), 161, 161, b"\x30\x26\x02\x01\x00"))

# 12. NAT BYPASS — workstation-A → Telegram
for _ in range(20):
    packets.append(eth_tcp("10.0.1.100", "91.108.4.10",
                            random.randint(1024,65000), 80, "GET / HTTP/1.1"))

# 13. NAT BYPASS — workstation-B → Tor SMTP
for _ in range(18):
    packets.append(eth_tcp("10.0.1.101", "185.220.101.4",
                            random.randint(1024,65000), 25, "EHLO bypass.local"))

# 14. NAT BYPASS — dev-machine → CDN
for _ in range(12):
    packets.append(eth_tcp("192.168.10.5", "198.51.100.5",
                            random.randint(1024,65000), 443, "TLS_BYPASS"))

# 15. Return traffic (public → internal)
for _ in range(30):
    pub = random.choice(list(PUBLIC.keys()))
    int_ip = random.choice(INTERNAL[:8])
    info = PUBLIC[pub]
    if info["proto"] == "TCP":
        packets.append(eth_tcp(pub, int_ip, info["port"], random.randint(32000,65000), "HTTP/1.1 200 OK"))
    else:
        packets.append(eth_udp(pub, int_ip, info["port"], random.randint(1024,65000), b"DNS_RESPONSE"))

random.shuffle(packets)
wrpcap(OUTPUT_FILE, packets)
print(f"✅  Generated {OUTPUT_FILE}  ({len(packets)} packets, linktype=Ethernet)")
