"""
Generate a realistic dummy PCAP file for NetFlow compliance dashboard testing.
Contains: TCP, UDP, ICMP flows across internal/public IPs including NAT bypass scenarios.
"""
from scapy.all import (
    IP, TCP, UDP, ICMP, Raw, Ether, wrpcap
)
import random

OUTPUT_FILE = "test_traffic.pcap"

# ── Network topology (mirrors MOCK_DATA in App.jsx) ──────────────────────────
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
    "8.8.8.8":          {"port": 53,   "proto": "UDP", "geo": "US/Google DNS"},
    "1.1.1.1":          {"port": 53,   "proto": "UDP", "geo": "AU/Cloudflare"},
    "203.0.113.10":     {"port": 3306, "proto": "TCP", "geo": "SG/Vendor"},
    "198.51.100.5":     {"port": 443,  "proto": "TCP", "geo": "DE/CDN"},
    "185.220.101.4":    {"port": 25,   "proto": "TCP", "geo": "NL/Tor Exit"},
    "104.18.22.33":     {"port": 443,  "proto": "TCP", "geo": "US/Cloudflare"},
    "91.108.4.10":      {"port": 80,   "proto": "TCP", "geo": "NL/Telegram"},
    "142.250.80.46":    {"port": 443,  "proto": "TCP", "geo": "US/Google"},
}

# Service port → (sport range, payload size range)
SERVICES = {
    (53,  "UDP"): (1024, 50,   80,   "dns_query"),
    (80,  "TCP"): (1024, 200,  1400, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    (443, "TCP"): (1024, 300,  1400, "TLS_HANDSHAKE"),
    (22,  "TCP"): (1024, 100,  600,  "SSH-2.0-OpenSSH_8.9\r\n"),
    (25,  "TCP"): (1024, 100,  400,  "EHLO mail.example.com\r\n"),
    (3306,"TCP"): (3200, 500,  4000, "MYSQL_QUERY"),
    (445, "TCP"): (1024, 200,  2000, "SMB_NEGOTIATE"),
    (123, "UDP"): (1024, 48,   48,   "NTP_REQUEST"),
}

packets = []
pkt_id  = 0

def make_tcp(src, dst, sport, dport, payload=b"", flags="S"):
    return (
        IP(src=src, dst=dst, id=pkt_id) /
        TCP(sport=sport, dport=dport, flags=flags, seq=random.randint(1000, 9999999)) /
        Raw(load=payload if isinstance(payload, bytes) else payload.encode()[:200])
    )

def make_udp(src, dst, sport, dport, payload=b""):
    return (
        IP(src=src, dst=dst, id=pkt_id) /
        UDP(sport=sport, dport=dport) /
        Raw(load=payload if isinstance(payload, bytes) else payload.encode()[:100])
    )

def make_icmp(src, dst):
    return IP(src=src, dst=dst, id=pkt_id) / ICMP(type=8, code=0) / Raw(load=b"ping" * 8)

random.seed(42)

# ── 1. Compliant web traffic (web-server-01 → CDN / Google) ──────────────────
for _ in range(40):
    pkt_id += 1
    src = "10.0.0.10"
    dst = random.choice(["142.250.80.46", "198.51.100.5", "104.18.22.33"])
    packets.append(make_tcp(src, dst, random.randint(32000, 65000), 443,
                            "TLS_CLIENT_HELLO", flags="PA"))

# ── 2. DNS queries (multiple servers → 8.8.8.8 / 1.1.1.1) ───────────────────
dns_senders = ["10.0.0.10", "10.0.0.11", "10.0.0.30", "10.0.1.100", "10.0.1.101"]
for _ in range(60):
    pkt_id += 1
    src = random.choice(dns_senders)
    dst = random.choice(["8.8.8.8", "1.1.1.1"])
    packets.append(make_udp(src, dst, random.randint(1024, 65000), 53, "DNS_QUERY"))

# ── 3. DB traffic (app-server → db-server, also external vendor) ─────────────
for _ in range(30):
    pkt_id += 1
    src = "10.0.0.30"
    dst = random.choice(["10.0.0.20", "10.0.0.21", "203.0.113.10"])
    dport = 3306 if dst.startswith("10.") else 3306
    packets.append(make_tcp(src, dst, random.randint(32000, 65000), dport,
                            "SELECT * FROM users LIMIT 10;", flags="PA"))

# ── 4. SSH management traffic ─────────────────────────────────────────────────
for _ in range(20):
    pkt_id += 1
    src = random.choice(["10.0.0.10", "10.0.0.20", "10.0.0.50"])
    dst = random.choice(["10.0.0.20", "10.0.0.50"])
    packets.append(make_tcp(src, dst, random.randint(1024, 65000), 22,
                            "SSH-2.0-OpenSSH_8.9\r\n", flags="PA"))

# ── 5. SMTP mail-server → suspicious Tor exit node (HIGH RISK) ───────────────
for _ in range(15):
    pkt_id += 1
    src = "10.0.0.40"
    dst = "185.220.101.4"
    packets.append(make_tcp(src, dst, random.randint(1024, 65000), 25,
                            "EHLO mail.example.com\r\n", flags="PA"))

# ── 6. SMB file sharing (file-server ↔ workstations) ─────────────────────────
for _ in range(25):
    pkt_id += 1
    src = random.choice(["10.0.0.50", "10.0.1.100", "10.0.1.101", "10.0.1.102"])
    dst = "10.0.0.50" if src != "10.0.0.50" else "10.0.1.100"
    packets.append(make_tcp(src, dst, random.randint(1024, 65000), 445,
                            "SMB2_NEGOTIATE_REQUEST", flags="PA"))

# ── 7. NTP sync ───────────────────────────────────────────────────────────────
for _ in range(10):
    pkt_id += 1
    src = random.choice(["10.0.0.10", "10.0.0.20"])
    packets.append(make_udp(src, "8.8.8.8", random.randint(1024, 65000), 123, b"\x1b" + b"\x00" * 47))

# ── 8. ICMP pings (diagnostic) ────────────────────────────────────────────────
for _ in range(20):
    pkt_id += 1
    src = random.choice(["10.0.0.10", "10.0.0.20", "10.0.0.1"])
    dst = random.choice(["10.0.0.11", "10.0.0.30", "8.8.8.8"])
    packets.append(make_icmp(src, dst))

# ── 9. HTTP-Alt (8080) app traffic ────────────────────────────────────────────
for _ in range(12):
    pkt_id += 1
    src = random.choice(["10.0.0.30", "10.0.1.100"])
    dst = "104.18.22.33"
    packets.append(make_tcp(src, dst, random.randint(1024, 65000), 8080,
                            "GET /api/health HTTP/1.1\r\n", flags="PA"))

# ── 10. PostgreSQL (app-server → db-server) ───────────────────────────────────
for _ in range(18):
    pkt_id += 1
    src = "10.0.0.30"
    dst = random.choice(["10.0.0.20", "10.0.0.21"])
    packets.append(make_tcp(src, dst, random.randint(32000, 65000), 5432,
                            "SELECT version();", flags="PA"))

# ── 11. SNMP polling (gateway → internal) ────────────────────────────────────
for _ in range(8):
    pkt_id += 1
    src = random.choice(["10.0.0.1", "10.0.0.2"])
    dst = random.choice(INTERNAL[:6])
    packets.append(make_udp(src, dst, 161, 161, b"\x30\x26\x02\x01\x00"))

# ── 12. NAT BYPASS: workstations routing direct (HIGH RISK) ──────────────────
# workstation-A bypasses gateway → Telegram
for _ in range(20):
    pkt_id += 1
    src = "10.0.1.100"
    dst = "91.108.4.10"
    packets.append(make_tcp(src, dst, random.randint(1024, 65000), 80,
                            "GET / HTTP/1.1\r\nHost: telegram.org\r\n", flags="PA"))

# workstation-B bypasses gateway → Tor exit SMTP
for _ in range(18):
    pkt_id += 1
    src = "10.0.1.101"
    dst = "185.220.101.4"
    packets.append(make_tcp(src, dst, random.randint(1024, 65000), 25,
                            "EHLO bypass.example.com\r\n", flags="PA"))

# dev-machine bypasses gateway → CDN  
for _ in range(12):
    pkt_id += 1
    src = "192.168.10.5"
    dst = "198.51.100.5"
    packets.append(make_tcp(src, dst, random.randint(1024, 65000), 443,
                            "TLS_CLIENT_HELLO_BYPASS", flags="PA"))

# ── 13. Telegram proxy (workstation-B) ───────────────────────────────────────
for _ in range(10):
    pkt_id += 1
    src = "10.0.1.101"
    dst = "91.108.4.10"
    packets.append(make_tcp(src, dst, random.randint(1024, 65000), 443,
                            "PROXY_CONNECT", flags="PA"))

# ── 14. Return traffic (public → internal, for bidirectional flow records) ────
for _ in range(30):
    pkt_id += 1
    pub_ip = random.choice(list(PUBLIC.keys()))
    int_ip = random.choice(INTERNAL[:8])
    pub_info = PUBLIC[pub_ip]
    if pub_info["proto"] == "TCP":
        packets.append(make_tcp(pub_ip, int_ip,
                                pub_info["port"],
                                random.randint(32000, 65000),
                                "HTTP/1.1 200 OK\r\n", flags="PA"))
    else:
        packets.append(make_udp(pub_ip, int_ip,
                                pub_info["port"],
                                random.randint(1024, 65000),
                                b"DNS_RESPONSE"))

# ── Shuffle to simulate real-world interleaved captures ──────────────────────
random.shuffle(packets)

wrpcap(OUTPUT_FILE, packets)

total = len(packets)
print(f"\n✅ Generated: {OUTPUT_FILE}")
print(f"   Total packets : {total}")
print(f"   Traffic types : TCP (HTTP, HTTPS, SSH, SMTP, MySQL, SMB, PostgreSQL, HTTP-Alt)")
print(f"                   UDP (DNS x{60}, NTP x{10}, SNMP x{8})")
print(f"                   ICMP (Ping x{20})")
print(f"   NAT bypasses  : workstation-A ({20} pkts), workstation-B ({18+10} pkts), dev-machine ({12} pkts)")
print(f"   High-risk     : SMTP to Tor exit node (185.220.101.4)")
print(f"\n   Upload this file at: http://localhost:5173  →  'Upload PCAP' button")
