import dpkt, socket

with open("test_traffic.pcap", "rb") as f:
    pcap = dpkt.pcap.Reader(f)
    print(f"Link type: {pcap.datalink()}")  # 1 = Ethernet, 228 = Raw IP
    
    count = 0
    eth_ok = 0
    ip_ok = 0
    
    for ts, buf in pcap:
        count += 1
        if count > 5:
            break
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            eth_ok += 1
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                ip_ok += 1
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                print(f"  Packet {count}: {src} -> {dst} proto={ip.p}")
        except Exception as e:
            print(f"  Packet {count}: parse error: {e}")
            # Try raw IP
            try:
                ip = dpkt.ip.IP(buf)
                print(f"  Packet {count} (raw IP): {socket.inet_ntoa(ip.src)} -> {socket.inet_ntoa(ip.dst)}")
            except Exception as e2:
                print(f"  Also failed as raw IP: {e2}")
