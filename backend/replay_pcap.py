import socket
import time
import sys
try:
    from scapy.all import rdpcap, UDP
except ImportError:
    print("Please install scapy: pip install scapy")
    sys.exit(1)

def replay_pcap(pcap_file, target_ip="127.0.0.1", target_port=2055):
    print(f"Reading {pcap_file}...")
    packets = rdpcap(pcap_file)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    count = 0
    
    print(f"Replaying NetFlow packets to {target_ip}:{target_port}...")
    for pkt in packets:
        if UDP in pkt and pkt[UDP].dport == target_port:
            payload = bytes(pkt[UDP].payload)
            if payload:
                sock.sendto(payload, (target_ip, target_port))
                count += 1
                # Add a small delay to simulate real-time traffic
                time.sleep(0.01)
                
    print(f"Replay complete. Sent {count} NetFlow packets.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python replay_pcap.py <path_to_pcap>")
        # If no pcap provided, we will just exit or we could generate fake data.
        # But user explicitly requested real pcap file.
        print("Please download a sample NetFlow v5 pcap and run this script.")
        sys.exit(1)
        
    pcap_path = sys.argv[1]
    replay_pcap(pcap_path)
