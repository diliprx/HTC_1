from database import get_connection, init_db
from pcap_parser import parse_pcap_file

init_db()

conn = get_connection()
before = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
print(f"Flows before parse: {before}")
conn.close()

count, msg = parse_pcap_file("test_traffic.pcap")
print(f"Flows inserted by parser: {count}")
print(f"Message: {msg}")

conn = get_connection()
after = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
print(f"Flows after parse: {after}")

# Show distinct src/dst pairs to verify
rows = conn.execute("""
    SELECT src_ip, dst_ip, protocol, COUNT(*) as c 
    FROM flows 
    GROUP BY src_ip, dst_ip, protocol 
    ORDER BY c DESC 
    LIMIT 10
""").fetchall()
print("\nTop flow groups:")
for row in rows:
    proto = {6:'TCP', 17:'UDP', 1:'ICMP'}.get(row[2], str(row[2]))
    print(f"  {row[0]:16} -> {row[1]:16} [{proto}]  count={row[3]}")
conn.close()
