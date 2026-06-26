import asyncio
import struct
import socket
from datetime import datetime
from database import get_connection

class NetFlowV5Protocol(asyncio.DatagramProtocol):
    def __init__(self):
        super().__init__()
        # We will batch inserts for better performance
        self.batch = []
        self.batch_size = 100
        self.conn = get_connection()
        self.header_format = '!HHIIIIBBH'
        self.header_size = struct.calcsize(self.header_format)
        self.record_format = '!IIIIIIIIIIHHBBBBHHBBH'
        self.record_size = struct.calcsize(self.record_format)

    def connection_made(self, transport):
        self.transport = transport
        print("NetFlow Collector started on UDP port 2055")

    def datagram_received(self, data, addr):
        try:
            if len(data) < self.header_size:
                return
            
            # Parse header
            header = struct.unpack(self.header_format, data[:self.header_size])
            version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, engine_type, engine_id, sampling = header
            
            if version != 5:
                # We only support v5 in this implementation
                return

            offset = self.header_size
            for _ in range(count):
                if offset + self.record_size > len(data):
                    break
                
                record = struct.unpack(self.record_format, data[offset:offset+self.record_size])
                offset += self.record_size
                
                # Extract fields
                src_ip = socket.inet_ntoa(struct.pack('!I', record[0]))
                dst_ip = socket.inet_ntoa(struct.pack('!I', record[1]))
                nexthop = socket.inet_ntoa(struct.pack('!I', record[2]))
                
                input_snmp = record[3]
                output_snmp = record[4]
                packets = record[5]
                bytes_count = record[6]
                first_switched = record[7]
                last_switched = record[8]
                src_port = record[9]
                dst_port = record[10]
                pad1 = record[11]
                tcp_flags = record[12]
                protocol = record[13]
                tos = record[14]
                src_as = record[15]
                dst_as = record[16]
                src_mask = record[17]
                dst_mask = record[18]
                pad2 = record[19]
                
                now = datetime.now()
                
                self.batch.append((
                    src_ip, dst_ip, nexthop, input_snmp, output_snmp,
                    packets, bytes_count, first_switched, last_switched,
                    src_port, dst_port, tcp_flags, protocol, tos,
                    src_as, dst_as, src_mask, dst_mask, now
                ))

            if len(self.batch) >= self.batch_size:
                self.flush_batch()
                
        except Exception as e:
            print(f"Error processing packet: {e}")

    def flush_batch(self):
        if not self.batch:
            return
        
        try:
            self.conn.executemany("""
                INSERT INTO flows (
                    id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
                    packets, bytes, first_switched, last_switched,
                    src_port, dst_port, tcp_flags, protocol, tos,
                    src_as, dst_as, src_mask, dst_mask, timestamp
                ) VALUES (nextval('flow_id_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, self.batch)
            self.batch.clear()
        except Exception as e:
            print(f"Error inserting batch: {e}")

async def start_collector(host="0.0.0.0", port=2055):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: NetFlowV5Protocol(),
        local_addr=(host, port)
    )
    return transport, protocol

if __name__ == "__main__":
    from database import init_db
    init_db()
    loop = asyncio.get_event_loop()
    transport, protocol = loop.run_until_complete(start_collector())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        transport.close()
        loop.close()
