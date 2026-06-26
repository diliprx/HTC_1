# import asyncio
# import struct
# import socket
# from datetime import datetime
# from database import get_connection

# class NetFlowV5Protocol(asyncio.DatagramProtocol):
#     def __init__(self):
#         super().__init__()
#         # We will batch inserts for better performance
#         self.batch = []
#         self.batch_size = 100
#         self.conn = get_connection()
#         self.header_format = '!HHIIIIBBH'
#         self.header_size = struct.calcsize(self.header_format)
#         self.record_format = '!IIIIIIIIIIHHBBBBHHBBH'
#         self.record_size = struct.calcsize(self.record_format)

#     def connection_made(self, transport):
#         self.transport = transport
#         print("NetFlow Collector started on UDP port 2055")

#     def datagram_received(self, data, addr):
#         try:
#             if len(data) < self.header_size:
#                 return
            
#             # Parse header
#             header = struct.unpack(self.header_format, data[:self.header_size])
#             version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, engine_type, engine_id, sampling = header
            
#             if version != 5:
#                 # We only support v5 in this implementation
#                 return

#             offset = self.header_size
#             for _ in range(count):
#                 if offset + self.record_size > len(data):
#                     break
                
#                 record = struct.unpack(self.record_format, data[offset:offset+self.record_size])
#                 offset += self.record_size
                
#                 # Extract fields
#                 src_ip = socket.inet_ntoa(struct.pack('!I', record[0]))
#                 dst_ip = socket.inet_ntoa(struct.pack('!I', record[1]))
#                 nexthop = socket.inet_ntoa(struct.pack('!I', record[2]))
                
#                 input_snmp = record[3]
#                 output_snmp = record[4]
#                 packets = record[5]
#                 bytes_count = record[6]
#                 first_switched = record[7]
#                 last_switched = record[8]
#                 src_port = record[9]
#                 dst_port = record[10]
#                 pad1 = record[11]
#                 tcp_flags = record[12]
#                 protocol = record[13]
#                 tos = record[14]
#                 src_as = record[15]
#                 dst_as = record[16]
#                 src_mask = record[17]
#                 dst_mask = record[18]
#                 pad2 = record[19]
                
#                 now = datetime.now()
                
#                 self.batch.append((
#                     src_ip, dst_ip, nexthop, input_snmp, output_snmp,
#                     packets, bytes_count, first_switched, last_switched,
#                     src_port, dst_port, tcp_flags, protocol, tos,
#                     src_as, dst_as, src_mask, dst_mask, now
#                 ))

#             if len(self.batch) >= self.batch_size:
#                 self.flush_batch()
                
#         except Exception as e:
#             print(f"Error processing packet: {e}")

#     def flush_batch(self):
#         if not self.batch:
#             return
        
#         try:
#             self.conn.executemany("""
#                 INSERT INTO flows (
#                     id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
#                     packets, bytes, first_switched, last_switched,
#                     src_port, dst_port, tcp_flags, protocol, tos,
#                     src_as, dst_as, src_mask, dst_mask, timestamp
#                 ) VALUES (nextval('flow_id_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
#             """, self.batch)
#             self.batch.clear()
#         except Exception as e:
#             print(f"Error inserting batch: {e}")

# async def start_collector(host="0.0.0.0", port=2055):
#     loop = asyncio.get_running_loop()
#     transport, protocol = await loop.create_datagram_endpoint(
#         lambda: NetFlowV5Protocol(),
#         local_addr=(host, port)
#     )
#     return transport, protocol

# if __name__ == "__main__":
#     from database import init_db
#     init_db()
#     loop = asyncio.get_event_loop()
#     transport, protocol = loop.run_until_complete(start_collector())
#     try:
#         loop.run_forever()
#     except KeyboardInterrupt:
#         pass
#     finally:
#         transport.close()
#         loop.close()

import asyncio
import struct
import socket
from datetime import datetime
from database import get_connection, get_lock

# NetFlow v5 header: version(2) count(2) uptime(4) unix_secs(4) unix_nsecs(4)
#                    flow_seq(4) engine_type(1) engine_id(1) sampling(2) = 24 bytes
HEADER_FORMAT = '!HHIIIIBBH'
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)   # 24 bytes

# NetFlow v5 record (official 48-byte layout):
#   srcaddr(4) dstaddr(4) nexthop(4)
#   input(2)  output(2)                    <-- H H  not I I  (the original bug)
#   dPkts(4)  dOctets(4) First(4) Last(4)
#   srcport(2) dstport(2)
#   pad1(1) tcp_flags(1) prot(1) tos(1)
#   src_as(2) dst_as(2)
#   src_mask(1) dst_mask(1) pad2(2)
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

class NetFlowV5Protocol(asyncio.DatagramProtocol):
    def __init__(self):
        super().__init__()
        self.batch      = []
        self.batch_size = 100

    def connection_made(self, transport):
        self.transport = transport
        print("NetFlow v5 Collector started on UDP port 2055")

    def datagram_received(self, data, addr):
        try:
            if len(data) < HEADER_SIZE:
                return
            header = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
            version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, engine_type, engine_id, sampling = header
            if version != 5:
                return

            offset = HEADER_SIZE
            for _ in range(count):
                if offset + RECORD_SIZE > len(data):
                    break
                record = struct.unpack(RECORD_FORMAT, data[offset:offset + RECORD_SIZE])
                offset += RECORD_SIZE

                src_ip   = socket.inet_ntoa(struct.pack('!I', record[0]))
                dst_ip   = socket.inet_ntoa(struct.pack('!I', record[1]))
                nexthop  = socket.inet_ntoa(struct.pack('!I', record[2]))

                # record indices after fix (H H for input/output):
                # [0]=srcaddr [1]=dstaddr [2]=nexthop
                # [3]=input   [4]=output
                # [5]=dPkts   [6]=dOctets [7]=First [8]=Last
                # [9]=srcport [10]=dstport
                # [11]=pad1   [12]=tcp_flags [13]=prot [14]=tos
                # [15]=src_as [16]=dst_as [17]=src_mask [18]=dst_mask [19]=pad2
                self.batch.append((
                    src_ip, dst_ip, nexthop,
                    record[3], record[4],          # input_snmp, output_snmp
                    record[5], record[6],          # packets, bytes
                    record[7], record[8],          # first_switched, last_switched
                    record[9], record[10],         # src_port, dst_port
                    record[12], record[13], record[14],  # tcp_flags, protocol, tos
                    record[15], record[16], record[17], record[18],  # AS + masks
                    datetime.fromtimestamp(unix_secs)
                ))

            if len(self.batch) >= self.batch_size:
                self._flush()

        except Exception as e:
            print(f"[Collector] Error processing datagram: {e}")

    def _flush(self):
        if not self.batch:
            return
        lock = get_lock()
        conn = get_connection()
        with lock:
            try:
                conn.executemany(INSERT_SQL, self.batch)
                conn.commit()          # FIX: was missing commit
                self.batch.clear()
            except Exception as e:
                print(f"[Collector] DB flush error: {e}")

    def error_received(self, exc):
        print(f"[Collector] Socket error: {exc}")

    def connection_lost(self, exc):
        self._flush()   # drain remaining on shutdown
        print("[Collector] Connection closed, remaining batch flushed.")


# Global transport reference so main.py can close it on shutdown
_transport = None

async def start_collector(host="0.0.0.0", port=2055):
    global _transport
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: NetFlowV5Protocol(),
        local_addr=(host, port)
    )
    _transport = transport
    print(f"[Collector] Listening on {host}:{port}")
    # Keep running until cancelled
    try:
        await asyncio.Future()   # run forever
    except asyncio.CancelledError:
        pass
    finally:
        transport.close()
        print("[Collector] Transport closed cleanly.")

def stop_collector():
    global _transport
    if _transport:
        _transport.close()
        _transport = None


if __name__ == "__main__":
    from database import init_db
    init_db()
    asyncio.run(start_collector())
