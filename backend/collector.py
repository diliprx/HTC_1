"""
HTC NetFlow Collector Pro — High-Performance Async UDP Daemon
=============================================================
RFC-compliant NetFlow v5 receiver on UDP port 2055 with micro-batching,
auto-flush watchdog, and UTC ISO timestamping.
"""

import asyncio
import struct
import socket
from datetime import datetime, timezone
from database import get_connection, get_lock

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

class NetFlowV5Protocol(asyncio.DatagramProtocol):
    def __init__(self, batch_size=20, flush_interval=2.0):
        super().__init__()
        self.batch          = []
        self.batch_size     = batch_size
        self.flush_interval = flush_interval
        self.flush_handle   = None
        self.total_received = 0

    def connection_made(self, transport):
        self.transport = transport
        loop = asyncio.get_event_loop()
        self._schedule_flush(loop)
        print("[Collector] NetFlow v5 Engine active on UDP 2055.")

    def _schedule_flush(self, loop):
        self.flush_handle = loop.call_later(self.flush_interval, self._periodic_flush, loop)

    def _periodic_flush(self, loop):
        if self.batch:
            self._flush()
        self._schedule_flush(loop)

    def datagram_received(self, data, addr):
        try:
            if len(data) < HEADER_SIZE:
                return
            header = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
            version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, engine_type, engine_id, sampling = header
            if version != 5:
                return

            # Format UTC timestamp string
            try:
                dt_str = datetime.fromtimestamp(unix_secs, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                dt_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            offset = HEADER_SIZE
            for _ in range(count):
                if offset + RECORD_SIZE > len(data):
                    break
                record = struct.unpack(RECORD_FORMAT, data[offset:offset + RECORD_SIZE])
                offset += RECORD_SIZE

                src_ip   = socket.inet_ntoa(struct.pack('!I', record[0]))
                dst_ip   = socket.inet_ntoa(struct.pack('!I', record[1]))
                nexthop  = socket.inet_ntoa(struct.pack('!I', record[2]))

                self.batch.append((
                    src_ip, dst_ip, nexthop,
                    record[3], record[4],
                    record[5], record[6],
                    record[7], record[8],
                    record[9], record[10],
                    record[12], record[13], record[14],
                    record[15], record[16], record[17], record[18],
                    dt_str
                ))
                self.total_received += 1

            if len(self.batch) >= self.batch_size:
                self._flush()

        except Exception as e:
            print(f"[Collector] Datagram decode error: {e}")

    def _flush(self):
        if not self.batch:
            return
        lock = get_lock()
        conn = get_connection()
        with lock:
            try:
                conn.executemany(INSERT_SQL, self.batch)
                conn.commit()
                self.batch.clear()
            except Exception as e:
                conn.rollback()
                print(f"[Collector] Database batch flush error: {e}")

    def error_received(self, exc):
        print(f"[Collector] Socket communication error: {exc}")

    def connection_lost(self, exc):
        if self.flush_handle:
            self.flush_handle.cancel()
        if self.batch:
            self._flush()
        print("[Collector] UDP Endpoint terminated cleanly.")


_transport = None

async def start_collector(host="0.0.0.0", port=2055):
    global _transport
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: NetFlowV5Protocol(),
        local_addr=(host, port)
    )
    _transport = transport
    try:
        await asyncio.Future()
    except asyncio.CancelledError:
        pass
    finally:
        transport.close()


def stop_collector():
    global _transport
    if _transport:
        _transport.close()
        _transport = None


if __name__ == "__main__":
    from database import init_db
    init_db()
    asyncio.run(start_collector())
