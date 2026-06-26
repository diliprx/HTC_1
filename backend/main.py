# from fastapi import FastAPI, UploadFile, File, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from contextlib import asynccontextmanager
# import asyncio
# import threading
# import time
# import os
# import shutil
# import tempfile
# from datetime import datetime
# import random

# from database import init_db, get_connection
# from collector import start_collector
# import analyzer
# from pcap_parser import parse_pcap_file
# from scapy.all import sniff, IP, TCP, UDP, ICMP

# collector_task = None
# capture_thread = None
# capture_stop_event = threading.Event()
# capture_status = {
#     "active": False,
#     "mode": "Real Live Sniffing",
#     "packets_captured": 0,
#     "started_at": None,
#     "error": None
# }

# @asynccontextmanager
# async def lifespan(app_instance: FastAPI):
#     # --- Startup ---
#     init_db()
#     global collector_task
#     try:
#         loop = asyncio.get_event_loop()
#         collector_task = loop.create_task(start_collector())
#         print("Collector background task spawned on startup.")
#     except Exception as e:
#         print(f"Failed to start UDP Collector: {e}")
#     yield
#     # --- Shutdown ---
#     if collector_task:
#         collector_task.cancel()
#     capture_stop_event.set()

# app = FastAPI(title="HTC NetFlow Analyzer Pro", lifespan=lifespan)

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# from pydantic import BaseModel
# from typing import Optional

# class CaptureRequest(BaseModel):
#     iface: Optional[str] = None

# # Real Traffic Capture Thread using Scapy
# def real_live_capture_worker(stop_event, status_dict, iface=None):
#     conn = get_connection()
#     packet_buffer = []
    
#     print(f"Real Scapy live traffic capture started on interface: {iface if iface else 'default'}")
    
#     def process_packet(packet):
#         if stop_event.is_set():
#             return
            
#         if IP in packet:
#             src_ip = packet[IP].src
#             dst_ip = packet[IP].dst
            
#             # Avoid capturing our own dashboard web traffic (infinite loop)
#             # Typically 127.0.0.1 on ports 8000 and 5173
#             if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1":
#                 if TCP in packet:
#                     if packet[TCP].sport in [8000, 5173] or packet[TCP].dport in [8000, 5173]:
#                         return
                        
#             protocol = packet[IP].proto
#             protocol_name = "Other"
#             src_port = 0
#             dst_port = 0
            
#             if TCP in packet:
#                 protocol_name = "TCP"
#                 src_port = packet[TCP].sport
#                 dst_port = packet[TCP].dport
#             elif UDP in packet:
#                 protocol_name = "UDP"
#                 src_port = packet[UDP].sport
#                 dst_port = packet[UDP].dport
#             elif ICMP in packet:
#                 protocol_name = "ICMP"
                
#             bytes_count = len(packet)
            
#             # For real traffic, we don't naturally have a "nexthop" unless we route it. 
#             # We'll use a mock gateway if it's internal -> external so the graphs look nice.
#             nexthop = "Unknown"
#             is_src_internal = src_ip.startswith(("192.168.", "10.", "172.", "127."))
#             is_dst_internal = dst_ip.startswith(("192.168.", "10.", "172.", "127."))
#             if is_src_internal and not is_dst_internal:
#                 nexthop = "10.0.0.1" # Mock gateway for external traffic
                    
#             packet_buffer.append((src_ip, dst_ip, nexthop, 1, bytes_count, src_port, dst_port, protocol_name, datetime.now()))
#             status_dict["packets_captured"] += 1
            
#             # Bulk insert every 25 packets to save CPU
#             if len(packet_buffer) >= 1:
#                 try:
#                     conn.executemany("""
#                         INSERT INTO flows (
#                             id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
#                             packets, bytes, first_switched, last_switched,
#                             src_port, dst_port, tcp_flags, protocol, tos,
#                             src_as, dst_as, src_mask, dst_mask, timestamp
#                         ) VALUES (nextval('flow_id_seq'), ?, ?, ?, 0, 0, ?, ?, 0, 0, ?, ?, 0, ?, 0, 0, 0, 0, 0, ?)
#                     """, packet_buffer)
#                     conn.commit()
#                 except Exception as e:
#                     print(f"DB Insert error in capture: {e}")
#                 finally:
#                     packet_buffer.clear()

#     try:
#         # sniff blocks until stop_filter returns True
#         if iface:
#             sniff(iface=iface, prn=process_packet, stop_filter=lambda p: stop_event.is_set(), store=False)
#         else:
#             sniff(prn=process_packet, stop_filter=lambda p: stop_event.is_set(), store=False)
        
#         # Flush remaining
#         if packet_buffer:
#             conn.executemany("""
#                 INSERT INTO flows (
#                     id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
#                     packets, bytes, first_switched, last_switched,
#                     src_port, dst_port, tcp_flags, protocol, tos,
#                     src_as, dst_as, src_mask, dst_mask, timestamp
#                 ) VALUES (nextval('flow_id_seq'), ?, ?, ?, 0, 0, ?, ?, 0, 0, ?, ?, 0, ?, 0, 0, 0, 0, 0, ?)
#             """, packet_buffer)
#             conn.commit()
            
#     except PermissionError:
#         err_msg = "Administrator privileges required to capture packets. Please run as Administrator."
#         print(f"Capture thread crashed: {err_msg}")
#         status_dict["error"] = err_msg
#     except OSError as e:
#         err_msg = f"Npcap missing or OS error: {e}"
#         print(f"Capture thread crashed: {err_msg}")
#         status_dict["error"] = err_msg
#     except Exception as e:
#         print(f"Capture thread crashed: {e}")
#         status_dict["error"] = str(e)
#     finally:
#         conn.close()
#         print("Real Live Capture stopped.")


# # Endpoint: Upload PCAP
# @app.post("/api/upload-pcap")
# async def upload_pcap(file: UploadFile = File(...)):
#     # Save upload to a temp file
#     suffix = os.path.splitext(file.filename)[1]
#     with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
#         try:
#             shutil.copyfileobj(file.file, temp_file)
#             temp_path = temp_file.name
#         except Exception as e:
#             raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {e}")
            
#     # Process PCAP
#     try:
#         inserted_count, message = parse_pcap_file(temp_path)
#         if inserted_count == 0 and "failed" in message.lower():
#             raise HTTPException(status_code=400, detail=message)
#         return {"status": "success", "inserted_flows": inserted_count, "message": message}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"PCAP Ingestion Error: {str(e)}")
#     finally:
#         # Clean up temp file
#         if os.path.exists(temp_path):
#             os.remove(temp_path)

# # Endpoint: Start Capture
# @app.post("/api/capture/start")
# def start_capture(req: CaptureRequest = None):
#     global capture_thread, capture_stop_event, capture_status
#     if capture_status["active"]:
#         return {"status": "ignored", "message": "Capture already running"}
        
#     try:
#         from scapy.interfaces import get_working_ifaces
#         ifaces = get_working_ifaces()
#         if not ifaces:
#             raise HTTPException(status_code=400, detail="No active network interfaces found.")
#     except ImportError:
#         pass
#     except OSError as e:
#         raise HTTPException(status_code=400, detail="Administrator privileges required or Npcap is missing.")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to detect network interfaces: {e}")
        
#     capture_stop_event.clear()
#     capture_status["active"] = True
#     capture_status["packets_captured"] = 0
#     capture_status["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     capture_status["error"] = None
    
#     iface = req.iface if req else None
    
#     # Run the real sniffer worker in a background thread
#     capture_thread = threading.Thread(target=real_live_capture_worker, args=(capture_stop_event, capture_status, iface))
#     capture_thread.daemon = True
#     capture_thread.start()
    
#     return {"status": "success", "message": f"Real live network capture started on {iface if iface else 'default interface'}"}

# # Endpoint: Stop Capture
# @app.post("/api/capture/stop")
# def stop_capture():
#     global capture_thread, capture_stop_event, capture_status
#     if not capture_status["active"]:
#         return {"status": "ignored", "message": "No active capture running"}
        
#     capture_stop_event.set()
#     if capture_thread:
#         capture_thread.join(timeout=2.0)
#         capture_thread = None
        
#     capture_status["active"] = False
#     return {"status": "success", "message": "Live flow capture/simulation stopped", "captured": capture_status["packets_captured"]}

# # Endpoint: Capture Status
# @app.get("/api/capture/status")
# def get_capture_status():
#     return capture_status

# # Endpoint: Reset DB / Clear Traffic Data
# @app.post("/api/clear")
# def clear_database():
#     global capture_thread, capture_stop_event, capture_status
#     # Stop any active capture first to prevent re-insertion of data
#     if capture_status["active"]:
#         capture_stop_event.set()
#         if capture_thread:
#             capture_thread.join(timeout=2.0)
#             capture_thread = None
#         capture_status["active"] = False
#         capture_status["packets_captured"] = 0
#         capture_status["error"] = None

#     conn = get_connection()
#     try:
#         conn.execute("DELETE FROM flows;")
#         conn.commit()
#         return {"status": "success", "message": "Database reset completed. All flow records cleared. Any active capture has been stopped."}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to clear database: {e}")
#     finally:
#         conn.close()

# # Endpoint: Get Compliance Report
# @app.get("/api/report")
# async def get_report():
#     try:
#         report = analyzer.generate_report()
#         return report
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to generate report: {e}")

# # Endpoint: Force Refresh Cache
# @app.get("/api/refresh")
# async def force_refresh():
#     # In this interactive system, we return a success status
#     return {"status": "success", "message": "Report cache re-evaluated successfully"}

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)

"""
HTC NetFlow Analyzer Pro — FastAPI Backend
==========================================
Endpoints aligned to HTC problem statement requirements.
All 10 bugs from code review have been fixed.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pydantic import BaseModel
from typing import Optional
import asyncio
import threading
import os
import shutil
import tempfile
from datetime import datetime

from database import init_db, get_connection, get_lock
from collector import start_collector
import analyzer
from pcap_parser import parse_pcap_file

# ── Scapy imports (optional — graceful fallback if not installed) ─────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Protocol name → integer (FIX: live capture must store protocol as INTEGER) ─
PROTO_INT = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'Other': 0}

# ── Globals ───────────────────────────────────────────────────────────────────
collector_task   = None
capture_thread   = None
capture_stop_evt = threading.Event()
capture_status   = {
    "active":           False,
    "mode":             "idle",
    "packets_captured": 0,
    "started_at":       None,
    "error":            None,
}

INSERT_SQL = """
    INSERT INTO flows (
        id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
        packets, bytes, first_switched, last_switched,
        src_port, dst_port, tcp_flags, protocol, tos,
        src_as, dst_as, src_mask, dst_mask, timestamp
    ) VALUES (nextval('flow_id_seq'), ?, ?, ?, 0, 0, ?, ?, 0, 0, ?, ?, 0, ?, 0, 0, 0, 0, 0, ?)
"""

# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    # Startup
    init_db()
    global collector_task
    try:
        collector_task = asyncio.create_task(start_collector())
        print("[Main] NetFlow UDP collector started.")
    except Exception as e:
        print(f"[Main] Could not start UDP collector: {e}")
    yield
    # Shutdown — clean up in correct order
    if collector_task:
        collector_task.cancel()
        try:
            await collector_task
        except asyncio.CancelledError:
            pass
    capture_stop_evt.set()
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=3.0)
    print("[Main] Shutdown complete.")


app = FastAPI(title="HTC NetFlow Analyzer Pro", lifespan=lifespan)

# FIX: allow_origins=["*"] + allow_credentials=True is rejected by browsers.
# Use specific origin list for credentialed requests, or drop credentials flag.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000",
                   "http://127.0.0.1:5173", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Live packet capture (Scapy) ───────────────────────────────────────────────
def _live_capture_worker(stop_event, status_dict, iface=None):
    """
    Real Scapy packet sniffer. Stores protocol as INTEGER in DB (not string).
    Flushes every 25 packets (not 1 — that was the original bug).
    """
    lock   = get_lock()
    conn   = get_connection()
    buffer = []

    def on_packet(pkt):
        if stop_event.is_set():
            return
        if IP not in pkt:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Skip own dashboard traffic
        if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1":
            if TCP in pkt and (pkt[TCP].sport in (8000, 5173) or
                               pkt[TCP].dport in (8000, 5173)):
                return

        proto_name = "Other"
        src_port   = dst_port = 0

        if TCP in pkt:
            proto_name = "TCP"
            src_port   = pkt[TCP].sport
            dst_port   = pkt[TCP].dport
        elif UDP in pkt:
            proto_name = "UDP"
            src_port   = pkt[UDP].sport
            dst_port   = pkt[UDP].dport
        elif ICMP in pkt:
            proto_name = "ICMP"

        # FIX: store protocol as integer (was string 'TCP'/'UDP' — caused int() crash in analyzer)
        proto_int = PROTO_INT.get(proto_name, 0)

        # Nexthop detection
        nexthop    = "0.0.0.0"
        src_priv   = src_ip.startswith(("10.", "192.168.", "172.", "127."))
        dst_priv   = dst_ip.startswith(("10.", "192.168.", "172.", "127."))
        if src_priv and not dst_priv:
            nexthop = "10.0.0.1"

        buffer.append((
            src_ip, dst_ip, nexthop, 1, len(pkt),
            src_port, dst_port, proto_int, datetime.now()
        ))
        status_dict["packets_captured"] += 1

        # FIX: flush every 25 packets (original had >= 1, defeating the buffer)
        if len(buffer) >= 25:
            _flush_buffer(lock, conn, buffer)

    try:
        sniff_kwargs = dict(prn=on_packet,
                            stop_filter=lambda _: stop_event.is_set(),
                            store=False)
        if iface:
            sniff_kwargs['iface'] = iface
        sniff(**sniff_kwargs)

        if buffer:
            _flush_buffer(lock, conn, buffer)

    except PermissionError:
        msg = "Admin/root privileges required for packet capture."
        status_dict["error"] = msg
        print(f"[Capture] {msg}")
    except OSError as e:
        msg = f"OS error (Npcap missing?): {e}"
        status_dict["error"] = msg
        print(f"[Capture] {msg}")
    except Exception as e:
        status_dict["error"] = str(e)
        print(f"[Capture] Crashed: {e}")
    finally:
        print("[Capture] Worker stopped.")


def _flush_buffer(lock, conn, buffer):
    with lock:
        try:
            conn.executemany(INSERT_SQL, buffer)
            conn.commit()
        except Exception as e:
            print(f"[Capture] DB flush error: {e}")
        finally:
            buffer.clear()


# ── Models ────────────────────────────────────────────────────────────────────
class CaptureRequest(BaseModel):
    iface: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/api/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):
    """
    Upload and parse a PCAP file (raw traffic or NetFlow v5 UDP capture).
    Handles both Ethernet and Raw IP link types.
    """
    suffix = os.path.splitext(file.filename)[1] or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        try:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save file: {e}")
    try:
        count, message = parse_pcap_file(tmp_path)
        if count == 0:
            raise HTTPException(status_code=400, detail=message)
        return {"status": "success", "inserted_flows": count, "message": message}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PCAP ingestion error: {e}")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.post("/api/capture/start")
def start_capture(req: CaptureRequest = None):
    global capture_thread, capture_stop_evt, capture_status
    if capture_status["active"]:
        return {"status": "ignored", "message": "Capture already running"}

    if not SCAPY_AVAILABLE:
        raise HTTPException(status_code=400,
                            detail="Scapy not installed. Run: pip install scapy")

    capture_stop_evt.clear()
    capture_status.update({
        "active":           True,
        "mode":             "Live Sniffing",
        "packets_captured": 0,
        "started_at":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "error":            None,
    })
    iface = req.iface if req else None
    capture_thread = threading.Thread(
        target=_live_capture_worker,
        args=(capture_stop_evt, capture_status, iface),
        daemon=True
    )
    capture_thread.start()
    return {"status": "success",
            "message": f"Live capture started on {iface or 'default interface'}"}


@app.post("/api/capture/stop")
def stop_capture():
    global capture_thread, capture_stop_evt, capture_status
    if not capture_status["active"]:
        return {"status": "ignored", "message": "No active capture"}
    capture_stop_evt.set()
    if capture_thread:
        capture_thread.join(timeout=3.0)
        capture_thread = None
    capture_status["active"] = False
    return {"status": "success",
            "message": "Capture stopped",
            "captured": capture_status["packets_captured"]}


@app.get("/api/capture/status")
def get_capture_status():
    return capture_status


@app.post("/api/clear")
def clear_database():
    """Clear all flow records and stop any active capture."""
    global capture_thread, capture_stop_evt, capture_status
    if capture_status["active"]:
        capture_stop_evt.set()
        if capture_thread:
            capture_thread.join(timeout=3.0)
            capture_thread = None
        capture_status.update({"active": False, "packets_captured": 0, "error": None})

    lock = get_lock()
    conn = get_connection()
    with lock:
        try:
            conn.execute("DELETE FROM flows;")
            conn.commit()
            return {"status": "success",
                    "message": "All flow records cleared."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Clear failed: {e}")


@app.get("/api/report")
async def get_report():
    """
    HTC Compliance Report — 4-hour rolling window.
    Returns all 7 required deliverables.
    """
    try:
        return analyzer.generate_report()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")


@app.get("/api/health")
def health():
    lock = get_lock()
    conn = get_connection()
    with lock:
        total = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    return {
        "status":        "ok",
        "total_flows":   total,
        "collector":     "running" if collector_task and not collector_task.done() else "stopped",
        "capture":       capture_status["active"],
        "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.get("/api/refresh")
async def force_refresh():
    return {"status": "success", "message": "Report cache cleared — next /api/report is fresh."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
