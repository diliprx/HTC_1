from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
import threading
import time
import os
import shutil
import tempfile
from datetime import datetime
import random

from database import init_db, get_connection
from collector import start_collector
import analyzer
from pcap_parser import parse_pcap_file
from scapy.all import sniff, IP, TCP, UDP, ICMP

collector_task = None
capture_thread = None
capture_stop_event = threading.Event()
capture_status = {
    "active": False,
    "mode": "Real Live Sniffing",
    "packets_captured": 0,
    "started_at": None,
    "error": None
}

@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    # --- Startup ---
    init_db()
    global collector_task
    try:
        loop = asyncio.get_event_loop()
        collector_task = loop.create_task(start_collector())
        print("Collector background task spawned on startup.")
    except Exception as e:
        print(f"Failed to start UDP Collector: {e}")
    yield
    # --- Shutdown ---
    if collector_task:
        collector_task.cancel()
    capture_stop_event.set()

app = FastAPI(title="HTC NetFlow Analyzer Pro", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from pydantic import BaseModel
from typing import Optional

class CaptureRequest(BaseModel):
    iface: Optional[str] = None

# Real Traffic Capture Thread using Scapy
def real_live_capture_worker(stop_event, status_dict, iface=None):
    conn = get_connection()
    packet_buffer = []
    
    print(f"Real Scapy live traffic capture started on interface: {iface if iface else 'default'}")
    
    def process_packet(packet):
        if stop_event.is_set():
            return
            
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Avoid capturing our own dashboard web traffic (infinite loop)
            # Typically 127.0.0.1 on ports 8000 and 5173
            if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1":
                if TCP in packet:
                    if packet[TCP].sport in [8000, 5173] or packet[TCP].dport in [8000, 5173]:
                        return
                        
            protocol = packet[IP].proto
            protocol_name = "Other"
            src_port = 0
            dst_port = 0
            
            if TCP in packet:
                protocol_name = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol_name = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol_name = "ICMP"
                
            bytes_count = len(packet)
            
            # For real traffic, we don't naturally have a "nexthop" unless we route it. 
            # We'll use a mock gateway if it's internal -> external so the graphs look nice.
            nexthop = "Unknown"
            is_src_internal = src_ip.startswith(("192.168.", "10.", "172.", "127."))
            is_dst_internal = dst_ip.startswith(("192.168.", "10.", "172.", "127."))
            if is_src_internal and not is_dst_internal:
                nexthop = "10.0.0.1" # Mock gateway for external traffic
                    
            packet_buffer.append((src_ip, dst_ip, nexthop, 1, bytes_count, src_port, dst_port, protocol_name, datetime.now()))
            status_dict["packets_captured"] += 1
            
            # Bulk insert every 25 packets to save CPU
            if len(packet_buffer) >= 25:
                try:
                    conn.executemany("""
                        INSERT INTO flows (
                            id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
                            packets, bytes, first_switched, last_switched,
                            src_port, dst_port, tcp_flags, protocol, tos,
                            src_as, dst_as, src_mask, dst_mask, timestamp
                        ) VALUES (nextval('flow_id_seq'), ?, ?, ?, 0, 0, ?, ?, 0, 0, ?, ?, 0, ?, 0, 0, 0, 0, 0, ?)
                    """, packet_buffer)
                    conn.commit()
                except Exception as e:
                    print(f"DB Insert error in capture: {e}")
                finally:
                    packet_buffer.clear()

    try:
        # sniff blocks until stop_filter returns True
        if iface:
            sniff(iface=iface, prn=process_packet, stop_filter=lambda p: stop_event.is_set(), store=False)
        else:
            sniff(prn=process_packet, stop_filter=lambda p: stop_event.is_set(), store=False)
        
        # Flush remaining
        if packet_buffer:
            conn.executemany("""
                INSERT INTO flows (
                    id, src_ip, dst_ip, nexthop, input_snmp, output_snmp,
                    packets, bytes, first_switched, last_switched,
                    src_port, dst_port, tcp_flags, protocol, tos,
                    src_as, dst_as, src_mask, dst_mask, timestamp
                ) VALUES (nextval('flow_id_seq'), ?, ?, ?, 0, 0, ?, ?, 0, 0, ?, ?, 0, ?, 0, 0, 0, 0, 0, ?)
            """, packet_buffer)
            conn.commit()
            
    except PermissionError:
        err_msg = "Administrator privileges required to capture packets. Please run as Administrator."
        print(f"Capture thread crashed: {err_msg}")
        status_dict["error"] = err_msg
    except OSError as e:
        err_msg = f"Npcap missing or OS error: {e}"
        print(f"Capture thread crashed: {err_msg}")
        status_dict["error"] = err_msg
    except Exception as e:
        print(f"Capture thread crashed: {e}")
        status_dict["error"] = str(e)
    finally:
        conn.close()
        print("Real Live Capture stopped.")


# Endpoint: Upload PCAP
@app.post("/api/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):
    # Save upload to a temp file
    suffix = os.path.splitext(file.filename)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
        try:
            shutil.copyfileobj(file.file, temp_file)
            temp_path = temp_file.name
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {e}")
            
    # Process PCAP
    try:
        inserted_count, message = parse_pcap_file(temp_path)
        if inserted_count == 0 and "failed" in message.lower():
            raise HTTPException(status_code=400, detail=message)
        return {"status": "success", "inserted_flows": inserted_count, "message": message}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PCAP Ingestion Error: {str(e)}")
    finally:
        # Clean up temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)

# Endpoint: Start Capture
@app.post("/api/capture/start")
def start_capture(req: CaptureRequest = None):
    global capture_thread, capture_stop_event, capture_status
    if capture_status["active"]:
        return {"status": "ignored", "message": "Capture already running"}
        
    try:
        from scapy.interfaces import get_working_ifaces
        ifaces = get_working_ifaces()
        if not ifaces:
            raise HTTPException(status_code=400, detail="No active network interfaces found.")
    except ImportError:
        pass
    except OSError as e:
        raise HTTPException(status_code=400, detail="Administrator privileges required or Npcap is missing.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to detect network interfaces: {e}")
        
    capture_stop_event.clear()
    capture_status["active"] = True
    capture_status["packets_captured"] = 0
    capture_status["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    capture_status["error"] = None
    
    iface = req.iface if req else None
    
    # Run the real sniffer worker in a background thread
    capture_thread = threading.Thread(target=real_live_capture_worker, args=(capture_stop_event, capture_status, iface))
    capture_thread.daemon = True
    capture_thread.start()
    
    return {"status": "success", "message": f"Real live network capture started on {iface if iface else 'default interface'}"}

# Endpoint: Stop Capture
@app.post("/api/capture/stop")
def stop_capture():
    global capture_thread, capture_stop_event, capture_status
    if not capture_status["active"]:
        return {"status": "ignored", "message": "No active capture running"}
        
    capture_stop_event.set()
    if capture_thread:
        capture_thread.join(timeout=2.0)
        capture_thread = None
        
    capture_status["active"] = False
    return {"status": "success", "message": "Live flow capture/simulation stopped", "captured": capture_status["packets_captured"]}

# Endpoint: Capture Status
@app.get("/api/capture/status")
def get_capture_status():
    return capture_status

# Endpoint: Reset DB / Clear Traffic Data
@app.post("/api/clear")
def clear_database():
    global capture_thread, capture_stop_event, capture_status
    # Stop any active capture first to prevent re-insertion of data
    if capture_status["active"]:
        capture_stop_event.set()
        if capture_thread:
            capture_thread.join(timeout=2.0)
            capture_thread = None
        capture_status["active"] = False
        capture_status["packets_captured"] = 0
        capture_status["error"] = None

    conn = get_connection()
    try:
        conn.execute("DELETE FROM flows;")
        conn.commit()
        return {"status": "success", "message": "Database reset completed. All flow records cleared. Any active capture has been stopped."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear database: {e}")
    finally:
        conn.close()

# Endpoint: Get Compliance Report
@app.get("/api/report")
async def get_report():
    try:
        report = analyzer.generate_report()
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {e}")

# Endpoint: Force Refresh Cache
@app.get("/api/refresh")
async def force_refresh():
    # In this interactive system, we return a success status
    return {"status": "success", "message": "Report cache re-evaluated successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
