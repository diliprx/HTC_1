"""
HTC NetFlow Analyzer Pro — Enterprise FastAPI Backend
======================================================
Dual-Mode 4-Hour Time Windowing, MITRE ATT&CK Threat Analytics,
Regulatory Compliance Auditing, Asset Inventory Management,
Live Packet Sniffing, PCAP Ingestion, and Multi-Format Exports.
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from contextlib import asynccontextmanager
from pydantic import BaseModel
from typing import Optional, List
import asyncio
import threading
import os
import shutil
import tempfile
import io
import csv
from datetime import datetime, timezone

from database import (
    init_db,
    get_connection,
    get_lock,
    close_connection,
    get_all_assets,
    upsert_asset,
    delete_asset,
    list_reports,
    get_report as get_stored_report,
)
from collector import start_collector
import analyzer
from pcap_parser import parse_pcap_file
from nexthop import NextHopResolver

# ── Scapy imports (optional — graceful fallback if not installed) ─────────────
import importlib.util
SCAPY_AVAILABLE = importlib.util.find_spec("scapy") is not None

PROTO_INT = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'Other': 0}

# ── Globals ───────────────────────────────────────────────────────────────────
collector_task   = None
scheduler_task   = None
capture_thread   = None
capture_stop_evt = threading.Event()
capture_status   = {
    "active":           False,
    "mode":             "idle",
    "packets_captured": 0,
    "started_at":       None,
    "interface":        None,
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

# ── 4-Hour Report Scheduler ───────────────────────────────────────────────────
async def report_scheduler():
    """
    At every 4-hour UTC boundary, generate and store the compliance report for
    the period that just ended. On startup it catches up the last completed
    period if that report is missing.
    """
    while True:
        try:
            meta = await asyncio.to_thread(analyzer.ensure_scheduled_report)
            if meta:
                print(f"[Scheduler] Stored 4h report #{meta['id']} ({meta['window_start']} -> {meta['window_end']} UTC)")
        except Exception as e:
            print(f"[Scheduler] Report generation failed: {e}")
        _, next_boundary = analyzer.cycle_bounds()
        wait = (next_boundary.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).total_seconds()
        await asyncio.sleep(max(wait, 0) + 2)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    global collector_task, scheduler_task

    try:
        collector_task = asyncio.create_task(start_collector())
        print("[Main] NetFlow v5 UDP:2055 Collector initialized.")
    except Exception as e:
        print(f"[Main] Failed to start collector: {e}")

    scheduler_task = asyncio.create_task(report_scheduler())
    print("[Main] 4-hour compliance report scheduler started.")

    yield

    for task in (collector_task, scheduler_task):
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    capture_stop_evt.set()
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=3)

    capture_status["active"] = False
    close_connection()
    print("[Main] Database checkpoint completed. Server stopped cleanly.")


app = FastAPI(title="HTC NetFlow Analyzer Pro", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", "http://localhost:5174", "http://localhost:5175",
        "http://localhost:3000", "http://localhost:3001",
        "http://127.0.0.1:5173", "http://127.0.0.1:5174", "http://127.0.0.1:5175",
        "http://127.0.0.1:3000", "http://127.0.0.1:3001"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Live Packet Capture Sniffer ───────────────────────────────────────────────
def _live_capture_worker(stop_event, status_dict, iface=None):
    from scapy.all import sniff, conf, getmacbyip, Ether, ARP, IP, TCP, UDP, ICMP
    lock     = get_lock()
    conn     = get_connection()
    buffer   = []
    resolver = NextHopResolver()

    # Prime the resolver with this machine's default route, if known
    try:
        gw_ip = conf.route.route("0.0.0.0")[2]
        gw_mac = getmacbyip(gw_ip) if gw_ip and gw_ip != "0.0.0.0" else None
        if gw_mac:
            resolver.learn_arp(gw_mac.lower(), gw_ip)
    except Exception:
        pass

    def on_packet(pkt):
        if stop_event.is_set():
            return
        if ARP in pkt:
            resolver.learn_arp(str(pkt[ARP].hwsrc).lower(), pkt[ARP].psrc)
            return
        if IP not in pkt:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Skip own dashboard traffic
        if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1":
            if TCP in pkt and (pkt[TCP].sport in (8000, 5173) or pkt[TCP].dport in (8000, 5173)):
                return

        proto_name = "Other"
        src_port = dst_port = 0

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

        proto_int = PROTO_INT.get(proto_name, 0)

        # Next hop = router the outbound frame is addressed to (Ethernet dst MAC)
        src_mac = str(pkt[Ether].src).lower() if Ether in pkt else None
        dst_mac = str(pkt[Ether].dst).lower() if Ether in pkt else None
        resolver.learn_packet(src_mac, dst_mac, src_ip, dst_ip)
        nexthop = resolver.nexthop(src_mac, dst_mac, src_ip, dst_ip)

        try:
            pkt_ts = datetime.fromtimestamp(float(pkt.time), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pkt_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        buffer.append((
            src_ip, dst_ip, nexthop, 1, len(pkt),
            src_port, dst_port, proto_int, pkt_ts
        ))
        status_dict["packets_captured"] += 1

        if len(buffer) >= 25:
            _flush_buffer(lock, conn, buffer)

    try:
        sniff_kwargs = dict(prn=on_packet, stop_filter=lambda _: stop_event.is_set(), store=False)
        if iface:
            sniff_kwargs['iface'] = iface
        sniff(**sniff_kwargs)

        if buffer:
            _flush_buffer(lock, conn, buffer)
    except PermissionError:
        status_dict["error"] = "Administrator privileges required for raw packet sniffing."
    except Exception as e:
        status_dict["error"] = str(e)
    finally:
        status_dict["active"] = False


def _flush_buffer(lock, conn, buffer):
    with lock:
        try:
            conn.executemany(INSERT_SQL, buffer)
            conn.commit()
        except Exception as e:
            print(f"[Capture] Flush error: {e}")
        finally:
            buffer.clear()


# ── Pydantic Request Models ───────────────────────────────────────────────────
class CaptureRequest(BaseModel):
    iface: Optional[str] = None

class AssetRequest(BaseModel):
    ip: str
    hostname: str
    expected_protocols: str = "TCP,UDP"
    risk_tier: str = "Medium"
    criticality: str = "Tier 2 (Business)"
    department: str = "General"
    compliance_scope: str = "PCI-DSS, NIST"


# ── REST API Endpoints ────────────────────────────────────────────────────────

@app.get("/api/report")
async def get_report(window: str = Query(default="4h", description="Time window: 15m, 1h, 4h, 12h, 24h, 7d, all")):
    """
    HTC Compliance & Traffic Report.
    Returns all 7 required deliverables with dynamic 4-hour windowing.
    """
    try:
        report = analyzer.generate_report(window)
        report['cycle'] = analyzer.cycle_info()
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report calculation failed: {e}")


@app.get("/api/reports")
def get_reports(limit: int = Query(default=50, ge=1, le=500)):
    """Stored compliance reports: one per completed 4-hour period, plus manual snapshots."""
    try:
        return {"cycle": analyzer.cycle_info(), "reports": list_reports(limit)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list reports: {e}")


@app.post("/api/reports/generate")
def generate_report_snapshot():
    """Store a snapshot of the current 4-hour period so far (does not replace the scheduled report)."""
    try:
        return analyzer.generate_manual_report()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")


@app.get("/api/reports/{report_id}")
def get_report_by_id(report_id: int):
    stored = get_stored_report(report_id)
    if not stored:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    return stored


@app.get("/api/threats")
async def get_threats(window: str = Query(default="4h")):
    """
    MITRE ATT&CK Threat Analytics & SOC Incident Triage.
    Evaluates T1046, T1071, T1048, T1021, and T1090 violations.
    """
    try:
        return analyzer.generate_threat_analysis(window)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat analysis failed: {e}")


@app.get("/api/compliance/audit")
async def get_compliance_audit(window: str = Query(default="4h")):
    """
    Regulatory Compliance Audit Scorecards for PCI-DSS v4.0, NIST SP 800-53,
    ISO/IEC 27001:2022, and CIS Controls v8.
    """
    try:
        return analyzer.generate_compliance_audit(window)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Compliance audit failed: {e}")


@app.get("/api/assets")
def list_assets():
    """Retrieve all configured enterprise assets in the inventory."""
    try:
        return get_all_assets()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch assets: {e}")


@app.post("/api/assets")
def create_or_update_asset(req: AssetRequest):
    """Add or edit an asset inventory record."""
    try:
        upsert_asset(
            req.ip, req.hostname, req.expected_protocols,
            req.risk_tier, req.criticality, req.department, req.compliance_scope
        )
        return {"status": "success", "message": f"Asset {req.ip} ({req.hostname}) saved."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Asset save failed: {e}")


@app.delete("/api/assets/{ip}")
def remove_asset(ip: str):
    """Delete an asset from inventory."""
    try:
        delete_asset(ip)
        return {"status": "success", "message": f"Asset {ip} deleted."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Asset deletion failed: {e}")


@app.post("/api/upload-pcap")
async def upload_pcap(
    file: UploadFile = File(...),
    shift_to_now: bool = Form(default=True)
):
    """
    Upload and parse PCAP/PCAPng.
    If shift_to_now=True, automatically maps timestamps to the current 4-hour window.
    """
    suffix = os.path.splitext(file.filename)[1] or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        try:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to write upload: {e}")

    try:
        count, message = parse_pcap_file(tmp_path, shift_to_now=shift_to_now)
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


@app.get("/api/capture/interfaces")
def get_interfaces():
    """List available network interfaces for live capture."""
    interfaces = []
    if SCAPY_AVAILABLE:
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
        except Exception:
            pass
    return {"interfaces": interfaces, "scapy_available": SCAPY_AVAILABLE}


@app.post("/api/capture/start")
def start_capture(req: CaptureRequest = None):
    global capture_thread, capture_stop_evt, capture_status
    if capture_status["active"]:
        return {"status": "ignored", "message": "Capture is already active"}

    if not SCAPY_AVAILABLE:
        raise HTTPException(status_code=400, detail="Scapy is not installed. Run: pip install scapy")

    capture_stop_evt.clear()
    iface = req.iface if req else None
    capture_status.update({
        "active":           True,
        "mode":             "Live Network Sniffing",
        "packets_captured": 0,
        "started_at":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "interface":        iface or "Default Adapter",
        "error":            None,
    })
    capture_thread = threading.Thread(
        target=_live_capture_worker,
        args=(capture_stop_evt, capture_status, iface),
        daemon=True
    )
    capture_thread.start()
    return {"status": "success", "message": f"Capture initiated on {iface or 'default interface'}"}


@app.post("/api/capture/stop")
def stop_capture():
    global capture_thread, capture_stop_evt, capture_status
    if not capture_status["active"]:
        return {"status": "ignored", "message": "No capture active"}
    capture_stop_evt.set()
    if capture_thread:
        capture_thread.join(timeout=3.0)
        capture_thread = None
    capture_status["active"] = False
    return {"status": "success", "message": "Capture stopped", "captured": capture_status["packets_captured"]}


@app.get("/api/capture/status")
def get_capture_status():
    return capture_status


@app.post("/api/clear")
def clear_database():
    """Clear all flow records and reset capture state."""
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
            return {"status": "success", "message": "All flow records successfully cleared."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Database clear failed: {e}")


@app.get("/api/export/csv")
def export_csv(dataset: str = Query(default="flows", description="Dataset: flows, assets, threats")):
    """Export flow data, asset inventory, or threat records as CSV."""
    lock = get_lock()
    conn = get_connection()
    output = io.StringIO()
    writer = csv.writer(output)

    with lock:
        if dataset == "assets":
            rows = conn.execute("SELECT ip, hostname, expected_protocols, risk_tier, criticality, department, compliance_scope FROM assets").fetchall()
            writer.writerow(["IP", "Hostname", "Expected Protocols", "Risk Tier", "Criticality", "Department", "Compliance Scope"])
            for r in rows:
                writer.writerow(r)
        elif dataset == "threats":
            threats_data = analyzer.generate_threat_analysis("4h")
            writer.writerow(["Threat ID", "MITRE ID", "MITRE Name", "Severity", "Asset IP", "Target IP", "Details", "Remediation"])
            for t in threats_data.get('threats', []):
                writer.writerow([t['id'], t['mitre_id'], t['mitre_name'], t['severity'], t['asset_ip'], t['target_ip'], t['details'], t['remediation']])
        else:
            rows = conn.execute("SELECT src_ip, dst_ip, nexthop, packets, bytes, src_port, dst_port, protocol, timestamp FROM flows ORDER BY timestamp DESC LIMIT 5000").fetchall()
            writer.writerow(["Source IP", "Destination IP", "Nexthop", "Packets", "Bytes", "Src Port", "Dst Port", "Protocol", "Timestamp"])
            for r in rows:
                writer.writerow(r)

    csv_content = output.getvalue()
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=htc_{dataset}_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
    )


@app.get("/api/health")
def health():
    lock = get_lock()
    conn = get_connection()
    with lock:
        try:
            total = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        except Exception:
            total = 0
    return {
        "status":        "ok",
        "total_flows":   total,
        "collector":     "running" if collector_task and not collector_task.done() else "stopped",
        "capture":       capture_status["active"],
        "timestamp":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


@app.get("/api/refresh")
async def force_refresh():
    return {"status": "success", "message": "Compliance dataset refreshed."}


if __name__ == "__main__":
    import uvicorn
    import sys
    try:
        print("[HTC] Starting Enterprise NetFlow Analytics Engine on http://localhost:8000 ...")
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
    except (KeyboardInterrupt, SystemExit):
        print("\n[!] Graceful server shutdown completed.")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
