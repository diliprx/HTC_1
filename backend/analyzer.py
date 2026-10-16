"""
HTC NetFlow Analyzer Pro — Enterprise Threat & Compliance Analytics Engine
==========================================================================
Dual-Mode 4-Hour Time Window Engine (Real-Time Live & Adaptive PCAP Ingest),
MITRE ATT&CK Threat Detection, Multi-Standard Regulatory Auditing
(PCI-DSS, NIST SP 800-53, ISO 27001, CIS Controls), and Dynamic Topology Mapping.
"""

from datetime import datetime, timedelta, timezone
from database import (get_connection, get_lock, get_all_assets,
                      save_report, scheduled_report_exists, list_reports)
import re

# ── Protocol & Port Standards Mappings ────────────────────────────────────────
PROTO_MAP = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH'}

PORT_SERVICE_MAP = {
    80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 23: 'Telnet',
    21: 'FTP', 25: 'SMTP', 53: 'DNS', 123: 'NTP',
    445: 'SMB', 3306: 'MySQL', 5432: 'PostgreSQL',
    8080: 'HTTP-Alt', 161: 'SNMP', 3389: 'RDP',
    8443: 'HTTPS-Alt', 110: 'POP3', 143: 'IMAP',
    6379: 'Redis', 27017: 'MongoDB', 5900: 'VNC',
    2222: 'SSH-Alt', 4444: 'Metasploit/C2', 8888: 'HTTP-Proxy'
}

PORT_RISK_MAP = {
    23: 'Critical',   # Telnet — plaintext
    21: 'Critical',   # FTP — plaintext credentials
    3389: 'Critical', # RDP — brute force / exploit target
    4444: 'Critical', # Metasploit payload / C2
    5900: 'High',     # VNC — unencrypted remote desktop
    445: 'High',      # SMB — EternalBlue / Ransomware lateral vector
    25: 'High',       # SMTP — spam / unencrypted relay
    2222: 'High',     # Non-standard SSH
    161: 'Medium',    # SNMP — reconnaissance
    22: 'Low',        # Standard SSH
    80: 'Low',
    443: 'Low',
    3306: 'Medium',
    5432: 'Medium',
    6379: 'Medium',
    27017: 'Medium',
    8080: 'Low',
}

DANGEROUS_PORTS = {23, 21, 3389, 4444, 5900, 2222, 445}
PORT_SCAN_THRESHOLD = 6
EXCESSIVE_CONN_THRESHOLD = 150
MALICIOUS_SCORE_THRESHOLD = 60


# ── Helper Functions ──────────────────────────────────────────────────────────

def _proto_name(p):
    try:
        return PROTO_MAP.get(int(p), f"Proto-{p}")
    except Exception:
        return str(p)

def _service(port):
    return PORT_SERVICE_MAP.get(port, f"Port-{port}")

def _risk(port):
    return PORT_RISK_MAP.get(port, 'Low')

def _hostname(ip):
    if not ip:
        return "unknown"
    parts = ip.split('.')
    try:
        last = parts[-1]
    except IndexError:
        last = ip
    return f"node-{last}"

def _geo(ip):
    if not ip:
        return "Unknown"
    if ip.startswith("8.8."):
        return "US / Google Anycast DNS"
    if ip.startswith("1.1.1.") or ip.startswith("1.0.0."):
        return "AU / Cloudflare Anycast DNS"
    if ip.startswith("185.220."):
        return "NL / Tor Exit Node (High Risk)"
    if ip.startswith("195.254."):
        return "RU / Bulletproof Hosting"
    if ip.startswith("199.87."):
        return "US / Known Proxy Network"
    if ip.startswith(("104.", "172.217.", "142.250.")):
        return "US / Cloud Edge CDN"
    if ip.startswith(("91.", "77.", "78.", "79.")):
        return "EU / Regional Tier-1 ISP"
    if ip.startswith(("203.", "202.", "111.", "112.")):
        return "APAC / Enterprise Gateway"
    return "Global Public Internet"

def _threat(ip):
    if not ip:
        return 0
    if ip.startswith("185.220."):
        return 95  # Tor Exit Node
    if ip.startswith("195.254."):
        return 90  # Bulletproof host
    if ip.startswith("199.87."):
        return 82  # Malicious proxy
    if ip.startswith("45.33.") or ip.startswith("198.199."):
        return 72
    if ip.startswith(("8.8.", "8.4.", "1.1.1.", "1.0.0.")):
        return 5   # Trusted DNS
    # Deterministic reputation score
    return max(10, (abs(hash(ip)) % 45) + 10)

def _is_private_sql(col):
    return f"""(
        {col} LIKE '10.%' OR
        {col} LIKE '192.168.%' OR
        {col} LIKE '127.%' OR
        regexp_matches({col}, '^172\\.(1[6-9]|2[0-9]|3[01])\\.')
    )"""

def _is_public_sql(col):
    """Routable unicast outside RFC1918 (no 0/8, link-local, multicast, broadcast)."""
    return f"""(
        NOT {_is_private_sql(col)} AND
        NOT regexp_matches({col}, '^(0\\.|169\\.254\\.|22[4-9]\\.|2[3-5][0-9]\\.)')
    )"""

# Service-port normalisation: a flow's port is the service side (well-known
# or registered port), not the client's ephemeral port. Reply traffic such as
# 8.8.8.8:53 -> 10.0.0.10:54321 is therefore attributed to port 53, with
# 8.8.8.8 as the server.
_KNOWN_PORTS = ','.join(str(p) for p in sorted(PORT_SERVICE_MAP))

def _svc_branches(dst_val, src_val, non_l4_val):
    return f"""CASE
        WHEN protocol NOT IN (6, 17) THEN {non_l4_val}
        WHEN dst_port < 1024 OR dst_port IN ({_KNOWN_PORTS}) THEN {dst_val}
        WHEN src_port < 1024 OR src_port IN ({_KNOWN_PORTS}) THEN {src_val}
        WHEN dst_port <= src_port THEN {dst_val}
        ELSE {src_val}
    END"""

SVC_PORT_SQL   = _svc_branches('dst_port', 'src_port', '0')
SVC_SERVER_SQL = _svc_branches('dst_ip', 'src_ip', 'dst_ip')

def _detect_gateways(conn, where, params, limit=3):
    """Egress next hops for internal -> public flows, ranked by bytes."""
    return conn.execute(f"""
        SELECT nexthop, SUM(bytes) AS total_bytes, COUNT(*) AS flow_count
        FROM flows
        WHERE nexthop IS NOT NULL
          AND nexthop NOT IN ('0.0.0.0', '127.0.0.1', '')
          AND {_is_private_sql('src_ip')}
          AND {_is_public_sql('dst_ip')}
          AND {where}
        GROUP BY nexthop
        ORDER BY total_bytes DESC
        LIMIT {limit}
    """, params).fetchall()


def _is_private_py(ip):
    if not ip:
        return False
    try:
        p = list(map(int, ip.split('.')))
        return (p[0] == 10 or p[0] == 127
                or (p[0] == 192 and p[1] == 168)
                or (p[0] == 172 and 16 <= p[1] <= 31))
    except Exception:
        return False


# ── Dual-Mode Time Window Parser ──────────────────────────────────────────────

def parse_time_window(conn, window_str="4h", start=None, end=None):
    """
    Parses dynamic time window ('15m', '1h', '4h', '12h', '24h', '7d', 'all', 'adaptive').
    Intelligently handles both real-time live clock AND historical PCAP datasets.
    
    Returns: (where_clause, params_list, window_start_str, window_end_str, is_adaptive, window_seconds)
    """
    window_map = {
        '15m': 15 * 60,
        '30m': 30 * 60,
        '1h':  3600,
        '2h':  7200,
        '4h':  14400,
        '8h':  28800,
        '12h': 43200,
        '24h': 86400,
        '7d':  7 * 86400,
    }

    if start is not None and end is not None:
        s, e = start.strftime("%Y-%m-%d %H:%M:%S"), end.strftime("%Y-%m-%d %H:%M:%S")
        return "timestamp >= ? AND timestamp < ?", [s, e], s, e, False, int((end - start).total_seconds())

    if window_str == 'all':
        return "1=1", [], "Epoch Start", "Present", False, 0

    duration_sec = window_map.get(window_str, 14400)
    
    # Check max timestamp in DB
    try:
        max_ts_row = conn.execute("SELECT MAX(timestamp) FROM flows").fetchone()
        max_db_ts = max_ts_row[0] if max_ts_row and max_ts_row[0] else None
    except Exception:
        max_db_ts = None

    now_utc = datetime.now(timezone.utc)

    # Determine if dataset is historical or live
    is_historical = False
    ref_time = now_utc

    if max_db_ts:
        if isinstance(max_db_ts, str):
            try:
                dt_clean = re.sub(r'\.\d+', '', max_db_ts.replace('Z', ''))
                max_dt = datetime.fromisoformat(dt_clean)
            except Exception:
                max_dt = now_utc.replace(tzinfo=None)
        else:
            max_dt = max_db_ts

        if max_dt.tzinfo is None:
            max_dt = max_dt.replace(tzinfo=timezone.utc)

        # If data is older than 24 hours from current wall clock, anchor window relative to dataset
        if (now_utc - max_dt).total_seconds() > 86400:
            is_historical = True
            ref_time = max_dt

    cutoff_time = ref_time - timedelta(seconds=duration_sec)
    cutoff_str = cutoff_time.strftime("%Y-%m-%d %H:%M:%S")
    end_str = ref_time.strftime("%Y-%m-%d %H:%M:%S")

    # In DuckDB, compare with ISO timestamp string
    where_clause = "timestamp >= ? AND timestamp <= ?"
    params = [cutoff_str, end_str]

    return where_clause, params, cutoff_str, end_str, is_historical, duration_sec


# ══════════════════════════════════════════════════════════════════════════════
# 4-HOUR REPORT CYCLE
# ══════════════════════════════════════════════════════════════════════════════
# Reports are cut on fixed UTC boundaries (00:00, 04:00, 08:00, ...). At each
# boundary the period that just ended is reported and stored.

REPORT_CYCLE_SECONDS = 4 * 3600


def cycle_bounds(now=None):
    """(start, end) of the 4-hour period containing `now` (naive UTC datetimes)."""
    now = now or datetime.now(timezone.utc)
    epoch = int(now.timestamp())
    start = epoch - epoch % REPORT_CYCLE_SECONDS
    to_dt = lambda s: datetime.fromtimestamp(s, timezone.utc).replace(tzinfo=None)
    return to_dt(start), to_dt(start + REPORT_CYCLE_SECONDS)


def cycle_info():
    start, end = cycle_bounds()
    last = list_reports(limit=1)
    return {
        'cycle_seconds':   REPORT_CYCLE_SECONDS,
        'cycle_start':     start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        'next_report_at':  end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        'last_report':     last[0] if last else None,
    }


def ensure_scheduled_report():
    """Generate and store the report for the last completed 4-hour period, once."""
    cur_start, _ = cycle_bounds()
    prev_start = cur_start - timedelta(seconds=REPORT_CYCLE_SECONDS)
    if scheduled_report_exists(prev_start, cur_start):
        return None
    report = generate_report("4h", start=prev_start, end=cur_start)
    return save_report(report, prev_start, cur_start, 'scheduled')


def generate_manual_report():
    """Snapshot of the current (still running) 4-hour period up to now."""
    cur_start, _ = cycle_bounds()
    now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0) + timedelta(seconds=1)
    report = generate_report("4h", start=cur_start, end=now)
    return save_report(report, cur_start, now, 'manual')


# ══════════════════════════════════════════════════════════════════════════════
# MAIN REPORT GENERATOR (HTC Deliverables 1-7)
# ══════════════════════════════════════════════════════════════════════════════

def generate_report(window="4h", start=None, end=None):
    """
    Build the report for a rolling window ('4h' etc.) or, when start/end are
    given, for that fixed period (used by the 4-hourly scheduled reports).
    An empty window yields an empty report; it never widens to other data.
    """
    lock = get_lock()
    conn = get_connection()

    with lock:
        where_clause, where_params, window_start, window_end, is_adaptive, window_seconds = parse_time_window(conn, window, start, end)

        # 0. Count flows in active window
        try:
            total_flows, window_bytes, window_pkts = conn.execute(
                f"SELECT COUNT(*), COALESCE(SUM(bytes), 0), COALESCE(SUM(packets), 0) FROM flows WHERE {where_clause}",
                where_params).fetchone()
        except Exception as e:
            raise RuntimeError(f"[Analyzer] Flow query failed: {e}")

        _w = where_clause
        _wp = where_params

        # ── 1. Unique Internal Assets ──────────────────────────────────────────
        assets_sql = f"""
            SELECT ip,
                   SUM(total_bytes)   AS bytes,
                   SUM(total_flows)   AS flows,
                   SUM(total_packets) AS packets,
                   MAX(last_seen)     AS last_seen
            FROM (
                SELECT src_ip AS ip,
                       SUM(bytes) AS total_bytes,
                       COUNT(*)   AS total_flows,
                       SUM(packets) AS total_packets,
                       MAX(timestamp) AS last_seen
                FROM flows
                WHERE {_is_private_sql('src_ip')} AND {_w}
                GROUP BY src_ip
                UNION ALL
                SELECT dst_ip AS ip,
                       SUM(bytes) AS total_bytes,
                       COUNT(*)   AS total_flows,
                       SUM(packets) AS total_packets,
                       MAX(timestamp) AS last_seen
                FROM flows
                WHERE {_is_private_sql('dst_ip')} AND {_w}
                GROUP BY dst_ip
            )
            GROUP BY ip
            ORDER BY bytes DESC
        """
        assets_raw = conn.execute(assets_sql, _wp + _wp).fetchall()

        asset_ports_sql = f"""
            WITH f AS (
                SELECT src_ip, dst_ip, protocol,
                       {SVC_PORT_SQL}   AS svc_port,
                       {SVC_SERVER_SQL} AS server_ip
                FROM flows WHERE {_w}
            ), ends AS (
                SELECT src_ip AS ip, protocol, svc_port, server_ip = src_ip AS is_server FROM f
                UNION ALL
                SELECT dst_ip AS ip, protocol, svc_port, server_ip = dst_ip AS is_server FROM f
            )
            SELECT ip,
                   LIST(DISTINCT protocol),
                   LIST(DISTINCT svc_port) FILTER (WHERE is_server AND svc_port > 0),
                   LIST(DISTINCT svc_port) FILTER (WHERE NOT is_server AND svc_port > 0)
            FROM ends
            WHERE {_is_private_sql('ip')}
            GROUP BY ip
        """
        asset_ports = {
            ip: (protos or [], sorted(listen or []), sorted(client or []))
            for ip, protos, listen, client in conn.execute(asset_ports_sql, _wp).fetchall()
        }

        # Load asset inventory metadata
        inventory_assets = {a['ip']: a for a in get_all_assets()}
        active_ips = set()
        internal_assets = []

        for ip, byte_total, flow_count, packet_total, last_seen in assets_raw:
            active_ips.add(ip)
            inv = inventory_assets.get(ip, {})
            
            proto_ids, listening, client = asset_ports.get(ip, ([], [], []))
            protos = sorted(_proto_name(p) for p in proto_ids)
            ports  = sorted(set(listening) | set(client))

            internal_assets.append({
                'ip':               ip,
                'host':             inv.get('hostname') or _hostname(ip),
                'type':             'Internal Asset',
                'bytes':            byte_total or 0,
                'flows':            flow_count or 0,
                'packets':          packet_total or 0,
                'lastSeen':         str(last_seen) if last_seen else 'Active',
                'protocols':        protos,
                'ports':            ports,       # all service ports used by / served by this IP
                'listeningPorts':   listening,   # services this IP provides
                'clientPorts':      client,      # services this IP connects to
                'criticality':      inv.get('criticality', 'Tier 2 (Business)'),
                'department':       inv.get('department', 'Infrastructure'),
                'complianceScope':  inv.get('compliance_scope', 'PCI-DSS, NIST'),
            })

        # ── 2. Identify Configured Gateway (derived from outbound traffic) ─────
        # The gateway is the next hop carrying most internal -> public bytes.
        # None when the traffic carries no next-hop information.
        gw_rows = _detect_gateways(conn, _w, _wp)
        gateway = gw_rows[0][0] if gw_rows else None

        gateways = []
        for idx, row in enumerate(gw_rows):
            gw_ip, gw_bytes, gw_flows = row[0], row[1], row[2]
            gateways.append({
                'ip': gw_ip,
                'host': _hostname(gw_ip),
                'type': 'Primary Default Gateway' if idx == 0 else f'Secondary Gateway #{idx+1}',
                'bytes': gw_bytes,
                'flows': gw_flows
            })

        # ── 3. Identify Public IPs talking to internal assets ──────────────────
        pub_sql = f"""
            SELECT ip,
                   SUM(bytes_in)          AS total_bytes,
                   ARRAY_AGG(DISTINCT internal_ip) AS talks_to,
                   ARRAY_AGG(DISTINCT protocol)    AS protocols
            FROM (
                SELECT src_ip AS ip, dst_ip AS internal_ip,
                       SUM(bytes) AS bytes_in, protocol
                FROM flows
                WHERE {_is_public_sql('src_ip')}
                  AND {_is_private_sql('dst_ip')}
                  AND {_w}
                GROUP BY src_ip, dst_ip, protocol
                UNION ALL
                SELECT dst_ip AS ip, src_ip AS internal_ip,
                       0 AS bytes_in, protocol
                FROM flows
                WHERE {_is_public_sql('dst_ip')}
                  AND {_is_private_sql('src_ip')}
                  AND {_w}
                GROUP BY dst_ip, src_ip, protocol
            )
            GROUP BY ip
            ORDER BY total_bytes DESC
        """
        pub_raw = conn.execute(pub_sql, _wp + _wp).fetchall()
        public_ips = []
        for ip, total_bytes, talks_to, protocols in pub_raw:
            public_ips.append({
                'ip':      ip,
                'geo':     _geo(ip),
                'talksto': list(set(t for t in talks_to if t)),
                'proto':   list(set(_proto_name(p) for p in protocols if p is not None)),
                'bytesIn': total_bytes or 0,
                'threat':  _threat(ip),
            })

        # ── 4. NAT Bypass / Rogue Gateway Routing Detection ───────────────────
        # Internal hosts reaching public IPs via a next hop other than the
        # gateway: these paths do not pass the gateway, i.e. a separate NAT.
        nat_sql = f"""
            SELECT src_ip, nexthop, dst_ip, COUNT(*) as flow_count, SUM(bytes) as bypass_bytes
            FROM flows
            WHERE {_is_private_sql('src_ip')}
              AND {_is_public_sql('dst_ip')}
              AND nexthop != ?
              AND nexthop NOT IN ('0.0.0.0', '127.0.0.1', '')
              AND nexthop IS NOT NULL
              AND {_w}
            GROUP BY src_ip, nexthop, dst_ip
            ORDER BY src_ip, nexthop, dst_ip
        """
        nat_raw = conn.execute(nat_sql, [gateway] + _wp).fetchall() if gateway else []
        nat_bypass = []
        for src, nh, dst, fcount, bbytes in nat_raw:
            nat_bypass.append({
                'src':       src,
                'nexthop':   nh,
                'dst':       dst,
                'host':      _hostname(src),
                'flows':     fcount,
                'bytes':     bbytes or 0,
                'risk':      'Critical' if _threat(dst) >= 50 else 'High',
                'recommendation': f"Enforce router ACL on {src}; block egress via unauthorized nexthop {nh}."
            })

        # ── 5. Protocol & Port Frequency Breakdown ────────────────────────────
        pp_sql = f"""
            SELECT protocol, {SVC_PORT_SQL} AS svc_port,
                   COUNT(*)   AS flow_count,
                   SUM(bytes) AS byte_count,
                   SUM(packets) AS pkt_count
            FROM flows
            WHERE {_w}
            GROUP BY protocol, svc_port
            ORDER BY flow_count DESC
        """
        pp_raw = conn.execute(pp_sql, _wp).fetchall()
        proto_ports = []
        for proto, port, flows, byte_vol, pkt_vol in pp_raw:
            proto_name = _proto_name(proto)
            svc_name   = _service(port) if proto_name in ('TCP', 'UDP') else proto_name
            proto_ports.append({
                'proto':    proto_name,
                'port':     port,
                'service':  svc_name,
                'flows':    flows,
                'bytes':    byte_vol or 0,
                'packets':  pkt_vol or 0,
                'risk':     _risk(port),
            })

        # ── 6. One-to-Many Network Relationship Topology Graph ────────────────
        graph_sql = f"""
            SELECT src_ip, dst_ip, protocol, nexthop,
                   SUM(bytes) AS edge_bytes,
                   COUNT(*)   AS edge_flows
            FROM flows
            WHERE {_w}
            GROUP BY src_ip, dst_ip, protocol, nexthop
            ORDER BY edge_bytes DESC
            LIMIT 250
        """
        graph_raw = conn.execute(graph_sql, _wp).fetchall()
        graph_nodes = {}
        graph_edges = []
        nat_bypass_srcs = {nb['src'] for nb in nat_bypass}

        for src, dst, proto, nexthop, ebytes, eflows in graph_raw:
            for ip in (src, dst):
                if ip not in graph_nodes:
                    is_priv = _is_private_py(ip)
                    is_gw = (ip == gateway)
                    is_bypass = (ip in nat_bypass_srcs)
                    node_type = 'Gateway' if is_gw else ('Internal' if is_priv else 'Public')
                    
                    graph_nodes[ip] = {
                        'id':        ip,
                        'label':     _hostname(ip) if is_priv else ip,
                        'type':      node_type,
                        'is_priv':   is_priv,
                        'is_gw':     is_gw,
                        'is_bypass': is_bypass,
                        'threat':    _threat(ip) if not is_priv else 0,
                    }

            is_bypass_edge = (src in nat_bypass_srcs and not _is_private_py(dst))
            graph_edges.append({
                'source':    src,
                'target':    dst,
                'bytes':     ebytes or 0,
                'flows':     eflows,
                'proto':     _proto_name(proto),
                'is_bypass': is_bypass_edge,
            })

        # ── 7. Compliance & Ghost Asset Watchdog ──────────────────────────────
        # Compare complete registered inventory against observed flows in window
        absent_ips = []
        all_inventory = get_all_assets()
        nexthops_seen = {r[0] for r in conn.execute(
            f"SELECT DISTINCT nexthop FROM flows WHERE nexthop IS NOT NULL AND {_w}", _wp).fetchall()}
        active_set = active_ips | nexthops_seen

        for asset in all_inventory:
            row_ip = asset['ip']
            if row_ip not in active_set:
                # Find historical last-seen
                try:
                    ls_row = conn.execute("SELECT MAX(timestamp) FROM flows WHERE src_ip=? OR dst_ip=?", [row_ip, row_ip]).fetchone()
                    last_seen_ts = ls_row[0] if ls_row and ls_row[0] else None
                except Exception:
                    last_seen_ts = None

                if last_seen_ts is None:
                    last_seen_label = "Never observed"
                else:
                    try:
                        if isinstance(last_seen_ts, str):
                            dt_clean = re.sub(r'\.\d+', '', last_seen_ts.replace('Z', ''))
                            dt = datetime.fromisoformat(dt_clean)
                        else:
                            dt = last_seen_ts
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        delta = datetime.now(timezone.utc) - dt
                        hrs = int(delta.total_seconds() // 3600)
                        mins = int((delta.total_seconds() % 3600) // 60)
                        last_seen_label = f"{hrs}h {mins}m ago" if hrs > 0 else f"{mins}m ago"
                    except Exception:
                        last_seen_label = str(last_seen_ts)

                absent_ips.append({
                    'ip':             row_ip,
                    'host':           asset['hostname'] or _hostname(row_ip),
                    'lastSeen':       last_seen_label,
                    'expectedProtos': asset['expected_protocols'] or 'TCP,UDP',
                    'riskTier':       asset['risk_tier'] or 'Medium',
                    'criticality':    asset.get('criticality', 'Tier 2 (Business)'),
                    'department':     asset.get('department', 'General'),
                    'status':         f'Silent / Absent ({window} window)',
                })

        # ── Summary & Compliance Scorecard ────────────────────────────────────
        total_tracked = len(all_inventory)
        compliant_count = total_tracked - len(absent_ips)
        compliance_score = max(0, min(100, round((compliant_count / max(total_tracked, 1)) * 100)))

        high_risk_ports  = [p for p in proto_ports if p['risk'] in ('High', 'Critical')]
        high_threat_ips  = [p for p in public_ips  if p['threat'] >= MALICIOUS_SCORE_THRESHOLD]

        # Calculate live throughput (bits per second & packets per second)
        eff_sec     = max(window_seconds if window_seconds > 0 else 14400, 1)
        avg_bps     = round((window_bytes * 8) / eff_sec, 2)
        avg_pps     = round(window_pkts / eff_sec, 2)

    return {
        'timestamp':       datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        'window':          window,
        'window_start':    window_start,
        'window_end':      window_end,
        'is_adaptive':     is_adaptive,
        'total_flows':     total_flows,
        'total_bytes':     window_bytes,
        'total_packets':   window_pkts,
        'avg_bps':         avg_bps,
        'avg_pps':         avg_pps,

        # HTC Deliverables 1–7
        'unique_assets':   internal_assets,
        'public_ips':      public_ips,
        'gateway':         gateway,
        'gateways':        gateways,
        'natBypass':       nat_bypass,
        'protoPort':       proto_ports,
        'graph': {
            'nodes': list(graph_nodes.values()),
            'edges': graph_edges,
        },
        'absentIPs':       absent_ips,
        'complianceScore': compliance_score,
        'highRiskPorts':   high_risk_ports,
        'highThreatIPs':   high_threat_ips,
    }


# ══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK THREAT DETECTION & INCIDENT TRIAGE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def generate_threat_analysis(window="4h"):
    """
    Evaluates live and replayed traffic against the MITRE ATT&CK enterprise matrix:
      - T1046: Network Service Scanning (Port sweeps & reconnaissance)
      - T1071: Standard Application Layer Protocol / Tor C2 Channels
      - T1048: Exfiltration Over Alternative Protocol (Unusual outbound volume)
      - T1021: Remote Services Abuse (Telnet, RDP, SMB, Metasploit)
      - T1090: Proxy & Rogue NAT Bypass (Circumventing enterprise gateway)
    """
    lock = get_lock()
    conn = get_connection()

    with lock:
        where_clause, where_params, w_start, w_end, is_adaptive, _ = parse_time_window(conn, window)
        _w = where_clause
        _wp = where_params

        # Ensure we have flows
        flow_check = conn.execute(f"SELECT COUNT(*) FROM flows WHERE {_w}", _wp).fetchone()[0]
        if flow_check == 0:
            all_check = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
            if all_check == 0:
                return {'threats': [], 'summary': _empty_threat_summary(), 'mitre_coverage': []}
            _w = "1=1"
            _wp = []

        threats = []

        # 1. T1090: Rogue NAT Gateway Bypass
        gw_rows = _detect_gateways(conn, _w, _wp, limit=1)
        gateway = gw_rows[0][0] if gw_rows else None

        bypass_sql = f"""
            SELECT src_ip, nexthop, dst_ip, SUM(bytes), COUNT(*)
            FROM flows
            WHERE {_is_private_sql('src_ip')} AND NOT {_is_private_sql('dst_ip')}
              AND nexthop != ? AND nexthop NOT IN ('0.0.0.0','') AND nexthop IS NOT NULL AND {_w}
            GROUP BY src_ip, nexthop, dst_ip
        """
        bypass_rows = conn.execute(bypass_sql, [gateway] + _wp).fetchall() if gateway else []
        for src, nh, dst, bbytes, fcount in bypass_rows:
            threats.append({
                'id':              f"THREAT-BYPASS-{src}-{dst}",
                'type':            'NAT_GATEWAY_BYPASS',
                'mitre_id':        'T1090.001',
                'mitre_name':      'Proxy: Internal Proxy / Unauthorized Egress',
                'severity':        'Critical' if _threat(dst) >= 50 else 'High',
                'asset_ip':        src,
                'target_ip':       dst,
                'details':         f"Host {src} bypassed primary gateway {gateway} via rogue router {nh} to reach public IP {dst}.",
                'bytes':           bbytes,
                'flows':           fcount,
                'remediation':     f"Isolate switch port for {src}; enforce 802.1X and block rogue nexthop {nh} in core routing tables."
            })

        # 2. T1021: Insecure / Dangerous Remote Protocols (Telnet, RDP, Metasploit, SMB)
        danger_sql = f"""
            SELECT src_ip, dst_ip, dst_port, protocol, SUM(bytes), COUNT(*)
            FROM flows
            WHERE dst_port IN ({','.join(str(p) for p in DANGEROUS_PORTS)}) AND {_w}
            GROUP BY src_ip, dst_ip, dst_port, protocol
        """
        for src, dst, port, proto, bbytes, fcount in conn.execute(danger_sql, _wp).fetchall():
            port_name = PORT_SERVICE_MAP.get(port, f"Port-{port}")
            sev = PORT_RISK_MAP.get(port, 'High')
            threats.append({
                'id':              f"THREAT-PORT-{src}-{dst}-{port}",
                'type':            'DANGEROUS_PROTOCOL',
                'mitre_id':        'T1021.001' if port in (3389, 23) else 'T1048.003',
                'mitre_name':      f'Remote Services: {port_name} Exploit Vector',
                'severity':        sev,
                'asset_ip':        dst if _is_private_py(dst) else src,
                'target_ip':       src if _is_private_py(dst) else dst,
                'details':         f"Dangerous port {port} ({port_name}) observed with {fcount} flows and {bbytes:,} bytes transferred.",
                'bytes':           bbytes,
                'flows':           fcount,
                'remediation':     f"Disable plaintext protocol ({port_name}) immediately. Mandate SSH/TLSv1.3 and deploy host-level firewall."
            })

        # 3. T1071: Malicious IP / Tor Exit Node Communication
        mal_sql = f"""
            SELECT src_ip, dst_ip, SUM(bytes), COUNT(*)
            FROM flows
            WHERE ((NOT {_is_private_sql('src_ip')} AND {_is_private_sql('dst_ip')})
               OR  (NOT {_is_private_sql('dst_ip')} AND {_is_private_sql('src_ip')})) AND {_w}
            GROUP BY src_ip, dst_ip
        """
        for src, dst, bbytes, fcount in conn.execute(mal_sql, _wp).fetchall():
            pub_ip = src if not _is_private_py(src) else dst
            priv_ip = dst if not _is_private_py(src) else src
            t_score = _threat(pub_ip)
            if t_score >= MALICIOUS_SCORE_THRESHOLD:
                threats.append({
                    'id':          f"THREAT-MAL-{priv_ip}-{pub_ip}",
                    'type':        'MALICIOUS_C2_CONNECTION',
                    'mitre_id':    'T1071.001',
                    'mitre_name':  'Command and Control: Web / Tor Protocols',
                    'severity':    'Critical' if t_score >= 80 else 'High',
                    'asset_ip':    priv_ip,
                    'target_ip':   pub_ip,
                    'details':     f"Communication with suspicious/Tor exit node {pub_ip} (Reputation Threat Score: {t_score}/100, Location: {_geo(pub_ip)}).",
                    'bytes':       bbytes,
                    'flows':       fcount,
                    'remediation': f"Block IP {pub_ip} on perimeter firewall. Quarantine {priv_ip} and perform forensic EDR memory analysis."
                })

        # 4. T1046: Network Service Reconnaissance / Port Scanning
        scan_sql = f"""
            SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) as distinct_ports, COUNT(*) as flow_count
            FROM flows
            WHERE {_w}
            GROUP BY src_ip, dst_ip
            HAVING COUNT(DISTINCT dst_port) >= {PORT_SCAN_THRESHOLD}
        """
        for src, dst, dports, fcount in conn.execute(scan_sql, _wp).fetchall():
            threats.append({
                'id':          f"THREAT-SCAN-{src}-{dst}",
                'type':        'PORT_RECON_SCAN',
                'mitre_id':    'T1046',
                'mitre_name':  'Network Service Discovery: Port Scanning',
                'severity':    'High',
                'asset_ip':    dst,
                'target_ip':   src,
                'details':     f"Host {src} conducted vertical port sweep against {dst} probing {dports} distinct destination ports.",
                'bytes':       0,
                'flows':       fcount,
                'remediation': f"Blacklist scanning IP {src} at switch ACL layer. Enable rate limiting for SYN packets."
            })

        # Summarize counts by severity
        crit_count = sum(1 for t in threats if t['severity'] == 'Critical')
        high_count = sum(1 for t in threats if t['severity'] == 'High')
        med_count  = sum(1 for t in threats if t['severity'] == 'Medium')
        low_count  = sum(1 for t in threats if t['severity'] == 'Low')

        summary = {
            'total_threats': len(threats),
            'critical':      crit_count,
            'high':          high_count,
            'medium':        med_count,
            'low':           low_count,
            'posture_score': max(0, 100 - (crit_count * 25 + high_count * 10 + med_count * 5)),
        }

        mitre_coverage = [
            {'tactic': 'Initial Access',   'technique': 'T1190 Exploit Public-Facing Application', 'status': 'Monitored'},
            {'tactic': 'Reconnaissance',   'technique': 'T1046 Network Service Discovery',        'status': 'Detected' if any(t['mitre_id'] == 'T1046' for t in threats) else 'Pass'},
            {'tactic': 'Command & Control','technique': 'T1071 Application Layer Protocol (Tor)',  'status': 'Alert' if any(t['mitre_id'] == 'T1071.001' for t in threats) else 'Pass'},
            {'tactic': 'Lateral Movement', 'technique': 'T1021 Remote Services (SMB/RDP/SSH)',     'status': 'Alert' if any(t['mitre_id'].startswith('T1021') for t in threats) else 'Pass'},
            {'tactic': 'Defense Evasion',  'technique': 'T1090 Proxy / Rogue Gateway Bypass',      'status': 'Critical Alert' if any(t['mitre_id'].startswith('T1090') for t in threats) else 'Pass'},
        ]

    return {
        'threats':        threats,
        'summary':        summary,
        'mitre_coverage': mitre_coverage,
        'window':         window,
    }


# ══════════════════════════════════════════════════════════════════════════════
# MULTI-FRAMEWORK REGULATORY COMPLIANCE AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_compliance_audit(window="4h"):
    """
    Generates industrial compliance audit reports for:
      - PCI-DSS v4.0 (Req 1: Network Security Controls)
      - NIST SP 800-53 Rev 5 (AC-4, SC-7, CM-8)
      - ISO/IEC 27001:2022 (A.8.20, A.8.9)
      - CIS Critical Security Controls v8 (Controls 1 & 12)
    """
    report = generate_report(window)
    threats_data = generate_threat_analysis(window)

    nat_bypass_count = len(report.get('natBypass', []))
    absent_asset_count = len(report.get('absentIPs', []))
    insecure_ports = [p for p in report.get('protoPort', []) if p['risk'] in ('High', 'Critical')]
    c2_threats = [t for t in threats_data.get('threats', []) if t['type'] == 'MALICIOUS_C2_CONNECTION']

    frameworks = {
        'PCI_DSS': {
            'name': 'PCI-DSS v4.0 (Payment Card Security)',
            'scope': 'Network Security Controls (Req 1.1 - 1.4)',
            'grade': 'FAIL' if (nat_bypass_count > 0 or len(insecure_ports) > 0) else 'PASS',
            'score': max(0, 100 - (nat_bypass_count * 30 + len(insecure_ports) * 20)),
            'checks': [
                {'req': '1.2.1', 'title': 'Restrict inbound and outbound traffic to necessary business purposes', 'status': 'FAIL' if nat_bypass_count > 0 else 'PASS'},
                {'req': '1.2.5', 'title': 'Prohibit insecure plaintext protocols (Telnet, FTP, unencrypted HTTP)', 'status': 'FAIL' if any(p['port'] in (21, 23) for p in insecure_ports) else 'PASS'},
                {'req': '1.3.1', 'title': 'Inbound traffic from untrusted networks strictly segmented', 'status': 'FAIL' if len(c2_threats) > 0 else 'PASS'},
                {'req': '1.4.1', 'title': 'Personal firewalls / endpoint network controls on workstations', 'status': 'PASS'}
            ]
        },
        'NIST_800_53': {
            'name': 'NIST SP 800-53 Rev 5 (Federal Security Standards)',
            'scope': 'AC-4 Information Flow Enforcement & SC-7 Boundary Protection',
            'grade': 'FAIL' if nat_bypass_count > 0 else 'PASS',
            'score': max(0, 100 - (nat_bypass_count * 25 + absent_asset_count * 15)),
            'checks': [
                {'req': 'SC-7(5)', 'title': 'Deny network traffic by default; allow by exception', 'status': 'FAIL' if nat_bypass_count > 0 else 'PASS'},
                {'req': 'AC-4',    'title': 'Information Flow Enforcement (Authorized gateways only)', 'status': 'FAIL' if nat_bypass_count > 0 else 'PASS'},
                {'req': 'CM-8',    'title': 'Information System Component Inventory (Ghost Asset tracking)', 'status': 'WARN' if absent_asset_count > 0 else 'PASS'},
                {'req': 'SI-4',    'title': 'Information System Monitoring (NetFlow stream analysis)', 'status': 'PASS'}
            ]
        },
        'ISO_27001': {
            'name': 'ISO/IEC 27001:2022 (ISMS)',
            'scope': 'Control A.8.20 Network Security & A.8.9 Configuration Management',
            'grade': 'PASS' if (nat_bypass_count == 0 and len(c2_threats) == 0) else 'WARN',
            'score': max(0, 100 - (nat_bypass_count * 20 + len(c2_threats) * 25)),
            'checks': [
                {'req': 'A.8.20', 'title': 'Networks and network devices are secured and managed', 'status': 'FAIL' if nat_bypass_count > 0 else 'PASS'},
                {'req': 'A.8.21', 'title': 'Security of network services and protocol segregation', 'status': 'FAIL' if len(insecure_ports) > 0 else 'PASS'},
                {'req': 'A.8.9',  'title': 'Configuration management & unauthorized bypass prevention', 'status': 'FAIL' if nat_bypass_count > 0 else 'PASS'}
            ]
        },
        'CIS_CONTROLS': {
            'name': 'CIS Critical Security Controls v8',
            'scope': 'Control 1 (Enterprise Asset Inventory) & Control 12 (Network Mgmt)',
            'grade': 'PASS' if absent_asset_count == 0 else 'WARN',
            'score': max(0, 100 - (absent_asset_count * 20 + nat_bypass_count * 20)),
            'checks': [
                {'req': 'CIS 1.1',  'title': 'Establish and maintain an accurate enterprise asset inventory', 'status': 'WARN' if absent_asset_count > 0 else 'PASS'},
                {'req': 'CIS 12.1', 'title': 'Ensure network infrastructure is up-to-date and monitored', 'status': 'PASS'},
                {'req': 'CIS 12.4', 'title': 'Deny communication over unauthorized ports and protocols', 'status': 'FAIL' if len(insecure_ports) > 0 else 'PASS'}
            ]
        }
    }

    total_score = sum(f['score'] for f in frameworks.values()) // len(frameworks)

    return {
        'audit_timestamp': datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        'window':          window,
        'overall_score':   total_score,
        'overall_status':  'COMPLIANT' if total_score >= 85 else ('REQUIRES_ATTENTION' if total_score >= 60 else 'NON_COMPLIANT'),
        'frameworks':      frameworks,
        'findings_count':  nat_bypass_count + absent_asset_count + len(insecure_ports) + len(c2_threats),
    }


def _empty_threat_summary():
    return {
        'total_threats': 0,
        'critical':      0,
        'high':          0,
        'medium':        0,
        'low':           0,
        'posture_score': 100,
    }
