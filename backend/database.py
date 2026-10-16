"""
HTC NetFlow Analyzer Pro — Enterprise DuckDB Storage Layer
==========================================================
Thread-safe connection pooling, schema migration, asset inventory,
and audit logging for industrial compliance & SOC analytics.
"""

import duckdb
import json
import os
import threading
from datetime import datetime, timezone

# -----------------------------------------------------------------------------
# Database Configuration
# -----------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.getenv(
    "DUCKDB_FILE",
    os.path.join(BASE_DIR, "netflow.duckdb")
)

_conn = None
_lock = threading.RLock()


def get_connection():
    """
    Returns a single shared DuckDB connection.
    Thread-safe.
    """
    global _conn
    with _lock:
        if _conn is None:
            try:
                _conn = duckdb.connect(
                    database=DB_FILE,
                    read_only=False
                )
                _conn.execute("PRAGMA enable_object_cache;")
                _conn.execute("PRAGMA threads=4;")
            except Exception as e:
                raise RuntimeError(
                    f"Unable to open DuckDB database:\n{e}"
                )
        return _conn


def get_lock():
    """Returns the global database lock."""
    return _lock


# -----------------------------------------------------------------------------
# Initialize Database Schema & Enterprise Seed Data
# -----------------------------------------------------------------------------

def init_db():
    with _lock:
        conn = get_connection()
        try:
            # 1. Flow Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    id BIGINT PRIMARY KEY,
                    src_ip VARCHAR,
                    dst_ip VARCHAR,
                    nexthop VARCHAR,
                    input_snmp INTEGER,
                    output_snmp INTEGER,
                    packets INTEGER,
                    bytes INTEGER,
                    first_switched BIGINT,
                    last_switched BIGINT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    tcp_flags INTEGER,
                    protocol INTEGER,
                    tos INTEGER,
                    src_as INTEGER,
                    dst_as INTEGER,
                    src_mask INTEGER,
                    dst_mask INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            conn.execute("""
                CREATE SEQUENCE IF NOT EXISTS flow_id_seq;
            """)

            # 2. Asset Inventory Table with Enterprise Criticality & Compliance Tags
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    ip                 VARCHAR PRIMARY KEY,
                    hostname           VARCHAR,
                    expected_protocols VARCHAR,
                    risk_tier          VARCHAR,
                    criticality        VARCHAR DEFAULT 'Tier 2 (Business)',
                    department         VARCHAR DEFAULT 'Engineering',
                    compliance_scope   VARCHAR DEFAULT 'PCI-DSS, NIST'
                );
            """)

            # Schema migration for existing tables
            try:
                conn.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS criticality VARCHAR DEFAULT 'Tier 2 (Business)';")
                conn.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS department VARCHAR DEFAULT 'Engineering';")
                conn.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS compliance_scope VARCHAR DEFAULT 'PCI-DSS, NIST';")
            except Exception:
                pass

            # 3. Security & Audit Incident Log Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id                 VARCHAR PRIMARY KEY,
                    timestamp          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    event_type         VARCHAR,
                    severity           VARCHAR,
                    framework          VARCHAR,
                    asset_ip           VARCHAR,
                    description        VARCHAR,
                    remediation        VARCHAR
                );
            """)

            # 4. Compliance report snapshots (one per 4-hour period, plus manual runs)
            conn.execute("CREATE SEQUENCE IF NOT EXISTS report_id_seq;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id                 BIGINT PRIMARY KEY,
                    window_start       TIMESTAMP,
                    window_end         TIMESTAMP,
                    generated_at       TIMESTAMP,
                    trigger            VARCHAR,
                    total_flows        BIGINT,
                    asset_count        INTEGER,
                    absent_count       INTEGER,
                    compliance_score   INTEGER,
                    report_json        VARCHAR
                );
            """)

            # Seed realistic corporate assets if empty
            existing = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            if existing == 0:
                seed_rows = [
                    ('10.0.0.1',       'core-gateway-01',    'TCP,UDP,ICMP', 'Low',      'Tier 1 (Mission-Critical)', 'Infrastructure', 'NIST, CIS, PCI-DSS'),
                    ('10.0.0.10',      'prod-web-01',        'TCP,HTTPS,HTTP', 'Low',    'Tier 1 (Mission-Critical)', 'Production',     'PCI-DSS, ISO 27001'),
                    ('10.0.0.11',      'prod-web-02',        'TCP,HTTPS,HTTP', 'Low',    'Tier 1 (Mission-Critical)', 'Production',     'PCI-DSS, ISO 27001'),
                    ('10.0.0.20',      'customer-db-primary','TCP,MySQL,SMB', 'High',    'Tier 1 (Mission-Critical)', 'Database Ops',   'PCI-DSS, HIPAA, GDPR'),
                    ('10.0.0.21',      'reporting-db-replica','TCP,PostgreSQL', 'High',  'Tier 2 (Business)',         'Analytics',      'ISO 27001'),
                    ('10.0.0.30',      'app-service-node',   'TCP,HTTP,MySQL', 'Medium', 'Tier 2 (Business)',         'Engineering',    'PCI-DSS, NIST'),
                    ('10.0.0.40',      'corp-mail-relay',    'TCP,SMTP,HTTPS', 'Medium', 'Tier 2 (Business)',         'IT Ops',         'NIST, CIS'),
                    ('10.0.0.50',      'corp-file-storage',  'TCP,SMB,SSH',    'High',   'Tier 2 (Business)',         'IT Ops',         'HIPAA, ISO 27001'),
                    ('10.0.1.100',     'workstation-exec-01','TCP,UDP,HTTPS',  'Medium', 'Tier 3 (Internal)',         'Executive',      'NIST, CIS'),
                    ('10.0.1.101',     'workstation-dev-01', 'TCP,UDP,SSH',    'Medium', 'Tier 3 (Internal)',         'Engineering',    'CIS Controls'),
                    ('10.0.1.102',     'workstation-fin-01', 'TCP,UDP,HTTPS',  'High',   'Tier 2 (Business)',         'Finance',        'PCI-DSS, SOX'),
                    ('192.168.10.5',   'rd-lab-workstation', 'TCP,UDP',        'Medium', 'Tier 3 (Internal)',         'R&D',            'NIST'),
                    ('192.168.1.100',  'sec-eng-laptop',     'TCP,UDP,SSH',    'Medium', 'Tier 3 (Internal)',         'Security Ops',   'CIS Controls'),
                    ('192.168.1.200',  'facility-iot-gateway','UDP,ICMP',      'High',   'Tier 4 (Peripheral)',       'Facilities',     'NIST IoT'),
                ]
                conn.executemany(
                    """
                    INSERT INTO assets (ip, hostname, expected_protocols, risk_tier, criticality, department, compliance_scope)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (ip) DO UPDATE SET
                        hostname = EXCLUDED.hostname,
                        expected_protocols = EXCLUDED.expected_protocols,
                        risk_tier = EXCLUDED.risk_tier,
                        criticality = EXCLUDED.criticality,
                        department = EXCLUDED.department,
                        compliance_scope = EXCLUDED.compliance_scope;
                    """,
                    seed_rows
                )
                print(f"[Database] Seeded {len(seed_rows)} enterprise asset records.")

            conn.commit()
            conn.execute("CHECKPOINT;")

        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            raise RuntimeError(f"Database initialization failed:\n{e}")


# -----------------------------------------------------------------------------
# Asset Inventory Helpers
# -----------------------------------------------------------------------------

def get_all_assets():
    """Retrieve all configured asset inventory records."""
    lock = get_lock()
    conn = get_connection()
    with lock:
        rows = conn.execute("""
            SELECT ip, hostname, expected_protocols, risk_tier, criticality, department, compliance_scope
            FROM assets
            ORDER BY ip ASC
        """).fetchall()
        return [
            {
                'ip': r[0],
                'hostname': r[1],
                'expected_protocols': r[2],
                'risk_tier': r[3],
                'criticality': r[4] or 'Tier 2 (Business)',
                'department': r[5] or 'General',
                'compliance_scope': r[6] or 'Standard'
            }
            for r in rows
        ]


def upsert_asset(ip, hostname, expected_protocols, risk_tier, criticality='Tier 2 (Business)', department='General', compliance_scope='PCI-DSS, NIST'):
    """Create or update an asset inventory record."""
    lock = get_lock()
    conn = get_connection()
    with lock:
        conn.execute("""
            INSERT INTO assets (ip, hostname, expected_protocols, risk_tier, criticality, department, compliance_scope)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (ip) DO UPDATE SET
                hostname = EXCLUDED.hostname,
                expected_protocols = EXCLUDED.expected_protocols,
                risk_tier = EXCLUDED.risk_tier,
                criticality = EXCLUDED.criticality,
                department = EXCLUDED.department,
                compliance_scope = EXCLUDED.compliance_scope;
        """, [ip, hostname, expected_protocols, risk_tier, criticality, department, compliance_scope])
        conn.commit()
        return True


def delete_asset(ip):
    """Remove an asset inventory record."""
    lock = get_lock()
    conn = get_connection()
    with lock:
        conn.execute("DELETE FROM assets WHERE ip = ?", [ip])
        conn.commit()
        return True


# -----------------------------------------------------------------------------
# Compliance Report Snapshots
# -----------------------------------------------------------------------------

_REPORT_META_COLS = "id, window_start, window_end, generated_at, trigger, total_flows, asset_count, absent_count, compliance_score"


def _report_meta(row):
    return {
        'id':              row[0],
        'window_start':    str(row[1]),
        'window_end':      str(row[2]),
        'generated_at':    str(row[3]),
        'trigger':         row[4],
        'total_flows':     row[5],
        'asset_count':     row[6],
        'absent_count':    row[7],
        'compliance_score': row[8],
    }


def save_report(report, window_start, window_end, trigger):
    """Store a generated report; returns its metadata."""
    with _lock:
        conn = get_connection()
        report_id = conn.execute("SELECT nextval('report_id_seq')").fetchone()[0]
        conn.execute("""
            INSERT INTO reports (id, window_start, window_end, generated_at, trigger,
                                 total_flows, asset_count, absent_count, compliance_score, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            report_id, window_start, window_end,
            datetime.now(timezone.utc).replace(tzinfo=None), trigger,
            report.get('total_flows', 0), len(report.get('unique_assets', [])),
            len(report.get('absentIPs', [])), report.get('complianceScore', 0),
            json.dumps(report, default=str),
        ])
        conn.commit()
        row = conn.execute(f"SELECT {_REPORT_META_COLS} FROM reports WHERE id = ?", [report_id]).fetchone()
        return _report_meta(row)


def scheduled_report_exists(window_start, window_end):
    with _lock:
        conn = get_connection()
        return conn.execute(
            "SELECT COUNT(*) FROM reports WHERE trigger = 'scheduled' AND window_start = ? AND window_end = ?",
            [window_start, window_end]).fetchone()[0] > 0


def list_reports(limit=50):
    with _lock:
        conn = get_connection()
        rows = conn.execute(
            f"SELECT {_REPORT_META_COLS} FROM reports ORDER BY window_end DESC, id DESC LIMIT ?", [limit]).fetchall()
        return [_report_meta(r) for r in rows]


def get_report(report_id):
    with _lock:
        conn = get_connection()
        row = conn.execute(
            f"SELECT {_REPORT_META_COLS}, report_json FROM reports WHERE id = ?", [report_id]).fetchone()
        if not row:
            return None
        meta = _report_meta(row)
        meta['report'] = json.loads(row[9])
        return meta


def is_connected():
    try:
        conn = get_connection()
        conn.execute("SELECT 1")
        return True
    except Exception:
        return False


def close_connection():
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.commit()
                _conn.execute("CHECKPOINT;")
                _conn.close()
            except Exception as e:
                print(f"[Database] Close warning: {e}")
            finally:
                _conn = None


if __name__ == "__main__":
    try:
        init_db()
        conn = get_connection()
        asset_count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        print("===================================")
        print(" DuckDB initialized successfully")
        print(" Database :", DB_FILE)
        print(" Connected:", is_connected())
        print(f" Assets   : {asset_count} enterprise assets in inventory")
        print("===================================")
    finally:
        close_connection()