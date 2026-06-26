# import duckdb
# import os

# DB_FILE = os.getenv("DUCKDB_FILE", "netflow.duckdb")

# def get_connection():
#     # Connects to DuckDB file (creates it if it doesn't exist)
#     conn = duckdb.connect(DB_FILE)
#     return conn

# def init_db():
#     conn = get_connection()
#     # Create the flows table
#     conn.execute("""
#         CREATE TABLE IF NOT EXISTS flows (
#             id BIGINT PRIMARY KEY,
#             src_ip VARCHAR,
#             dst_ip VARCHAR,
#             nexthop VARCHAR,
#             input_snmp INTEGER,
#             output_snmp INTEGER,
#             packets INTEGER,
#             bytes INTEGER,
#             first_switched BIGINT,
#             last_switched BIGINT,
#             src_port INTEGER,
#             dst_port INTEGER,
#             tcp_flags INTEGER,
#             protocol INTEGER,
#             tos INTEGER,
#             src_as INTEGER,
#             dst_as INTEGER,
#             src_mask INTEGER,
#             dst_mask INTEGER,
#             timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
#         );
        
#         -- Create a sequence for the ID
#         CREATE SEQUENCE IF NOT EXISTS flow_id_seq;
#     """)
#     conn.close()

# if __name__ == "__main__":
#     init_db()
#     print("Database initialized successfully.")

import duckdb
import os
import threading

DB_FILE = os.getenv("DUCKDB_FILE", "netflow.duckdb")

# Single shared connection + lock to prevent concurrent write conflicts (DuckDB limitation)
_conn = None
_lock = threading.Lock()

def get_connection():
    """Return the shared DuckDB connection. Thread-safe via _lock."""
    global _conn
    if _conn is None:
        _conn = duckdb.connect(DB_FILE)
    return _conn

def get_lock():
    return _lock

def init_db():
    with _lock:
        conn = get_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id            BIGINT PRIMARY KEY,
                src_ip        VARCHAR,
                dst_ip        VARCHAR,
                nexthop       VARCHAR,
                input_snmp    INTEGER,
                output_snmp   INTEGER,
                packets       INTEGER,
                bytes         INTEGER,
                first_switched BIGINT,
                last_switched  BIGINT,
                src_port      INTEGER,
                dst_port      INTEGER,
                tcp_flags     INTEGER,
                protocol      INTEGER,
                tos           INTEGER,
                src_as        INTEGER,
                dst_as        INTEGER,
                src_mask      INTEGER,
                dst_mask      INTEGER,
                timestamp     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("CREATE SEQUENCE IF NOT EXISTS flow_id_seq;")
        conn.commit()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
