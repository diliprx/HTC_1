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

# import duckdb
# import os
# import threading

# DB_FILE = os.getenv("DUCKDB_FILE", "netflow.duckdb")


# # Single shared connection + lock to prevent concurrent write conflicts (DuckDB limitation)
# _conn = None
# _lock = threading.Lock()

# def get_connection():
#     """Return the shared DuckDB connection. Thread-safe via _lock."""
#     global _conn
#     if _conn is None:
#        try:
#          _conn = duckdb.connect(
#              database=DB_FILE,
#              read_only=False
#              )
#        except Exception as e:
#          raise RuntimeError(f"Cannot open DuckDB database: {e}")
#     return _conn

# def get_lock():
#     return _lock

# def init_db():
#     with _lock:
#         conn = get_connection()
#         conn.execute("""
#             CREATE TABLE IF NOT EXISTS flows (
#                 id            BIGINT PRIMARY KEY,
#                 src_ip        VARCHAR,
#                 dst_ip        VARCHAR,
#                 nexthop       VARCHAR,
#                 input_snmp    INTEGER,
#                 output_snmp   INTEGER,
#                 packets       INTEGER,
#                 bytes         INTEGER,
#                 first_switched BIGINT,
#                 last_switched  BIGINT,
#                 src_port      INTEGER,
#                 dst_port      INTEGER,
#                 tcp_flags     INTEGER,
#                 protocol      INTEGER,
#                 tos           INTEGER,
#                 src_as        INTEGER,
#                 dst_as        INTEGER,
#                 src_mask      INTEGER,
#                 dst_mask      INTEGER,
#                 timestamp     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
#             );
#         """)
#         conn.execute("CREATE SEQUENCE IF NOT EXISTS flow_id_seq;")
#         conn.commit()
#         conn.execute("CHECKPOINT;")

# if __name__ == "__main__":
#     init_db()
#     print("Database initialized successfully.")

import duckdb
import os
import threading

# -----------------------------------------------------------------------------
# Database Configuration
# -----------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.getenv(
    "DUCKDB_FILE",
    os.path.join(BASE_DIR, "netflow.duckdb")
)

# -----------------------------------------------------------------------------
# Global Shared Connection
# -----------------------------------------------------------------------------

_conn = None
_lock = threading.Lock()


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

                # Improve query performance
                _conn.execute("PRAGMA enable_object_cache;")

            except Exception as e:
                raise RuntimeError(
                    f"Unable to open DuckDB database:\n{e}"
                )

        return _conn


def get_lock():
    """
    Returns the global database lock.
    """
    return _lock


# -----------------------------------------------------------------------------
# Initialize Database
# -----------------------------------------------------------------------------

def init_db():

    with _lock:

        conn = get_connection()

        try:

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

            conn.commit()

            # Flush to disk
            conn.execute("CHECKPOINT;")

        except Exception as e:

            try:
                conn.rollback()
            except:
                pass

            raise RuntimeError(
                f"Database initialization failed:\n{e}"
            )


# -----------------------------------------------------------------------------
# Health Check
# -----------------------------------------------------------------------------

def is_connected():

    try:

        conn = get_connection()

        conn.execute("SELECT 1")

        return True

    except:

        return False


# -----------------------------------------------------------------------------
# Close Connection
# -----------------------------------------------------------------------------

def close_connection():

    global _conn

    with _lock:

        if _conn is not None:

            try:

                _conn.commit()

                conn = _conn

                conn.execute("CHECKPOINT;")

                conn.close()

            except Exception as e:

                print(f"[Database] Close warning: {e}")

            finally:

                _conn = None


# -----------------------------------------------------------------------------
# Manual Test
# -----------------------------------------------------------------------------

if __name__ == "__main__":

    try:

        init_db()

        print("===================================")
        print(" DuckDB initialized successfully")
        print(" Database :", DB_FILE)
        print(" Connected:", is_connected())
        print("===================================")

    finally:

        close_connection()