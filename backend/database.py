import sqlite3
import os
import sys
import pandas as pd
from datetime import datetime

# Configure UTF-8 for console output on Windows to prevent UnicodeEncodeError
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Path configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'acis_database.db')
SCHEMA_PATH = os.path.join(BASE_DIR, 'schema.sql')

# Header mapping from CSV names to SQL column names (matching data.csv)
COLUMN_MAPPING = {
    'Timestamp': 'timestamp',
    'Source IP Address': 'source_ip',
    'Destination IP Address': 'destination_ip',
    'Source Port': 'source_port',
    'Destination Port': 'destination_port',
    'Protocol': 'protocol',
    'Packet Length': 'packet_length',
    'Packet Type': 'packet_type',
    'Traffic Type': 'traffic_type',
    'Payload Data': 'payload_data',
    'Malware Indicators': 'malware_indicators',
    'Anomaly Scores': 'anomaly_scores',
    'Alerts/Warnings': 'alerts_warnings',
    'Attack Type': 'attack_type',
    'Attack Signature': 'attack_signature',
    'Action Taken': 'action_taken',
    'Severity Level': 'severity_level',
    'User Information': 'user_information',
    'Device Information': 'device_information',
    'Network Segment': 'network_segment',
    'Geo-location Data': 'geo_location_data',
    'Proxy Information': 'proxy_information',
    'Firewall Logs': 'firewall_logs',
    'IDS/IPS Alerts': 'ids_ips_alerts',
    'Log Source': 'log_source',
    # Common variations & legacy fallbacks
    'source_ip_address': 'source_ip',
    'destination_ip_address': 'destination_ip',
    'severity': 'severity_level',
    'Label': 'attack_type',
    'label': 'attack_type'
}

def find_data_csv_path():
    """Locate data.csv regardless of current working directory."""
    candidates = [
        os.path.join(BASE_DIR, '..', 'data.csv'),
        os.path.join(BASE_DIR, 'data.csv'),
        os.path.join(os.getcwd(), 'ACIS-Core', 'data.csv'),
        os.path.join(os.getcwd(), 'data.csv'),
        os.path.join(os.getcwd(), '..', 'data.csv')
    ]
    for p in candidates:
        if os.path.exists(p) and os.path.isfile(p):
            return os.path.abspath(p)
    return None

def get_connection():
    """Establish and return SQLite database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(force_recreate=False):
    """Initialize SQL database using schema.sql DDL and ensure table columns match data.csv."""
    if not os.path.exists(SCHEMA_PATH):
        print(f"[WARN] schema.sql not found at {SCHEMA_PATH}")
        return

    with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
        schema_sql = f.read()

    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        # Check if existing network_traffic has legacy schema
        cursor.execute("PRAGMA table_info(network_traffic)")
        existing_cols = set(row[1] for row in cursor.fetchall())
        
        if existing_cols and ('flow_duration' in existing_cols or 'source_ip' not in existing_cols or force_recreate):
            cursor.execute("DROP TABLE IF EXISTS network_traffic")
            conn.commit()

        conn.executescript(schema_sql)
        conn.commit()
        print(f"[OK] SQL Database initialized successfully at: {DB_PATH}")
    except Exception as e:
        print(f"[WARN] Error initializing database: {e}")
    finally:
        conn.close()

def normalize_column_name(col):
    """Normalize CSV column names to SQL column names."""
    col_clean = str(col).strip()
    if col_clean in COLUMN_MAPPING:
        return COLUMN_MAPPING[col_clean]
    
    # Check case-insensitive match in mapping
    col_lower = col_clean.lower()
    for k, v in COLUMN_MAPPING.items():
        if k.lower() == col_lower:
            return v

    clean = "".join([c if c.isalnum() else "_" for c in col_clean]).lower()
    return clean.strip('_')

def get_traffic_count():
    """Return total row count of network_traffic table."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM network_traffic")
        count = cursor.fetchone()[0]
        return count
    except Exception:
        return 0
    finally:
        conn.close()

def save_traffic_chunk(df, if_exists='append'):
    """Save pandas DataFrame chunk into network_traffic table."""
    df_sql = df.copy()
    new_cols = {col: normalize_column_name(col) for col in df_sql.columns}
    df_sql = df_sql.rename(columns=new_cols)

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(network_traffic)")
        table_cols = set(row[1] for row in cursor.fetchall())
        
        valid_cols = [c for c in df_sql.columns if c in table_cols]
        if valid_cols:
            df_to_save = df_sql[valid_cols]
            df_to_save.to_sql('network_traffic', conn, if_exists=if_exists, index=False, chunksize=5000)
            conn.commit()
    finally:
        conn.close()

def load_training_data(limit=50000):
    """
    Retrieve network traffic rows from SQL database for ML model training.
    If database is empty, returns None.
    """
    count = get_traffic_count()
    if count == 0:
        return None

    conn = get_connection()
    try:
        query = f"SELECT * FROM network_traffic LIMIT {limit}"
        df = pd.read_sql_query(query, conn)
        if 'id' in df.columns:
            df = df.drop(columns=['id'])
        if 'created_at' in df.columns:
            df = df.drop(columns=['created_at'])
        return df
    finally:
        conn.close()

def save_threat_log(threat_data):
    """Insert dynamic threat log entry into threat_logs table."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO threat_logs 
            (threat_id, timestamp, source_ip, prediction, attack_probability, severity, status, action_taken, requires_human)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat_data.get('threat_id'),
            threat_data.get('timestamp', datetime.now().isoformat()),
            threat_data.get('source', threat_data.get('source_ip', '192.168.1.1')),
            int(threat_data.get('prediction', 0)),
            float(threat_data.get('attack_probability', 0.0)),
            str(threat_data.get('severity', 'LOW')),
            str(threat_data.get('status', 'LOGGED')),
            str(threat_data.get('action_taken', 'Monitored')),
            1 if threat_data.get('requires_human', False) else 0
        ))
        conn.commit()
    except Exception as e:
        print(f"[WARN] Error saving threat log: {e}")
    finally:
        conn.close()

def get_threat_logs(limit=50):
    """Retrieve recent threat log entries from threat_logs table."""
    conn = get_connection()
    try:
        query = f"SELECT * FROM threat_logs ORDER BY timestamp DESC LIMIT {limit}"
        df = pd.read_sql_query(query, conn)
        return df.to_dict(orient='records')
    except Exception:
        return []
    finally:
        conn.close()

def get_database_stats():
    """Return summary statistics of the database for the current data.csv schema."""
    conn = get_connection()
    try:
        traffic_count = get_traffic_count()
        
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM threat_logs")
        threat_count = cursor.fetchone()[0]
        
        attack_distribution = {}
        severity_distribution = {}
        if traffic_count > 0:
            cursor.execute("SELECT attack_type, COUNT(*) FROM network_traffic GROUP BY attack_type")
            for row in cursor.fetchall():
                attack_type = row[0] or 'Normal Traffic'
                attack_distribution[attack_type] = row[1]
                
            cursor.execute("SELECT severity_level, COUNT(*) FROM network_traffic GROUP BY severity_level")
            for row in cursor.fetchall():
                severity = row[0] or 'Unknown'
                severity_distribution[severity] = row[1]

        return {
            'db_path': DB_PATH,
            'network_traffic_rows': traffic_count,
            'threat_logs_count': threat_count,
            'attack_distribution': attack_distribution,
            'severity_distribution': severity_distribution
        }
    except Exception as e:
        return {'error': str(e), 'network_traffic_rows': 0, 'threat_logs_count': 0}
    finally:
        conn.close()

# Auto-initialize database schema when database.py is loaded
init_db()
