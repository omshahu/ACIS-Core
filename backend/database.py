import sqlite3
import os
import pandas as pd
from datetime import datetime

# Path to SQLite database file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'acis_database.db')
SCHEMA_PATH = os.path.join(BASE_DIR, 'schema.sql')

# Header mapping from CSV names to SQL column names
COLUMN_MAPPING = {
    'Destination Port': 'destination_port',
    'Flow Duration': 'flow_duration',
    'Total Fwd Packets': 'total_fwd_packets',
    'Total Length of Fwd Packets': 'total_length_of_fwd_packets',
    'Fwd Packet Length Max': 'fwd_packet_length_max',
    'Fwd Packet Length Min': 'fwd_packet_length_min',
    'Fwd Packet Length Mean': 'fwd_packet_length_mean',
    'Fwd Packet Length Std': 'fwd_packet_length_std',
    'Bwd Packet Length Max': 'bwd_packet_length_max',
    'Bwd Packet Length Min': 'bwd_packet_length_min',
    'Bwd Packet Length Mean': 'bwd_packet_length_mean',
    'Bwd Packet Length Std': 'bwd_packet_length_std',
    'Flow Bytes/s': 'flow_bytes_s',
    'Flow Packets/s': 'flow_packets_s',
    'Flow IAT Mean': 'flow_iat_mean',
    'Flow IAT Std': 'flow_iat_std',
    'Flow IAT Max': 'flow_iat_max',
    'Flow IAT Min': 'flow_iat_min',
    'Fwd IAT Total': 'fwd_iat_total',
    'Fwd IAT Mean': 'fwd_iat_mean',
    'Fwd IAT Std': 'fwd_iat_std',
    'Fwd IAT Max': 'fwd_iat_max',
    'Fwd IAT Min': 'fwd_iat_min',
    'Bwd IAT Total': 'bwd_iat_total',
    'Bwd IAT Mean': 'bwd_iat_mean',
    'Bwd IAT Std': 'bwd_iat_std',
    'Bwd IAT Max': 'bwd_iat_max',
    'Bwd IAT Min': 'bwd_iat_min',
    'Fwd Header Length': 'fwd_header_length',
    'Bwd Header Length': 'bwd_header_length',
    'Fwd Packets/s': 'fwd_packets_s',
    'Bwd Packets/s': 'bwd_packets_s',
    'Min Packet Length': 'min_packet_length',
    'Max Packet Length': 'max_packet_length',
    'Packet Length Mean': 'packet_length_mean',
    'Packet Length Std': 'packet_length_std',
    'Packet Length Variance': 'packet_length_variance',
    'FIN Flag Count': 'fin_flag_count',
    'PSH Flag Count': 'psh_flag_count',
    'ACK Flag Count': 'ack_flag_count',
    'Average Packet Size': 'average_packet_size',
    'Subflow Fwd Bytes': 'subflow_fwd_bytes',
    'Init_Win_bytes_forward': 'init_win_bytes_forward',
    'Init_Win_bytes_backward': 'init_win_bytes_backward',
    'act_data_pkt_fwd': 'act_data_pkt_fwd',
    'min_seg_size_forward': 'min_seg_size_forward',
    'Active Mean': 'active_mean',
    'Active Max': 'active_max',
    'Active Min': 'active_min',
    'Idle Mean': 'idle_mean',
    'Idle Max': 'idle_max',
    'Idle Min': 'idle_min',
    'Attack Type': 'attack_type',
    'Label': 'attack_type',
    'label': 'attack_type'
}

def get_connection():
    """Establish and return SQLite database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize SQL database using schema.sql DDL."""
    if os.path.exists(SCHEMA_PATH):
        with open(SCHEMA_PATH, 'r') as f:
            schema_sql = f.read()
        conn = get_connection()
        try:
            conn.executescript(schema_sql)
            conn.commit()
            print(f"✅ SQL Database initialized successfully at: {DB_PATH}")
        finally:
            conn.close()
    else:
        print(f"⚠️ Warning: schema.sql not found at {SCHEMA_PATH}")

def normalize_column_name(col):
    """Normalize CSV column names to SQL column names."""
    col_clean = col.strip()
    if col_clean in COLUMN_MAPPING:
        return COLUMN_MAPPING[col_clean]
    # Fallback cleaning: lowercase, replace non-alphanumeric with underscore
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
    except Exception as e:
        return 0
    finally:
        conn.close()

def save_traffic_chunk(df, if_exists='append'):
    """Save pandas DataFrame chunk into network_traffic table."""
    # Rename columns using COLUMN_MAPPING
    df_sql = df.copy()
    new_cols = {}
    for col in df_sql.columns:
        new_cols[col] = normalize_column_name(col)
    df_sql = df_sql.rename(columns=new_cols)

    conn = get_connection()
    try:
        # Get actual SQL table column names to filter out incompatible columns
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(network_traffic)")
        table_cols = set(row[1] for row in cursor.fetchall())
        
        valid_cols = [c for c in df_sql.columns if c in table_cols]
        if valid_cols:
            df_sql = df_sql[valid_cols]
            df_sql.to_sql('network_traffic', conn, if_exists=if_exists, index=False, chunksize=5000)
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
            threat_data.get('prediction', 0),
            threat_data.get('attack_probability', 0.0),
            threat_data.get('severity', 'LOW'),
            threat_data.get('status', 'LOGGED'),
            threat_data.get('action_taken', 'Monitored'),
            1 if threat_data.get('requires_human', False) else 0
        ))
        conn.commit()
    except Exception as e:
        print(f"❌ Error saving threat log: {e}")
    finally:
        conn.close()

def get_threat_logs(limit=50):
    """Retrieve recent threat log entries from threat_logs table."""
    conn = get_connection()
    try:
        query = f"SELECT * FROM threat_logs ORDER BY timestamp DESC LIMIT {limit}"
        df = pd.read_sql_query(query, conn)
        return df.to_dict(orient='records')
    except Exception as e:
        return []
    finally:
        conn.close()

def get_database_stats():
    """Return summary statistics of the database."""
    conn = get_connection()
    try:
        traffic_count = get_traffic_count()
        
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM threat_logs")
        threat_count = cursor.fetchone()[0]
        
        attack_distribution = {}
        if traffic_count > 0:
            cursor.execute("SELECT attack_type, COUNT(*) FROM network_traffic GROUP BY attack_type")
            for row in cursor.fetchall():
                attack_type = row[0] or 'Normal Traffic'
                attack_distribution[attack_type] = row[1]
                
        return {
            'db_path': DB_PATH,
            'network_traffic_rows': traffic_count,
            'threat_logs_count': threat_count,
            'attack_distribution': attack_distribution
        }
    except Exception as e:
        return {'error': str(e), 'network_traffic_rows': 0, 'threat_logs_count': 0}
    finally:
        conn.close()

# Auto-initialize database schema when database.py is loaded
init_db()
