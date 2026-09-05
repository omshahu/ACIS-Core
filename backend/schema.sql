-- ACIS-Core SQL Database Schema
-- Table for Network Traffic Data (data.csv)
CREATE TABLE IF NOT EXISTS network_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination_port INTEGER,
    flow_duration REAL,
    total_fwd_packets INTEGER,
    total_length_of_fwd_packets REAL,
    fwd_packet_length_max REAL,
    fwd_packet_length_min REAL,
    fwd_packet_length_mean REAL,
    fwd_packet_length_std REAL,
    bwd_packet_length_max REAL,
    bwd_packet_length_min REAL,
    bwd_packet_length_mean REAL,
    bwd_packet_length_std REAL,
    flow_bytes_s REAL,
    flow_packets_s REAL,
    flow_iat_mean REAL,
    flow_iat_std REAL,
    flow_iat_max REAL,
    flow_iat_min REAL,
    fwd_iat_total REAL,
    fwd_iat_mean REAL,
    fwd_iat_std REAL,
    fwd_iat_max REAL,
    fwd_iat_min REAL,
    bwd_iat_total REAL,
    bwd_iat_mean REAL,
    bwd_iat_std REAL,
    bwd_iat_max REAL,
    bwd_iat_min REAL,
    fwd_header_length INTEGER,
    bwd_header_length INTEGER,
    fwd_packets_s REAL,
    bwd_packets_s REAL,
    min_packet_length REAL,
    max_packet_length REAL,
    packet_length_mean REAL,
    packet_length_std REAL,
    packet_length_variance REAL,
    fin_flag_count INTEGER,
    psh_flag_count INTEGER,
    ack_flag_count INTEGER,
    average_packet_size REAL,
    subflow_fwd_bytes REAL,
    init_win_bytes_forward INTEGER,
    init_win_bytes_backward INTEGER,
    act_data_pkt_fwd INTEGER,
    min_seg_size_forward INTEGER,
    active_mean REAL,
    active_max REAL,
    active_min REAL,
    idle_mean REAL,
    idle_max REAL,
    idle_min REAL,
    attack_type VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Performance Indexes for fast queries and ML sampling
CREATE INDEX IF NOT EXISTS idx_attack_type ON network_traffic(attack_type);
CREATE INDEX IF NOT EXISTS idx_destination_port ON network_traffic(destination_port);

-- Table for Live Threat Detections & SOAR Audits
CREATE TABLE IF NOT EXISTS threat_logs (
    threat_id VARCHAR(50) PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(50),
    prediction INTEGER,
    attack_probability REAL,
    severity VARCHAR(20),
    status VARCHAR(50),
    action_taken TEXT,
    requires_human BOOLEAN
);

CREATE INDEX IF NOT EXISTS idx_threat_severity ON threat_logs(severity);
CREATE INDEX IF NOT EXISTS idx_threat_status ON threat_logs(status);
