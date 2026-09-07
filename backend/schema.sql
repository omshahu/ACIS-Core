-- ACIS-Core SQL Database Schema
-- Table for Network Traffic Data (data.csv)
CREATE TABLE IF NOT EXISTS network_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip VARCHAR(50),
    destination_ip VARCHAR(50),
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(20),
    packet_length INTEGER,
    packet_type VARCHAR(50),
    traffic_type VARCHAR(50),
    payload_data TEXT,
    malware_indicators VARCHAR(100),
    anomaly_scores REAL,
    alerts_warnings VARCHAR(100),
    attack_type VARCHAR(100),
    attack_signature VARCHAR(100),
    action_taken VARCHAR(50),
    severity_level VARCHAR(50),
    user_information TEXT,
    device_information TEXT,
    network_segment VARCHAR(50),
    geo_location_data TEXT,
    proxy_information TEXT,
    firewall_logs TEXT,
    ids_ips_alerts TEXT,
    log_source VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Performance Indexes for fast queries and ML sampling
CREATE INDEX IF NOT EXISTS idx_attack_type ON network_traffic(attack_type);
CREATE INDEX IF NOT EXISTS idx_severity_level ON network_traffic(severity_level);
CREATE INDEX IF NOT EXISTS idx_destination_port ON network_traffic(destination_port);
CREATE INDEX IF NOT EXISTS idx_source_ip ON network_traffic(source_ip);

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
