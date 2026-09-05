// ACIS-Core REST API Client Module
const BASE_URL = "http://127.0.0.1:5001/api";

async function apiRequest(endpoint, method = 'GET', body = null) {
    try {
        const options = {
            method,
            headers: { 'Content-Type': 'application/json' }
        };
        if (body) {
            options.body = JSON.stringify(body);
        }
        const res = await fetch(`${BASE_URL}${endpoint}`, options);
        return await res.json();
    } catch (err) {
        console.warn(`API call failed for ${endpoint}:`, err);
        return { success: false, error: err.message };
    }
}

// 18 Core REST Endpoints
const API = {
    getHealth: () => apiRequest('/health'),
    getMetrics: () => apiRequest('/metrics'),
    runThreatDetection: (data) => apiRequest('/threat', 'POST', data),
    getThreatLogs: () => apiRequest('/threat/logs'),
    getTwinTopology: () => apiRequest('/twin/topology'),
    simulateTwinAttack: (attackType, targetNode) => apiRequest('/twin/simulate', 'POST', { attack_type: attackType, target_node: targetNode }),
    syncTwinTelemetry: (telemetry) => apiRequest('/twin/sync', 'POST', telemetry),
    getRlPolicy: () => apiRequest('/rl/policy'),
    stepRlAgent: (actionIndex) => apiRequest('/rl/step', 'POST', { action_index: actionIndex }),
    approveSOARThreat: (threatId) => apiRequest('/soar/approve', 'POST', { threat_id: threatId }),
    triggerFlRound: () => apiRequest('/fl/round', 'POST'),
    getFlStatus: () => apiRequest('/fl/status'),
    getBlockchainAudit: () => apiRequest('/blockchain/audit'),
    verifyBlockchainHash: (hash) => apiRequest('/blockchain/verify', 'POST', { model_hash: hash }),
    getThreatIntelIOCs: () => apiRequest('/threat-intel/iocs'),
    benchmarkEdge: (platform) => apiRequest('/edge/benchmark', 'POST', { platform }),
    getDbStats: () => apiRequest('/db/stats')
};