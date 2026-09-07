/**
 * ACIS-Core — Digital Twin Component Layer
 * Decoupled observer & real-time SSE visualizer, topology engine, playback controller, and sandbox simulator.
 */

class DigitalTwinUI {
    constructor() {
        this.apiBase = window.location.origin.includes('5001') ? '/api' : 'http://127.0.0.1:5001/api';
        this.sseSource = null;
        this.isLive = true;
        this.historyBuffer = [];
        this.currentFrameIndex = -1;
        this.liveState = null;
        this.canvas = null;
        this.ctx = null;
        this.animationFrameId = null;
        this.selectedNodeId = 'core-ai-engine';
        this.packetParticles = [];

        this.nodeCoords = {
            'waf-gateway': { x: 120, y: 180 },
            'telemetry-broker': { x: 280, y: 80 },
            'core-ai-engine': { x: 300, y: 220 },
            'trust-ledger-db': { x: 480, y: 90 },
            'sandbox-env': { x: 480, y: 230 }
        };

        this.connections = [
            ['waf-gateway', 'telemetry-broker'],
            ['telemetry-broker', 'core-ai-engine'],
            ['core-ai-engine', 'trust-ledger-db'],
            ['core-ai-engine', 'sandbox-env'],
            ['waf-gateway', 'core-ai-engine']
        ];
    }

    init() {
        this.canvas = document.getElementById('twinTopologyCanvas');
        if (this.canvas) {
            this.ctx = this.canvas.getContext('2d');
            this.resizeCanvas();
            window.addEventListener('resize', () => this.resizeCanvas());
            this.canvas.addEventListener('click', (e) => this.handleCanvasClick(e));
            this.initParticles();
            this.startCanvasLoop();
        }

        this.connectSSE();
        this.loadHistory();
    }

    resizeCanvas() {
        if (!this.canvas) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.canvas.width = rect.width || 600;
        this.canvas.height = 300;
    }

    initParticles() {
        this.packetParticles = [];
        for (let i = 0; i < 12; i++) {
            const conn = this.connections[Math.floor(Math.random() * this.connections.length)];
            this.packetParticles.push({
                from: conn[0],
                to: conn[1],
                progress: Math.random(),
                speed: 0.005 + Math.random() * 0.01
            });
        }
    }

    // ---------- REAL-TIME SSE STREAMING ----------
    connectSSE() {
        if (this.sseSource) {
            this.sseSource.close();
        }

        const statusEl = document.getElementById('twinStreamStatus');
        if (statusEl) statusEl.innerHTML = '<span class="status-dot running"></span> Connecting SSE...';

        try {
            this.sseSource = new EventSource(`${this.apiBase}/twin/stream`);

            this.sseSource.onopen = () => {
                if (statusEl) statusEl.innerHTML = '<span class="status-dot success"></span> Live SSE Streaming';
            };

            this.sseSource.onmessage = (event) => {
                if (!this.isLive) return;
                try {
                    const data = JSON.parse(event.data);
                    this.updateState(data);
                } catch (e) {
                    console.error('SSE parse error', e);
                }
            };

            this.sseSource.onerror = () => {
                if (statusEl) statusEl.innerHTML = '<span class="status-dot warning"></span> SSE Reconnecting (Polling active)';
                this.fallbackPolling();
            };
        } catch (e) {
            this.fallbackPolling();
        }
    }

    async fallbackPolling() {
        try {
            const res = await fetch(`${this.apiBase}/twin/state`);
            const data = await res.json();
            if (data.success && this.isLive) {
                this.updateState(data.twin_state);
            }
        } catch (e) { /* ignore */ }
    }

    updateState(stateData) {
        if (!stateData) return;
        this.liveState = stateData;
        const metrics = stateData.metrics || stateData;
        
        // Push snapshot to history buffer for timeline playback
        const snapshot = {
            timestamp: new Date().toLocaleTimeString(),
            metrics: dictCopy(metrics),
            nodes: dictCopy(stateData.nodes || {})
        };
        this.historyBuffer.push(snapshot);
        if (this.historyBuffer.length > 50) this.historyBuffer.shift();

        this.renderTelemetry(metrics);
        this.renderNodeDetails();
        this.updateTimelineUI();
    }

    // ---------- CANVAS TOPOLOGY RENDER LOOP ----------
    startCanvasLoop() {
        const render = () => {
            this.drawTopology();
            this.animationFrameId = requestAnimationFrame(render);
        };
        render();
    }

    drawTopology() {
        if (!this.ctx || !this.canvas) return;
        const ctx = this.ctx;
        const w = this.canvas.width;
        const h = this.canvas.height;

        ctx.clearRect(0, 0, w, h);

        // Responsive scaling factor
        const scaleX = w / 600;
        const scaleY = h / 300;

        // Draw connection lines
        ctx.lineWidth = 2;
        this.connections.forEach(([fromId, toId]) => {
            const p1 = this.nodeCoords[fromId];
            const p2 = this.nodeCoords[toId];
            if (!p1 || !p2) return;

            const x1 = p1.x * scaleX;
            const y1 = p1.y * scaleY;
            const x2 = p2.x * scaleX;
            const y2 = p2.y * scaleY;

            ctx.strokeStyle = 'rgba(100, 116, 139, 0.25)';
            ctx.beginPath();
            ctx.moveTo(x1, y1);
            ctx.lineTo(x2, y2);
            ctx.stroke();
        });

        // Draw animated data packets
        this.packetParticles.forEach(p => {
            p.progress += p.speed;
            if (p.progress >= 1.0) {
                p.progress = 0;
                const nextConn = this.connections[Math.floor(Math.random() * this.connections.length)];
                p.from = nextConn[0];
                p.to = nextConn[1];
            }

            const p1 = this.nodeCoords[p.from];
            const p2 = this.nodeCoords[p.to];
            if (p1 && p2) {
                const px = (p1.x + (p2.x - p1.x) * p.progress) * scaleX;
                const py = (p1.y + (p2.y - p1.y) * p.progress) * scaleY;

                ctx.fillStyle = '#60A5FA';
                ctx.beginPath();
                ctx.arc(px, py, 3.5, 0, Math.PI * 2);
                ctx.fill();
            }
        });

        // Draw nodes with Solid State Health Dots (no spinners)
        const nodes = this.liveState?.nodes || {
            'waf-gateway': { name: 'WAF Gateway', health: 0.97, status: 'operational' },
            'telemetry-broker': { name: 'Telemetry Broker', health: 0.96, status: 'operational' },
            'core-ai-engine': { name: 'ACIS AI Core', health: 0.98, status: 'operational' },
            'trust-ledger-db': { name: 'Trust Ledger DB', health: 0.99, status: 'operational' },
            'sandbox-env': { name: 'Sandbox Env', health: 0.98, status: 'operational' }
        };

        Object.keys(this.nodeCoords).forEach(nId => {
            const coords = this.nodeCoords[nId];
            const nx = coords.x * scaleX;
            const ny = coords.y * scaleY;
            const nodeData = nodes[nId] || { name: nId, status: 'operational', health: 0.98 };

            const isSelected = this.selectedNodeId === nId;
            const healthScore = (nodeData.health !== undefined) ? (nodeData.health > 1 ? nodeData.health : nodeData.health * 100) : 98;

            // Solid State Health Dot rule:
            // Green if >95%, Yellow if 80-95%, Red if <80%
            let healthColor = '#10B981'; // Green
            if (healthScore < 80) {
                healthColor = '#EF4444'; // Red
            } else if (healthScore <= 95) {
                healthColor = '#F59E0B'; // Yellow
            }

            // Node Outer Disk (Clean solid style, no spinning animation)
            ctx.fillStyle = isSelected ? 'rgba(59, 130, 246, 0.25)' : 'rgba(30, 41, 59, 0.9)';
            ctx.strokeStyle = isSelected ? '#3B82F6' : '#475569';
            ctx.lineWidth = isSelected ? 2.5 : 1.5;
            ctx.beginPath();
            ctx.arc(nx, ny, 20, 0, Math.PI * 2);
            ctx.fill();
            ctx.stroke();

            // Inner Core
            ctx.fillStyle = '#1E293B';
            ctx.beginPath();
            ctx.arc(nx, ny, 14, 0, Math.PI * 2);
            ctx.fill();

            // Solid State Indicator Dot (Top Right)
            ctx.fillStyle = healthColor;
            ctx.beginPath();
            ctx.arc(nx + 13, ny - 13, 4.5, 0, Math.PI * 2);
            ctx.fill();

            // Node label
            ctx.fillStyle = 'var(--text-primary)';
            ctx.font = '600 11px Inter, sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(nodeData.name || nId, nx, ny + 34);
        });
    }

    handleCanvasClick(e) {
        if (!this.canvas) return;
        const rect = this.canvas.getBoundingClientRect();
        const clickX = e.clientX - rect.left;
        const clickY = e.clientY - rect.top;

        const scaleX = this.canvas.width / 600;
        const scaleY = this.canvas.height / 300;

        Object.keys(this.nodeCoords).forEach(nId => {
            const coords = this.nodeCoords[nId];
            const nx = coords.x * scaleX;
            const ny = coords.y * scaleY;

            const dist = Math.hypot(clickX - nx, clickY - ny);
            if (dist <= 25) {
                this.selectedNodeId = nId;
                this.renderNodeDetails();
            }
        });
    }

    // ---------- UI RENDERING ----------
    renderTelemetry(metrics) {
        if (!metrics) return;

        setElemText('twinCpuText', `${metrics.cpu_usage || 0}%`);
        setElemWidth('twinCpuBar', `${metrics.cpu_usage || 0}%`);

        setElemText('twinMemoryText', `${metrics.memory_usage || 0}%`);
        setElemWidth('twinMemoryBar', `${metrics.memory_usage || 0}%`);

        setElemText('twinDiskText', `${metrics.disk_io || 0}%`);
        setElemText('twinLatencyText', `${metrics.network_latency || 0} ms`);
        setElemText('twinConnText', metrics.active_connections || 0);

        const risk = metrics.risk_score || 10;
        const riskEl = document.getElementById('twinRiskScoreBadge');
        if (riskEl) {
            riskEl.textContent = `Risk Index: ${risk}/100`;
            riskEl.style.color = risk > 60 ? 'var(--danger)' : risk > 35 ? 'var(--warning)' : 'var(--success)';
            riskEl.style.background = risk > 60 ? 'var(--danger-bg)' : risk > 35 ? 'var(--warning-bg)' : 'var(--success-bg)';
        }

        const health = Math.round((metrics.network_health || 0.95) * 100);
        setElemText('twinHealthText', `${health}%`);
    }

    renderNodeDetails() {
        const container = document.getElementById('twinNodeDetailCard');
        if (!container) return;

        const nodes = this.liveState?.nodes || {};
        const node = nodes[this.selectedNodeId] || { id: this.selectedNodeId, name: this.selectedNodeId, status: 'operational', load: 30, health: 0.98 };

        container.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <strong style="font-size:0.95rem; color:var(--text-primary);"><i class="fas fa-server"></i> ${node.name}</strong>
                <span class="status-tag ${node.status === 'operational' ? 'verified' : 'pending'}">${node.status.toUpperCase()}</span>
            </div>
            <div style="font-size:0.8rem; color:var(--text-secondary); display:grid; grid-template-columns:1fr 1fr; gap:6px;">
                <div><span class="key">Node ID:</span> <span class="value">${node.id}</span></div>
                <div><span class="key">Type:</span> <span class="value">${node.type || 'service'}</span></div>
                <div><span class="key">Load:</span> <span class="value">${node.load || 30}%</span></div>
                <div><span class="key">Health Score:</span> <span class="value">${Math.round((node.health || 0.98) * 100)}%</span></div>
            </div>
        `;
    }

    // ---------- PLAYBACK TIMELINE ----------
    updateTimelineUI() {
        const slider = document.getElementById('twinPlaybackSlider');
        if (!slider) return;

        slider.max = Math.max(0, this.historyBuffer.length - 1);
        if (this.isLive) {
            slider.value = slider.max;
            setElemText('twinPlaybackTime', 'Live Stream (Real-Time)');
        }
    }

    onSliderChange(val) {
        const index = parseInt(val, 10);
        if (index === this.historyBuffer.length - 1) {
            this.isLive = true;
            setElemText('twinPlaybackTime', 'Live Stream (Real-Time)');
        } else {
            this.isLive = false;
            this.currentFrameIndex = index;
            const snapshot = this.historyBuffer[index];
            if (snapshot) {
                setElemText('twinPlaybackTime', `Playback Snapshot: ${snapshot.timestamp}`);
                this.renderTelemetry(snapshot.metrics);
            }
        }
    }

    toggleLivePlayback() {
        const btn = document.getElementById('twinLiveToggleBtn');
        this.isLive = !this.isLive;
        if (this.isLive) {
            if (btn) btn.innerHTML = '<i class="fas fa-pause"></i> Pause';
            this.connectSSE();
        } else {
            if (btn) btn.innerHTML = '<i class="fas fa-play"></i> Resume Live';
            setElemText('twinStreamStatus', 'Paused Playback Mode');
        }
    }

    async loadHistory() {
        try {
            const res = await fetch(`${this.apiBase}/twin/history?limit=30`);
            const data = await res.json();
            if (data.success && data.history) {
                data.history.forEach(item => {
                    this.historyBuffer.push({
                        timestamp: item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : 'Past',
                        metrics: item,
                        nodes: this.liveState?.nodes || {}
                    });
                });
                this.updateTimelineUI();
            }
        } catch (e) { /* ignore */ }
    }

    // ---------- SANDBOX WHAT-IF SIMULATOR ----------
    async runWhatIfSimulation() {
        const scenario = document.getElementById('twinWhatIfScenario')?.value || 'ddos_attack';
        const loadFactor = parseFloat(document.getElementById('twinWhatIfLoadFactor')?.value || '1.5');
        const attackIntensity = parseFloat(document.getElementById('twinWhatIfIntensity')?.value || '0.7');
        const isolateWaf = document.getElementById('twinIsolateWafCheck')?.checked || false;

        const isolated_nodes = [];
        if (isolateWaf) isolated_nodes.push('waf-gateway');

        const resultsContainer = document.getElementById('twinWhatIfResults');
        if (resultsContainer) {
            resultsContainer.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Running Sandbox Simulation...</div>';
        }

        try {
            const res = await fetch(`${this.apiBase}/twin/simulate-what-if`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scenario: scenario,
                    params: {
                        load_factor: loadFactor,
                        attack_intensity: attackIntensity,
                        isolated_nodes: isolated_nodes
                    }
                })
            });

            const data = await res.json();
            if (data.success && data.simulation) {
                const sim = data.simulation;
                const m = sim.sandbox_metrics;
                const comp = sim.live_comparison;

                let html = `
                    <div style="background:var(--bg-input); padding:14px; border-radius:8px; border-left:4px solid var(--accent); margin-top:10px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                            <strong style="color:var(--text-primary); font-size:0.9rem;">
                                <i class="fas fa-flask"></i> Sandbox Result: ${sim.scenario.toUpperCase()}
                            </strong>
                            <span class="status-tag ${m.predicted_threat_level === 'CRITICAL' || m.predicted_threat_level === 'HIGH' ? 'pending' : 'verified'}">
                                Predicted: ${m.predicted_threat_level}
                            </span>
                        </div>
                        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; font-size:0.8rem; margin-bottom:10px;">
                            <div><span class="key">Attack Probability:</span> <span class="value">${(m.attack_probability * 100).toFixed(1)}%</span></div>
                            <div><span class="key">Simulated Risk Score:</span> <span class="value">${m.risk_score}/100</span></div>
                            <div><span class="key">Simulated CPU Load:</span> <span class="value">${m.simulated_cpu}%</span></div>
                            <div><span class="key">Simulated Latency:</span> <span class="value">${m.simulated_latency} ms</span></div>
                        </div>

                        <div style="padding:8px 12px; background:var(--panel-bg); border-radius:6px; font-size:0.75rem; border:1px solid var(--border-color);">
                            <strong>Impact vs Production Live:</strong> Risk Score Delta: 
                            <span style="color:${comp.risk_delta > 0 ? 'var(--danger)' : 'var(--success)'}; font-weight:700;">
                                ${comp.risk_delta > 0 ? '+' : ''}${comp.risk_delta} pts
                            </span> 
                            (Production state strictly unmutated ✅)
                        </div>
                    </div>
                `;
                if (resultsContainer) resultsContainer.innerHTML = html;
            } else {
                if (resultsContainer) resultsContainer.innerHTML = `<div class="result-error">Sandbox Error: ${data.error || 'Unknown'}</div>`;
            }
        } catch (e) {
            if (resultsContainer) resultsContainer.innerHTML = `<div class="result-error">Network Error: ${e.message}</div>`;
        }
    }
}

// Helpers
function setElemText(id, txt) {
    const el = document.getElementById(id);
    if (el) el.textContent = txt;
}
function setElemWidth(id, w) {
    const el = document.getElementById(id);
    if (el) el.style.width = w;
}
function dictCopy(obj) {
    return JSON.parse(JSON.stringify(obj || {}));
}

// Global instance
window.digitalTwinUI = new DigitalTwinUI();
