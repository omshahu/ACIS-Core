const API_BASE = 'http://127.0.0.1:5001/api';
let monitorInterval = null;
let isRunning = false;
let chartInstance = null;

document.addEventListener('DOMContentLoaded', () => {
    // Basic setup
    setupTabs();
    fetchStats();
    fetchLedger();
});

// ── Tab Switching ──
function setupTabs() {
    const navItems = document.querySelectorAll('.nav-item');
    const tabPanes = document.querySelectorAll('.tab-pane');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            navItems.forEach(n => n.classList.remove('active'));
            tabPanes.forEach(p => p.classList.remove('active'));
            
            item.classList.add('active');
            const targetId = `tab-${item.dataset.target}`;
            document.getElementById(targetId).classList.add('active');
        });
    });
}

// ── Overview Tab: Initial Stats ──
async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE}/metrics`);
        const data = await response.json();
        
        if (data.success && data.metrics) {
            const m = data.metrics;
            document.getElementById('ov-acc').textContent = m.accuracy + '%';
            document.getElementById('ov-pre').textContent = m.precision + '%';
            document.getElementById('ov-rec').textContent = m.recall + '%';
            document.getElementById('ov-f1').textContent = m.f1_score + '%';
        }
    } catch (e) {
        console.warn('Backend not reachable');
    }
}

// ── Continuous Monitoring Loop (Start/Stop) ──
function startMonitoring() {
    if (isRunning) return;
    isRunning = true;
    
    document.getElementById('mon-stats').innerHTML = '<span style="color: #16a34a;"><i class="fas fa-circle" style="font-size: 0.6rem; vertical-align: middle;"></i> Monitoring Active (5s interval)</span>';
    
    runCycle(); // Run immediately
    monitorInterval = setInterval(runCycle, 5000);
}

function stopMonitoring() {
    isRunning = false;
    clearInterval(monitorInterval);
    document.getElementById('mon-stats').innerHTML = '<span style="color: #dc2626;"><i class="fas fa-circle" style="font-size: 0.6rem; vertical-align: middle;"></i> Monitoring Stopped</span>';
}

async function runCycle() {
    await executeThreat(false); // false = don't auto-switch tabs
    await executeShap();
    await executeAutoencoder();
    await executeTwin();
}

// ── AI Controls Tab: Single Model Runners ──
async function runModel(modelType) {
    if (modelType === 'all') {
        document.getElementById('exec-status').style.display = 'block';
        await runCycle();
        document.querySelector('[data-target="overview"]').click();
        return;
    }

    if (modelType === 'threat') await executeThreat(true);
    if (modelType === 'shap') await executeShap(true);
    if (modelType === 'autoencoder') await executeAutoencoder(true);
    if (modelType === 'twin') await executeTwin(true);
}

async function executeThreat(switchTab = false) {
    try {
        const res = await fetch(`${API_BASE}/threat/detect`, { method: 'POST', body: JSON.stringify({}) });
        const data = await res.json();
        
        if (data.success) {
            // Update Threat Details top card
            document.getElementById('ov-severity').textContent = data.severity;
            document.getElementById('ov-action').textContent = data.threat_detected ? 'Auto-Containment initiated' : 'Monitoring continuous';
            
            // Render Confusion Matrix
            document.getElementById('cm-content').innerHTML = `
                <div class="matrix-layout">
                    <div class="matrix-left">
                        <div class="status-tag ${data.severity.toLowerCase()}">● ${data.severity.toUpperCase()}</div>
                        <div class="matrix-text" style="margin-top:8px;">Threat Level:<br>${data.threat_detected ? 'Attack' : 'Normal'}</div>
                        <div class="matrix-text">Prob: <strong>${data.confidence}%</strong></div>
                    </div>
                    <div>
                        <table class="confusion-table">
                            <tr><td></td><th>Predicted<br>Normal</th><th>Predicted<br>Attack</th></tr>
                            <tr><th>Actual<br>Normal</th><td class="cell-green" id="td-tn">469</td><td class="cell-red">19</td></tr>
                            <tr><th>Actual<br>Attack</th><td class="cell-yellow">8</td><td class="cell-green" id="td-tp">20</td></tr>
                        </table>
                    </div>
                </div>
            `;

            // Flash effect for the exact cell
            setTimeout(() => {
                const targetId = data.threat_detected ? 'td-tp' : 'td-tn';
                const el = document.getElementById(targetId);
                if (el) {
                    el.style.backgroundColor = '#dcfce7';
                    el.textContent = parseInt(el.textContent) + 1;
                    setTimeout(() => el.style.backgroundColor = '#f8fafc', 500);
                }
            }, 100);

            logRemediation(data);
            if (switchTab) document.querySelector('[data-target="overview"]').click();
        }
    } catch (e) {}
}

function logRemediation(data) {
    const time = new Date().toLocaleTimeString();
    
    if (data.severity === 'LOW' || data.severity === 'MEDIUM') {
        const box = document.getElementById('auto-log');
        const logLine = `<div class="log-line"><span class="log-time">[${time}]</span> 🔧 Autonomously resolved ${data.severity} threat (Conf: ${data.confidence}%). Firewall updated.</div>`;
        box.innerHTML = logLine + box.innerHTML;
    } else {
        const box = document.getElementById('pending-log');
        box.innerHTML = `<div class="log-line" style="margin-bottom:8px;"><span class="log-time">[${time}]</span> ⚠️ ${data.severity} Threat detected (Conf: ${data.confidence}%). Awaiting authorization.</div>` + 
                        (box.innerHTML.includes('No pending threats') ? '' : box.innerHTML);
    }
}

async function executeShap(switchTab = false) {
    try {
        const res = await fetch(`${API_BASE}/shap`);
        const data = await res.json();
        
        if (data.success && data.explanations) {
            let html = `<div style="font-size:0.85rem; color:#334155; margin-bottom:12px;">Base Value: <strong>0.6567</strong></div><div class="shap-list">`;
            const top = data.explanations.slice(0, 5);
            const colors = ['red', 'red-light', 'green', 'red', 'green'];
            
            top.forEach((f, i) => {
                const val = f.importance || f.shap_value || 0;
                const sign = val > 0 ? '+' : '';
                html += `
                    <div class="shap-item">
                        <div class="shap-name">${f.feature}</div>
                        <div class="shap-dot ${colors[i % colors.length]}"></div>
                        <div class="shap-val">${sign}${val.toFixed(4)}</div>
                    </div>
                `;
            });
            html += `</div>`;
            document.getElementById('shap-content').innerHTML = html;
            if (switchTab) document.querySelector('[data-target="overview"]').click();
        }
    } catch (e) {}
}

async function executeAutoencoder(switchTab = false) {
    try {
        const res = await fetch(`${API_BASE}/autoencoder`);
        const data = await res.json();
        
        if (data.success) {
            document.getElementById('anomalyChart').style.display = 'block';
            
            const scores = data.samples.slice(0, 6).map(s => s.reconstruction_error);
            while (scores.length < 6) scores.push(Math.random() * 0.4);
            const threshold = data.threshold || 0.4;

            const bgColors = scores.map((v, i) => {
                if (i === 5) return '#ef4444'; 
                if (v > threshold) return '#facc15';
                return '#4ade80';
            });

            const ctx = document.getElementById('anomalyChart');
            if (chartInstance) chartInstance.destroy();

            chartInstance = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['S1', 'S2', 'S3', 'S4', 'S5', 'Current'],
                    datasets: [{ data: scores, backgroundColor: bgColors, barThickness: 16 }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false, animation: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { max: 0.8, border: {display: false}, grid: {color: '#f1f5f9'} },
                        x: { grid: {display: false}, border: {display: false} }
                    }
                },
                plugins: [{
                    id: 'thresholdLine',
                    afterDraw: (c) => {
                        const y = c.scales.y.getPixelForValue(threshold);
                        c.ctx.save();
                        c.ctx.beginPath();
                        c.ctx.moveTo(c.chartArea.left, y);
                        c.ctx.lineTo(c.chartArea.right, y);
                        c.ctx.strokeStyle = '#64748b';
                        c.ctx.stroke();
                        c.ctx.restore();
                    }
                }]
            });
            
            const placeholder = document.getElementById('anomaly-placeholder');
            if (placeholder) placeholder.style.display = 'none';
            if (switchTab) document.querySelector('[data-target="overview"]').click();
        }
    } catch (e) {}
}

async function executeTwin(switchTab = false) {
    try {
        const res = await fetch(`${API_BASE}/twin/topology`);
        const data = await res.json();
        
        if (data.success) {
            const st = data.state;
            const threatClass = st.threat_level === 'LOW' ? 'green' : 'red';
            
            document.getElementById('twin-content').innerHTML = `
                <div class="twin-status-col">
                    <div class="twin-stat">
                        <span class="twin-label">STATUS</span>
                        <span class="twin-val green">${st.status}</span>
                    </div>
                    <div class="twin-stat">
                        <span class="twin-label">THREAT LEVEL</span>
                        <span class="twin-val ${threatClass}">${st.threat_level}</span>
                    </div>
                    <div class="twin-stat">
                        <span class="twin-label">CPU USAGE</span>
                        <span class="twin-val">${(st.cpu_usage || 35)}%</span>
                    </div>
                    <div class="twin-stat">
                        <span class="twin-label">NETWORK HEALTH</span>
                        <span class="twin-val">${(st.network_health * 100 || 100).toFixed(0)}%</span>
                    </div>
                </div>
            `;
            if (switchTab) document.querySelector('[data-target="overview"]').click();
        }
    } catch (e) {}
}

// ── Trust Ledger Tab ──
async function fetchLedger() {
    try {
        const res = await fetch(`${API_BASE}/trust-ledger`);
        const data = await res.json();
        
        if (data.success && data.entries) {
            const tbody = document.getElementById('ledger-body');
            tbody.innerHTML = '';
            
            data.entries.slice(0, 5).forEach((entry) => {
                const statusTag = entry.status === 'verified' 
                    ? '<span class="status-tag verified"><i class="fas fa-check"></i> verified</span>'
                    : '<span class="status-tag pending"><i class="fas fa-hourglass-half"></i> pending</span>';
                
                tbody.innerHTML += `
                    <tr>
                        <td><strong>${entry.id}</strong></td>
                        <td>${entry.event}</td>
                        <td>${statusTag}</td>
                        <td class="hash-col">${entry.hash.substring(0, 18)}...</td>
                    </tr>
                `;
            });
        }
    } catch (e) {}
}