import sys
import json
import importlib.metadata

try:
    if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
        getattr(sys.stdout, 'reconfigure')(encoding='utf-8')
except Exception:
    pass
try:
    if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
        getattr(sys.stderr, 'reconfigure')(encoding='utf-8')
except Exception:
    pass

import werkzeug
if not hasattr(werkzeug, '__version__'):
    try:
        setattr(werkzeug, '__version__', importlib.metadata.version('werkzeug'))
    except Exception:
        setattr(werkzeug, '__version__', '3.1.3')

from app import app, analyze_threat, pending_approvals, process_threat

client = app.test_client()

print("="*60)
print("TEST 1: Verify /api/pending-threats has ONLY HIGH and CRITICAL")
print("="*60)
res = client.get('/api/pending-threats')
data = json.loads(res.data)
assert res.status_code == 200 and data['success']
pending = data['pending']
print(f"Total pending threats: {len(pending)}")
severities = set()
for t in pending:
    sev = t['severity']
    severities.add(sev)
    conf = t['threat_data']['details']['confidence']
    prob = t['threat_data']['details']['attack_probability']
    print(f"  Threat [{t['threat_id']}]: {sev:8} | Conf: {conf*100:5.1f}% | Prob: {prob*100:5.1f}%")
    assert conf < 1.0, f"Confidence {conf} must be under 1.0 (never 100%)"
    assert conf <= 0.999, f"Confidence {conf} must be <= 0.999"
    assert sev in ['HIGH', 'CRITICAL'], f"Pending threat {t['threat_id']} has unexpected severity {sev}!"

print("Unique severities present in pending approvals:", severities)
assert {'HIGH', 'CRITICAL'}.issubset(severities), "HIGH and CRITICAL must be present in pending approvals!"
assert 'LOW' not in severities, "LOW severity threats must NOT be in pending approvals (auto-resolved)!"
assert 'MEDIUM' not in severities, "MEDIUM severity threats must NOT be in pending approvals (auto-resolved)!"

print("\n" + "="*60)
print("TEST 2: Verify Auto-Remediation of LOW and MEDIUM Threats")
print("="*60)
auto_res = client.get('/api/auto-remediation/log')
auto_data = json.loads(auto_res.data)
assert auto_res.status_code == 200 and auto_data['success']
auto_logs = auto_data['logs']
auto_sevs = {log['severity'] for log in auto_logs}
print(f"Total auto-remediated threats logged: {len(auto_logs)}")
for log in auto_logs:
    print(f"  Auto-Fix [{log['threat_id']}]: {log['severity']:8} -> {log['action']}")
assert 'LOW' in auto_sevs or 'MEDIUM' in auto_sevs, "LOW and MEDIUM threats must be present in auto_remediation_log!"

print("\n" + "="*60)
print("TEST 3: Verify Alerts Count is Strictly Less Than Total Threats")
print("="*60)
mon_res = client.get('/api/monitoring/status')
mon_data = json.loads(mon_res.data)
assert mon_res.status_code == 200
threats_detected = mon_data['threats_detected']
alerts_count = mon_data['alerts']
print(f"Threats detected: {threats_detected} | Alerts: {alerts_count} | Auto-fixes: {mon_data['auto_fixes']}")
assert alerts_count < threats_detected, f"Alert count ({alerts_count}) must be less than threats ({threats_detected})!"

print("\n" + "="*60)
print("TEST 4: Verify analyze_threat Thresholds & Modes")
print("="*60)
modes = ['low_attack', 'medium_attack', 'severe_attack']
for m in modes:
    res = analyze_threat(None, mode=m)
    prob = res['attack_probability']
    sev = res['severity']
    conf = res['confidence']
    print(f"Mode '{m:13}': Severity={sev:8} | Prob={prob:5.3f} | Conf={conf:5.3f}")
    assert conf <= 0.999, f"Confidence {conf} must be <= 0.999"
    if m == 'low_attack':
        assert sev == 'LOW' and prob < 0.40, f"LOW severity expected < 0.40, got {prob}"
    elif m == 'medium_attack':
        assert sev == 'MEDIUM' and 0.40 <= prob <= 0.70, f"MEDIUM severity expected 0.40-0.70, got {prob}"
    elif m == 'severe_attack':
        assert sev == 'CRITICAL' and prob > 0.90, f"CRITICAL severity expected > 0.90, got {prob}"

print("\n" + "="*60)
print("TEST 5: Test Approval & Rejection via /api/remediate")
print("="*60)
first_id = pending[0]['threat_id']
approve_res = client.post('/api/remediate', json={'threat_id': first_id, 'action': 'approve'})
approve_data = json.loads(approve_res.data)
assert approve_res.status_code == 200 and approve_data['success']
print(f"Approved threat {first_id}: status={approve_data['status']}")

second_id = pending[1]['threat_id']
reject_res = client.post('/api/remediate', json={'threat_id': second_id, 'action': 'reject'})
reject_data = json.loads(reject_res.data)
assert reject_res.status_code == 200 and reject_data['success']
print(f"Rejected threat {second_id}: status={reject_data['status']}")

res_after = client.get('/api/pending-threats')
data_after = json.loads(res_after.data)
print(f"Remaining pending threats: {len(data_after['pending'])} (was {len(pending)})")
assert len(data_after['pending']) == len(pending) - 2

print("\n[ALL SEVERITY & APPROVAL TESTS PASSED SUCCESSFULLY!]")
