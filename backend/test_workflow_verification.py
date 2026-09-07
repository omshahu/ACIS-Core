"""
Comprehensive test suite validating:
1. Backend process_threat():
   - LOW / MEDIUM: auto-remediated, not in pending_approvals
   - HIGH / CRITICAL with confidence <= 0.95: auto-remediated, not in pending_approvals
   - HIGH / CRITICAL with confidence > 0.95: added to pending_approvals for human approval
2. Threats Blocked vs Pending Human Approval counts:
   - Threats Blocked includes all auto-remediated threats
   - Pending Approvals only contains confidence > 95% and severity HIGH/CRITICAL
3. Alert logic:
   - Alerts generated ONLY for threats added to pending_approvals (confidence > 0.95 and HIGH/CRITICAL)
   - Auto-remediated threats do not trigger user alerts
4. Realistic confidence:
   - Derived from max(probability), never hardcoded
   - Strictly capped at 99.9% (never 100%)
"""

import sys
import json
import importlib.metadata

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

import werkzeug
if not hasattr(werkzeug, '__version__'):
    try:
        werkzeug.__version__ = importlib.metadata.version('werkzeug')
    except Exception:
        werkzeug.__version__ = '3.1.3'

from app import (
    app,
    analyze_threat,
    process_threat,
    pending_approvals,
    auto_remediation_log,
    alert_history,
    threat_history
)

client = app.test_client()

print("=" * 70)
print("[TEST 1] Verify Confidence Threshold (>95%) in process_threat()")
print("=" * 70)

# 1. LOW Severity (Always auto-remediate)
t_low = process_threat({
    'threat_id': 'TH-CONF-LOW-01',
    'source': '10.0.0.1',
    'severity': 'LOW',
    'confidence': 0.98,  # Even with high confidence, LOW is auto-remediated
    'details': {'attack_probability': 0.20, 'confidence': 0.98}
})
print(f"LOW (conf=98%): status={t_low['status']}, requires_human={t_low['requires_human']}")
assert t_low['status'] == 'RESOLVED_AUTOMATICALLY'
assert t_low['requires_human'] is False
assert 'TH-CONF-LOW-01' not in pending_approvals

# 2. MEDIUM Severity (Always auto-remediate)
t_med = process_threat({
    'threat_id': 'TH-CONF-MED-01',
    'source': '10.0.0.2',
    'severity': 'MEDIUM',
    'confidence': 0.97,
    'details': {'attack_probability': 0.55, 'confidence': 0.97}
})
print(f"MEDIUM (conf=97%): status={t_med['status']}, requires_human={t_med['requires_human']}")
assert t_med['status'] == 'RESOLVED_AUTOMATICALLY'
assert t_med['requires_human'] is False
assert 'TH-CONF-MED-01' not in pending_approvals

# 3. HIGH Severity with Confidence <= 95% (e.g. 88.5%) -> Auto-remediate!
t_high_low_conf = process_threat({
    'threat_id': 'TH-CONF-HIGH-AUTO',
    'source': '198.51.100.10',
    'severity': 'HIGH',
    'confidence': 0.885,
    'details': {'attack_probability': 0.82, 'confidence': 0.885}
})
print(f"HIGH (conf=88.5% <= 95%): status={t_high_low_conf['status']}, requires_human={t_high_low_conf['requires_human']}")
assert t_high_low_conf['status'] == 'RESOLVED_AUTOMATICALLY'
assert t_high_low_conf['requires_human'] is False
assert 'TH-CONF-HIGH-AUTO' not in pending_approvals
assert any(entry['threat_id'] == 'TH-CONF-HIGH-AUTO' for entry in auto_remediation_log)

# 4. CRITICAL Severity with Confidence <= 95% (e.g. 93.0%) -> Auto-remediate!
t_crit_low_conf = process_threat({
    'threat_id': 'TH-CONF-CRIT-AUTO',
    'source': '198.51.100.20',
    'severity': 'CRITICAL',
    'confidence': 0.930,
    'details': {'attack_probability': 0.94, 'confidence': 0.930}
})
print(f"CRITICAL (conf=93.0% <= 95%): status={t_crit_low_conf['status']}, requires_human={t_crit_low_conf['requires_human']}")
assert t_crit_low_conf['status'] == 'RESOLVED_AUTOMATICALLY'
assert t_crit_low_conf['requires_human'] is False
assert 'TH-CONF-CRIT-AUTO' not in pending_approvals
assert any(entry['threat_id'] == 'TH-CONF-CRIT-AUTO' for entry in auto_remediation_log)

# 5. HIGH Severity with Confidence > 95% (e.g. 96.8%) -> Awaiting Human Approval!
t_high_approval = process_threat({
    'threat_id': 'TH-CONF-HIGH-PENDING',
    'source': '203.0.113.80',
    'severity': 'HIGH',
    'confidence': 0.968,
    'details': {'attack_probability': 0.88, 'confidence': 0.968}
})
print(f"HIGH (conf=96.8% > 95%): status={t_high_approval['status']}, requires_human={t_high_approval['requires_human']}")
assert t_high_approval['status'] == 'PENDING_HUMAN_APPROVAL'
assert t_high_approval['requires_human'] is True
assert 'TH-CONF-HIGH-PENDING' in pending_approvals

# 6. CRITICAL Severity with Confidence > 95% (e.g. 97.4%) -> Awaiting Human Approval!
t_crit_approval = process_threat({
    'threat_id': 'TH-CONF-CRIT-PENDING',
    'source': '203.0.113.90',
    'severity': 'CRITICAL',
    'confidence': 0.974,
    'details': {'attack_probability': 0.96, 'confidence': 0.974}
})
print(f"CRITICAL (conf=97.4% > 95%): status={t_crit_approval['status']}, requires_human={t_crit_approval['requires_human']}")
assert t_crit_approval['status'] == 'PENDING_HUMAN_APPROVAL'
assert t_crit_approval['requires_human'] is True
assert 'TH-CONF-CRIT-PENDING' in pending_approvals

print("[PASS] Test 1 completed successfully!")

print("\n" + "=" * 70)
print("[TEST 2] Verify /api/pending-threats API Contains Only conf > 95% & HIGH/CRITICAL")
print("=" * 70)
res = client.get('/api/pending-threats')
data = json.loads(res.data)
assert res.status_code == 200 and data['success']
pending_items = data['pending']
print(f"Total pending approvals returned by backend: {len(pending_items)}")
for item in pending_items:
    sev = item['severity']
    conf = item['confidence']
    conf_pct = item['confidence_pct']
    print(f"  Pending Threat [{item['threat_id']}]: {sev:8} | Conf: {conf_pct}% (fraction={conf})")
    assert sev in ['HIGH', 'CRITICAL'], f"Unexpected severity {sev} in pending list!"
    assert conf > 0.95, f"Threat {item['threat_id']} with conf {conf} <= 0.95 must not be pending!"
    assert conf <= 0.999, f"Confidence {conf} exceeds 99.9% cap!"

print("[PASS] Test 2 completed successfully!")

print("\n" + "=" * 70)
print("[TEST 3] Verify Threats Blocked Includes All Auto-Remediated Threats")
print("=" * 70)
mon_res = client.get('/api/monitoring/status')
mon_data = json.loads(mon_res.data)
threats_blocked = mon_data['threats_blocked']
auto_fixes = mon_data['auto_fixes']
pending_count = mon_data['pending_approvals']
alerts_count = mon_data['alerts']

print(f"Threats Blocked (Auto-Remediated): {threats_blocked}")
print(f"Pending Human Approval: {pending_count}")
print(f"Active Alerts: {alerts_count}")
assert threats_blocked == len(auto_remediation_log)
assert threats_blocked >= 4  # Contains LOW, MEDIUM, and HIGH/CRITICAL <= 95%
assert pending_count == len(pending_approvals)
# All pending approvals must be strictly high-confidence HIGH/CRITICAL
assert all(p['confidence'] > 0.95 for p in pending_approvals.values())
print("[PASS] Test 3 completed successfully!")

print("\n" + "=" * 70)
print("[TEST 4] Verify Alert Logic: Generated ONLY for Pending Approvals")
print("=" * 70)
for alert in alert_history:
    assert alert['requires_human'] is True
    assert alert['confidence'] > 0.95
    assert alert['alert_type'] in ['HIGH', 'CRITICAL']
    print(f"  Alert [{alert['threat_id']}]: {alert['alert_type']} | Conf: {alert['confidence_display']} -> {alert['message']}")

print(f"Verified {len(alert_history)} alerts. Zero alerts for auto-remediated threats.")
print("[PASS] Test 4 completed successfully!")

print("\n" + "=" * 70)
print("[TEST 5] Verify Confidence Calculation from Model & 99.9% Cap")
print("=" * 70)
modes = ['normal', 'low_attack', 'medium_attack', 'severe_attack']
for m in modes:
    analyzed = analyze_threat(None, mode=m)
    conf = analyzed['confidence']
    conf_pct = analyzed['confidence_pct']
    print(f"Mode {m:14}: Conf={conf} ({conf_pct}%) | AttackProb={analyzed['attack_probability']}")
    assert conf < 1.0, f"Confidence {conf} must never reach 1.0"
    assert conf <= 0.999, f"Confidence {conf} capped at 99.9%"
    assert conf_pct <= 99.9

print("[PASS] Test 5 completed successfully!")

print("\n" + "=" * 70)
print("ALL CONFIDENCE-BASED APPROVAL WORKFLOW TESTS PASSED!")
print("=" * 70)
