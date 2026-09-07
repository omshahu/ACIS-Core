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

from app import app, digital_twin

client = app.test_client()

print("=== 1. Testing /api/metrics ===")
res = client.get('/api/metrics')
data = json.loads(res.data)
assert res.status_code == 200 and data['success']
m = data['metrics']
print(f"Metrics: Acc={m['accuracy']}%, Prec={m['precision']}%, Rec={m['recall']}%, F1={m['f1_score']}%")
print(f"Decisions: {m['threats_blocked']} / {m['total_decisions']} ({m['decision_ratio']}%)")
assert m['accuracy'] < 100.0 and m['precision'] < 100.0 and m['recall'] < 100.0 and m['f1_score'] < 100.0

print("\n=== 2. Testing /api/twin/topology ===")
res = client.get('/api/twin/topology')
data = json.loads(res.data)
assert res.status_code == 200 and data['success']
expected_nodes = {'core-ai-engine', 'waf-gateway', 'trust-ledger-db', 'telemetry-broker', 'sandbox-env'}
actual_nodes = set(data['nodes'].keys())
print(f"Topology nodes: {actual_nodes}")
assert actual_nodes == expected_nodes

print("\n=== 3. Testing 4 Plain-English Scenarios via /api/twin ===")
scenarios = [
    'Normal Operation (Baseline)',
    'DDoS Surge Attack',
    'Ransomware Propagation',
    'CPU/Memory Overload (3x Spike)'
]

for scen in scenarios:
    res = client.post('/api/twin', json={'scenario': scen})
    data = json.loads(res.data)
    assert res.status_code == 200 and data['success']
    nodes = data['twin_state']['nodes']
    print(f"\nScenario: '{scen}'")
    for nid, ndata in nodes.items():
        h = ndata['health'] * 100
        status_dot = "GREEN" if h > 95 else ("YELLOW" if h >= 80 else "RED")
        print(f"  - {nid:20}: Health={h:5.1f}% [{status_dot}] (status={ndata.get('status', 'n/a')})")

print("\n=== 4. Testing SSE /api/twin/stream generator output ===")
stream_res = client.get('/api/twin/stream')
assert stream_res.status_code == 200
# Read first SSE chunk
first_chunk = next(stream_res.response)
text = first_chunk.decode('utf-8')
print("First SSE event chunk:")
print(text[:200] + "...")
assert text.startswith('data: ')
parsed_payload = json.loads(text[6:])
assert 'nodes' in parsed_payload
assert 'metrics' in parsed_payload
assert parsed_payload['metrics']['accuracy'] < 100.0

print("\n[ALL VERIFICATION CHECKS PASSED SUCCESSFULLY]")
