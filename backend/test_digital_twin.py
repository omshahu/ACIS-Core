import sys

# Configure UTF-8 for console output on Windows
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

# Ensure werkzeug has __version__ for Flask test_client compatibility (Werkzeug 3.1+)
import werkzeug
if not hasattr(werkzeug, '__version__'):
    try:
        import importlib.metadata
        werkzeug.__version__ = importlib.metadata.version('werkzeug')
    except Exception:
        werkzeug.__version__ = "3.1.3"

import unittest
import json
import numpy as np
from app import app, threat_store, pending_approvals, classifier, autoencoder

class TestDigitalTwinIntegration(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_01_existing_health_endpoint(self):
        """Verify /api/health works without regression"""
        response = self.app.get('/api/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data.get('status'), 'online')
        self.assertEqual(data.get('version'), '2.0.0')

    def test_02_existing_metrics_endpoint(self):
        """Verify /api/metrics works without regression and returns realistic floating metrics"""
        response = self.app.get('/api/metrics')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data.get('success'))
        metrics = data.get('metrics', {})
        self.assertIn('accuracy', metrics)
        # Ensure metrics are realistic floating values and NOT 100%
        self.assertNotEqual(metrics['accuracy'], 100.0)
        self.assertNotEqual(metrics['precision'], 100.0)
        self.assertNotEqual(metrics['recall'], 100.0)
        self.assertNotEqual(metrics['f1_score'], 100.0)

    def test_03_existing_threat_endpoint(self):
        """Verify /api/threat works without regression"""
        response = self.app.post('/api/threat', json={'mode': 'normal'})
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data.get('success'))
        self.assertIn('prediction', data)
        self.assertIn('threat_level', data)

    def test_04_digital_twin_state(self):
        """Verify updated /api/twin/state endpoint with 5 target nodes"""
        response = self.app.get('/api/twin/state')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data.get('success'))
        twin_state = data.get('twin_state', {})
        self.assertIn('metrics', twin_state)
        self.assertIn('nodes', twin_state)
        # Verify new node names
        self.assertIn('core-ai-engine', twin_state['nodes'])
        self.assertIn('waf-gateway', twin_state['nodes'])
        self.assertIn('trust-ledger-db', twin_state['nodes'])
        self.assertIn('telemetry-broker', twin_state['nodes'])
        self.assertIn('sandbox-env', twin_state['nodes'])

    def test_05_digital_twin_history(self):
        """Verify new /api/twin/history endpoint"""
        response = self.app.get('/api/twin/history?limit=10')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data.get('success'))
        self.assertIsInstance(data.get('history'), list)

    def test_06_what_if_sandbox_isolation(self):
        """Verify /api/twin/simulate-what-if runs in sandbox mode without mutating production state"""
        initial_threat_count = len(threat_store)
        initial_pending_count = len(pending_approvals)

        payload = {
            'scenario': 'DDoS Surge Attack',
            'params': {
                'load_factor': 2.0,
                'attack_intensity': 0.9,
                'isolated_nodes': ['waf-gateway']
            }
        }
        response = self.app.post('/api/twin/simulate-what-if', json=payload)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data.get('success'))
        sim = data.get('simulation', {})
        self.assertTrue(sim.get('is_sandbox'))
        self.assertEqual(sim.get('scenario'), 'DDoS Surge Attack')
        self.assertIn('sandbox_metrics', sim)

        # STRICT ZERO-REGRESSION CHECK: Verify production state was NOT mutated
        self.assertEqual(len(threat_store), initial_threat_count, "Threat store must not mutate during sandbox run")
        self.assertEqual(len(pending_approvals), initial_pending_count, "Pending approvals must not mutate during sandbox run")

if __name__ == '__main__':
    unittest.main()
