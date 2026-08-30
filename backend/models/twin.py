import numpy as np
import random
from datetime import datetime
import time

class DigitalTwin:
    def __init__(self):
        # Default state (100% compatible with original schema)
        self.state = {
            'status': 'operational',
            'network_health': 0.95,
            'threat_level': 'LOW',
            'active_connections': 120,
            'cpu_usage': 35.0,
            'memory_usage': 45.0,
            'disk_io': 25.0,
            'network_latency': 10.0,
            'risk_score': 12,
            'last_update': datetime.now().isoformat()
        }
        
        # Detailed component nodes data model
        self.nodes = {
            'fw-01': {'id': 'fw-01', 'name': 'Edge Firewall', 'type': 'firewall', 'status': 'operational', 'load': 28, 'health': 0.98},
            'waf-01': {'id': 'waf-01', 'name': 'Web App Gateway', 'type': 'gateway', 'status': 'operational', 'load': 35, 'health': 0.96},
            'ai-engine': {'id': 'ai-engine', 'name': 'ACIS AI Core', 'type': 'ai_core', 'status': 'operational', 'load': 42, 'health': 0.99},
            'db-cluster': {'id': 'db-cluster', 'name': 'Security Ledger DB', 'type': 'database', 'status': 'operational', 'load': 20, 'health': 0.97},
            'ep-subnet': {'id': 'ep-subnet', 'name': 'Endpoint Subnet', 'type': 'endpoints', 'status': 'operational', 'load': 15, 'health': 0.95}
        }
        
        self.history = []
        # Pre-fill initial history for playback timeline
        self._seed_initial_history()

    def _seed_initial_history(self):
        """Seeds a rolling history buffer for timeline playback."""
        now = time.time()
        for i in range(15, 0, -1):
            t_str = datetime.fromtimestamp(now - i * 5).isoformat()
            self.history.append({
                'timestamp': t_str,
                'status': 'operational',
                'network_health': round(0.92 + random.uniform(0, 0.07), 3),
                'threat_level': 'LOW',
                'active_connections': random.randint(100, 140),
                'cpu_usage': round(25.0 + random.uniform(0, 15), 1),
                'memory_usage': round(40.0 + random.uniform(0, 10), 1),
                'disk_io': round(15.0 + random.uniform(0, 10), 1),
                'network_latency': round(8.0 + random.uniform(0, 5), 1),
                'risk_score': random.randint(5, 20)
            })

    def simulate(self, scenario='normal'):
        """Original simulation method — preserved with enhanced telemetry payload."""
        timestamp = datetime.now().isoformat()
        state = {
            'status': 'operational',
            'timestamp': timestamp,
            'network_health': round(random.uniform(0.8, 1.0), 3),
            'threat_level': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
            'active_connections': random.randint(50, 200),
            'cpu_usage': round(random.uniform(10, 80), 1),
            'memory_usage': round(random.uniform(20, 70), 1),
            'disk_io': round(random.uniform(10, 50), 1),
            'network_latency': round(random.uniform(1, 20), 1),
            'risk_score': random.randint(10, 45)
        }
        
        if scenario == 'attack':
            state['threat_level'] = 'CRITICAL'
            state['network_health'] = round(random.uniform(0.3, 0.6), 3)
            state['cpu_usage'] = round(random.uniform(70, 95), 1)
            state['network_latency'] = round(random.uniform(50, 200), 1)
            state['active_connections'] = random.randint(200, 500)
            state['status'] = 'compromised'
            state['risk_score'] = random.randint(75, 98)
            self._update_node_statuses('degraded', 'compromised')
        elif scenario == 'recovery':
            state['threat_level'] = 'LOW'
            state['network_health'] = round(random.uniform(0.9, 1.0), 3)
            state['cpu_usage'] = round(random.uniform(10, 30), 1)
            state['active_connections'] = random.randint(30, 80)
            state['status'] = 'recovering'
            state['risk_score'] = random.randint(15, 30)
            self._update_node_statuses('operational', 'recovering')
        elif scenario == 'maintenance':
            state['cpu_usage'] = round(random.uniform(10, 25), 1)
            state['active_connections'] = random.randint(10, 40)
            state['threat_level'] = 'LOW'
            state['status'] = 'maintenance'
            state['risk_score'] = random.randint(5, 15)
            self._update_node_statuses('operational', 'maintenance')
        else:
            self._update_node_statuses('operational', 'operational')

        self.state = state
        self.history.append(state)
        if len(self.history) > 100:
            self.history.pop(0)
        return state

    def _update_node_statuses(self, default_status, target_status):
        for n_id, n_data in self.nodes.items():
            if target_status == 'compromised' and n_id in ['waf-01', 'ep-subnet']:
                n_data['status'] = 'compromised'
                n_data['health'] = round(random.uniform(0.3, 0.5), 2)
            else:
                n_data['status'] = default_status
                n_data['health'] = round(random.uniform(0.9, 1.0), 2)

    def get_state(self):
        """Returns full live twin state snapshot including node topology."""
        return {
            'metrics': self.state,
            'nodes': self.nodes,
            'last_update': datetime.now().isoformat()
        }

    def update_state(self, updates):
        self.state.update(updates)
        self.state['last_update'] = datetime.now().isoformat()
        return self.state

    def get_history(self, limit=50):
        return self.history[-limit:]

    # ---------- OBSERVER PATTERN HOOKS (DECOUPLED) ----------
    def observe_threat(self, threat_event):
        """Non-blocking observer hook called when upstream threat engine processes a threat."""
        try:
            severity = threat_event.get('severity', 'LOW')
            prob = threat_event.get('attack_probability', 0.0)
            
            # Update internal twin state mirror without altering upstream data
            self.state['threat_level'] = severity
            self.state['last_update'] = datetime.now().isoformat()
            
            if severity in ['HIGH', 'CRITICAL']:
                self.state['risk_score'] = min(100, int(prob * 100) + 20)
                self.state['network_health'] = max(0.2, round(1.0 - (prob * 0.7), 2))
                self.nodes['waf-01']['status'] = 'warning'
                self.nodes['waf-01']['health'] = round(max(0.3, 1.0 - prob), 2)
            else:
                self.state['risk_score'] = max(5, int(prob * 40))
                self.nodes['waf-01']['status'] = 'operational'
            
            snapshot = dict(self.state)
            snapshot['timestamp'] = datetime.now().isoformat()
            self.history.append(snapshot)
            if len(self.history) > 100:
                self.history.pop(0)
        except Exception:
            pass  # Observer must fail silently to ensure ZERO upstream regression

    def observe_remediation(self, remediation_event):
        """Observer hook when SOAR remediation occurs."""
        try:
            self.state['threat_level'] = 'LOW'
            self.state['risk_score'] = max(5, self.state.get('risk_score', 20) - 30)
            self.state['network_health'] = min(0.99, self.state.get('network_health', 0.8) + 0.15)
            for n_id, n_data in self.nodes.items():
                n_data['status'] = 'operational'
                n_data['health'] = 0.98
            
            snapshot = dict(self.state)
            snapshot['timestamp'] = datetime.now().isoformat()
            self.history.append(snapshot)
            if len(self.history) > 100:
                self.history.pop(0)
        except Exception:
            pass

    # ---------- SANDBOX WHAT-IF ENGINE ----------
    def run_sandbox_simulation(self, scenario, params, classifier_ref, autoencoder_ref):
        """
        Runs a prospective scenario in an isolated sandbox environment.
        Passes parameters to upstream ML models without modifying production database or state history.
        """
        base_features = params.get('features')
        if not base_features or len(base_features) != 10:
            # Generate baseline features matching dataset shape
            np.random.seed(random.randint(1, 10000))
            base_features = np.random.randn(10).tolist()
        
        # Apply parameter modifications in sandbox scope
        load_factor = float(params.get('load_factor', 1.0))
        attack_intensity = float(params.get('attack_intensity', 0.0))
        isolated_nodes = params.get('isolated_nodes', [])
        
        sim_features = [f * load_factor + (attack_intensity * 0.5) for f in base_features]
        sim_array = np.array(sim_features).reshape(1, -1)
        
        # Call production ML models in read-only sandbox mode
        pred = 0
        prob = [0.9, 0.1]
        anomaly = False
        reconstruction_err = 0.12
        
        if classifier_ref and hasattr(classifier_ref, 'predict_proba'):
            try:
                prob = classifier_ref.predict_proba(sim_array)[0].tolist()
                pred = int(classifier_ref.predict(sim_array)[0])
            except Exception:
                pass
                
        if autoencoder_ref and hasattr(autoencoder_ref, 'predict'):
            try:
                anomaly = bool(autoencoder_ref.predict(sim_array)[0])
            except Exception:
                pass

        attack_prob = prob[1] if len(prob) > 1 else (0.85 if scenario == 'attack' else 0.15)
        simulated_risk_score = min(100, max(5, int(attack_prob * 100 + (load_factor - 1.0) * 20)))
        
        # Map simulated impact on node topology without modifying live nodes
        sandbox_nodes = {}
        for n_id, n_data in self.nodes.items():
            s_node = dict(n_data)
            if n_id in isolated_nodes:
                s_node['status'] = 'isolated'
                s_node['health'] = 1.0
            elif attack_prob > 0.6 and n_id in ['waf-01', 'ep-subnet']:
                s_node['status'] = 'compromised' if attack_prob > 0.8 else 'degraded'
                s_node['health'] = round(1.0 - attack_prob, 2)
            else:
                s_node['status'] = 'operational'
                s_node['health'] = round(min(1.0, 0.95 / load_factor), 2)
            sandbox_nodes[n_id] = s_node

        # Return sandbox evaluation
        return {
            'scenario': scenario,
            'is_sandbox': True,
            'simulated_at': datetime.now().isoformat(),
            'sandbox_metrics': {
                'prediction': pred,
                'attack_probability': round(attack_prob, 4),
                'risk_score': simulated_risk_score,
                'anomaly_detected': anomaly,
                'predicted_threat_level': 'CRITICAL' if attack_prob > 0.8 else 'HIGH' if attack_prob > 0.6 else 'MEDIUM' if attack_prob > 0.3 else 'LOW',
                'simulated_cpu': min(100.0, round(self.state['cpu_usage'] * load_factor + (attack_intensity * 30), 1)),
                'simulated_latency': round(self.state['network_latency'] * load_factor + (attack_intensity * 50), 1)
            },
            'sandbox_nodes': sandbox_nodes,
            'live_comparison': {
                'live_risk_score': self.state.get('risk_score', 15),
                'live_threat_level': self.state.get('threat_level', 'LOW'),
                'risk_delta': simulated_risk_score - self.state.get('risk_score', 15)
            }
        }