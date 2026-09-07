import numpy as np
import random
from datetime import datetime
import time

class DigitalTwin:
    def __init__(self):
        # Default telemetry metrics state
        self.state = {
            'status': 'operational',
            'scenario': 'Normal Operation (Baseline)',
            'network_health': 0.974,
            'threat_level': 'LOW',
            'active_connections': 128,
            'cpu_usage': 28.5,
            'memory_usage': 42.0,
            'disk_io': 22.0,
            'network_latency': 9.5,
            'risk_score': 12,
            'threats_blocked': 142,
            'total_decisions': 150,
            'last_update': datetime.now().isoformat()
        }
        
        # 5 Target Topology Nodes with health scores (0.0 - 1.0)
        self.nodes = {
            'core-ai-engine': {
                'id': 'core-ai-engine',
                'name': 'ACIS AI Core',
                'type': 'ai_core',
                'status': 'operational',
                'load': 38,
                'health': 0.985
            },
            'waf-gateway': {
                'id': 'waf-gateway',
                'name': 'WAF Gateway',
                'type': 'gateway',
                'status': 'operational',
                'load': 32,
                'health': 0.972
            },
            'trust-ledger-db': {
                'id': 'trust-ledger-db',
                'name': 'Trust Ledger DB',
                'type': 'database',
                'status': 'operational',
                'load': 24,
                'health': 0.991
            },
            'telemetry-broker': {
                'id': 'telemetry-broker',
                'name': 'Telemetry Broker',
                'type': 'broker',
                'status': 'operational',
                'load': 30,
                'health': 0.965
            },
            'sandbox-env': {
                'id': 'sandbox-env',
                'name': 'Sandbox Env',
                'type': 'sandbox',
                'status': 'operational',
                'load': 18,
                'health': 0.982
            }
        }
        
        self.history = []
        self._seed_initial_history()

    def _seed_initial_history(self):
        """Seeds initial history buffer for playback timeline."""
        now = time.time()
        for i in range(15, 0, -1):
            t_str = datetime.fromtimestamp(now - i * 5).isoformat()
            self.history.append({
                'timestamp': t_str,
                'status': 'operational',
                'scenario': 'Normal Operation (Baseline)',
                'network_health': round(0.96 + random.uniform(0, 0.03), 3),
                'threat_level': 'LOW',
                'active_connections': random.randint(110, 140),
                'cpu_usage': round(25.0 + random.uniform(0, 10), 1),
                'memory_usage': round(40.0 + random.uniform(0, 6), 1),
                'disk_io': round(15.0 + random.uniform(0, 8), 1),
                'network_latency': round(8.0 + random.uniform(0, 4), 1),
                'risk_score': random.randint(8, 16)
            })

    def simulate(self, scenario='normal'):
        """
        Simulate telemetry under 4 exact scenarios:
        1. Normal Operation (Baseline)
        2. DDoS Surge Attack
        3. Ransomware Propagation
        4. CPU/Memory Overload (3x Spike)
        """
        timestamp = datetime.now().isoformat()
        scen_clean = str(scenario).lower()

        # 1. Normal Operation (Baseline)
        if 'normal' in scen_clean or 'baseline' in scen_clean:
            scenario_title = 'Normal Operation (Baseline)'
            state = {
                'status': 'operational',
                'scenario': scenario_title,
                'timestamp': timestamp,
                'network_health': round(random.uniform(0.96, 0.99), 3),
                'threat_level': 'LOW',
                'active_connections': random.randint(100, 150),
                'cpu_usage': round(random.uniform(22.0, 34.0), 1),
                'memory_usage': round(random.uniform(36.0, 46.0), 1),
                'disk_io': round(random.uniform(15.0, 28.0), 1),
                'network_latency': round(random.uniform(6.0, 14.0), 1),
                'risk_score': random.randint(6, 18),
                'threats_blocked': self.state.get('threats_blocked', 142) + random.randint(0, 1),
                'total_decisions': self.state.get('total_decisions', 150) + random.randint(1, 2)
            }
            # All nodes > 95% (Green)
            for n_id, n in self.nodes.items():
                n['status'] = 'operational'
                n['health'] = round(random.uniform(0.96, 0.995), 3)
                n['load'] = random.randint(20, 38)

        # 2. DDoS Surge Attack
        elif 'ddos' in scen_clean or 'surge' in scen_clean:
            scenario_title = 'DDoS Surge Attack'
            state = {
                'status': 'under_attack',
                'scenario': scenario_title,
                'timestamp': timestamp,
                'network_health': round(random.uniform(0.65, 0.76), 3),
                'threat_level': 'CRITICAL',
                'active_connections': random.randint(650, 950),
                'cpu_usage': round(random.uniform(78.0, 91.0), 1),
                'memory_usage': round(random.uniform(70.0, 84.0), 1),
                'disk_io': round(random.uniform(65.0, 88.0), 1),
                'network_latency': round(random.uniform(110.0, 185.0), 1),
                'risk_score': random.randint(78, 95),
                'threats_blocked': self.state.get('threats_blocked', 142) + random.randint(3, 8),
                'total_decisions': self.state.get('total_decisions', 150) + random.randint(4, 9)
            }
            # WAF Gateway compromised/stressed (<80% Red), Telemetry & AI in yellow
            self.nodes['waf-gateway']['health'] = round(random.uniform(0.68, 0.77), 3) # Red (<80%)
            self.nodes['waf-gateway']['status'] = 'degraded'
            self.nodes['waf-gateway']['load'] = random.randint(90, 98)

            self.nodes['telemetry-broker']['health'] = round(random.uniform(0.82, 0.89), 3) # Yellow (80-95%)
            self.nodes['telemetry-broker']['status'] = 'warning'
            self.nodes['telemetry-broker']['load'] = random.randint(82, 92)

            self.nodes['core-ai-engine']['health'] = round(random.uniform(0.88, 0.93), 3) # Yellow (80-95%)
            self.nodes['core-ai-engine']['status'] = 'operational'
            self.nodes['core-ai-engine']['load'] = random.randint(75, 88)

            self.nodes['trust-ledger-db']['health'] = round(random.uniform(0.96, 0.99), 3) # Green
            self.nodes['trust-ledger-db']['status'] = 'operational'

            self.nodes['sandbox-env']['health'] = round(random.uniform(0.95, 0.98), 3) # Green
            self.nodes['sandbox-env']['status'] = 'operational'

        # 3. Ransomware Propagation
        elif 'ransomware' in scen_clean or 'propagation' in scen_clean:
            scenario_title = 'Ransomware Propagation'
            state = {
                'status': 'critical_threat',
                'scenario': scenario_title,
                'timestamp': timestamp,
                'network_health': round(random.uniform(0.52, 0.68), 3),
                'threat_level': 'CRITICAL',
                'active_connections': random.randint(220, 420),
                'cpu_usage': round(random.uniform(82.0, 94.0), 1),
                'memory_usage': round(random.uniform(76.0, 89.0), 1),
                'disk_io': round(random.uniform(88.0, 99.0), 1),
                'network_latency': round(random.uniform(65.0, 130.0), 1),
                'risk_score': random.randint(85, 98),
                'threats_blocked': self.state.get('threats_blocked', 142) + random.randint(4, 9),
                'total_decisions': self.state.get('total_decisions', 150) + random.randint(5, 10)
            }
            # Trust Ledger DB and Sandbox under siege (<80% Red)
            self.nodes['trust-ledger-db']['health'] = round(random.uniform(0.65, 0.76), 3) # Red (<80%)
            self.nodes['trust-ledger-db']['status'] = 'compromised'
            self.nodes['trust-ledger-db']['load'] = random.randint(88, 98)

            self.nodes['sandbox-env']['health'] = round(random.uniform(0.70, 0.79), 3) # Red (<80%)
            self.nodes['sandbox-env']['status'] = 'isolated'
            self.nodes['sandbox-env']['load'] = random.randint(84, 95)

            self.nodes['core-ai-engine']['health'] = round(random.uniform(0.85, 0.92), 3) # Yellow (80-95%)
            self.nodes['core-ai-engine']['status'] = 'warning'
            self.nodes['core-ai-engine']['load'] = random.randint(80, 92)

            self.nodes['waf-gateway']['health'] = round(random.uniform(0.91, 0.94), 3) # Yellow
            self.nodes['telemetry-broker']['health'] = round(random.uniform(0.92, 0.95), 3) # Yellow

        # 4. CPU/Memory Overload (3x Spike)
        elif 'overload' in scen_clean or 'spike' in scen_clean or 'cpu' in scen_clean:
            scenario_title = 'CPU/Memory Overload (3x Spike)'
            state = {
                'status': 'resource_exhaustion',
                'scenario': scenario_title,
                'timestamp': timestamp,
                'network_health': round(random.uniform(0.72, 0.84), 3),
                'threat_level': 'HIGH',
                'active_connections': random.randint(350, 600),
                'cpu_usage': round(random.uniform(93.0, 98.5), 1),  # 3x spike
                'memory_usage': round(random.uniform(89.0, 96.0), 1),
                'disk_io': round(random.uniform(70.0, 88.0), 1),
                'network_latency': round(random.uniform(45.0, 95.0), 1),
                'risk_score': random.randint(62, 79),
                'threats_blocked': self.state.get('threats_blocked', 142) + random.randint(1, 3),
                'total_decisions': self.state.get('total_decisions', 150) + random.randint(2, 4)
            }
            # AI Engine and Telemetry Broker overloaded (<80% Red)
            self.nodes['core-ai-engine']['health'] = round(random.uniform(0.71, 0.78), 3) # Red (<80%)
            self.nodes['core-ai-engine']['status'] = 'degraded'
            self.nodes['core-ai-engine']['load'] = random.randint(94, 99)

            self.nodes['telemetry-broker']['health'] = round(random.uniform(0.74, 0.79), 3) # Red (<80%)
            self.nodes['telemetry-broker']['status'] = 'degraded'
            self.nodes['telemetry-broker']['load'] = random.randint(91, 98)

            self.nodes['waf-gateway']['health'] = round(random.uniform(0.86, 0.92), 3) # Yellow (80-95%)
            self.nodes['trust-ledger-db']['health'] = round(random.uniform(0.88, 0.94), 3) # Yellow (80-95%)
            self.nodes['sandbox-env']['health'] = round(random.uniform(0.91, 0.95), 3) # Yellow (80-95%)

        else:
            return self.simulate('normal')

        self.state = state
        self.history.append(state)
        if len(self.history) > 100:
            self.history.pop(0)
        return state

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

    # ---------- OBSERVER PATTERN HOOKS ----------
    def observe_threat(self, threat_event):
        """Non-blocking observer hook called when upstream threat engine processes a threat."""
        try:
            severity = threat_event.get('severity', 'LOW')
            prob = threat_event.get('attack_probability', 0.0)
            
            self.state['threat_level'] = severity
            self.state['last_update'] = datetime.now().isoformat()
            
            if severity in ['HIGH', 'CRITICAL']:
                self.state['risk_score'] = min(100, int(prob * 100) + 15)
                self.state['network_health'] = max(0.4, round(1.0 - (prob * 0.5), 3))
                self.nodes['waf-gateway']['health'] = max(0.65, round(1.0 - prob * 0.35, 3))
                self.nodes['core-ai-engine']['health'] = max(0.75, round(1.0 - prob * 0.25, 3))
            else:
                self.state['risk_score'] = random.randint(8, 22)
                self.state['network_health'] = round(0.96 + random.uniform(0, 0.03), 3)
                for n in self.nodes.values():
                    n['health'] = max(n['health'], round(random.uniform(0.96, 0.99), 3))
        except Exception:
            pass

    def observe_remediation(self, remediation_event):
        try:
            self.state['threats_blocked'] = self.state.get('threats_blocked', 142) + 1
            self.state['total_decisions'] = self.state.get('total_decisions', 150) + 1
            self.state['risk_score'] = max(5, self.state.get('risk_score', 20) - 15)
            self.state['network_health'] = min(0.99, round(self.state.get('network_health', 0.85) + 0.08, 3))
            for n in self.nodes.values():
                n['health'] = min(0.995, round(n.get('health', 0.85) + 0.1, 3))
                if n['health'] > 0.95:
                    n['status'] = 'operational'
        except Exception:
            pass

    # ---------- SANDBOX WHAT-IF ENGINE ----------
    def run_sandbox_simulation(self, scenario, params, classifier_ref, autoencoder_ref):
        n_feats = len(classifier_ref.feature_names) if (classifier_ref and hasattr(classifier_ref, 'feature_names') and classifier_ref.feature_names) else 12
        base_features = params.get('features')
        if not base_features or len(base_features) != n_feats:
            np.random.seed(random.randint(1, 10000))
            base_features = np.random.randn(n_feats).tolist()
        
        load_factor = float(params.get('load_factor', 1.0))
        attack_intensity = float(params.get('attack_intensity', 0.0))
        isolated_nodes = params.get('isolated_nodes', [])
        
        sim_features = [f * load_factor + (attack_intensity * 0.5) for f in base_features]
        sim_array = np.array(sim_features).reshape(1, -1)
        if classifier_ref and hasattr(classifier_ref, 'feature_names') and classifier_ref.feature_names and len(classifier_ref.feature_names) == n_feats:
            import pandas as pd
            sim_input = pd.DataFrame(sim_array, columns=classifier_ref.feature_names)
        else:
            sim_input = sim_array
        
        pred = 0
        prob = [0.95, 0.05]
        anomaly = False
        reconstruction_err = 0.12
        
        if classifier_ref and hasattr(classifier_ref, 'predict_proba'):
            try:
                prob = classifier_ref.predict_proba(sim_input)[0].tolist()
                res = classifier_ref.predict(sim_input)
                pred = int(res[0][0] if isinstance(res, tuple) else res[0])
            except Exception:
                pass
                
        if autoencoder_ref and hasattr(autoencoder_ref, 'predict'):
            try:
                anomaly = bool(autoencoder_ref.predict(sim_array)[0])
            except Exception:
                pass

        attack_prob = prob[1] if len(prob) > 1 else 0.15
        simulated_risk_score = min(100, max(5, int(attack_prob * 100 + (load_factor - 1.0) * 20)))
        
        sandbox_nodes = {}
        for n_id, n_data in self.nodes.items():
            s_node = dict(n_data)
            if n_id in isolated_nodes:
                s_node['status'] = 'isolated'
                s_node['health'] = 0.99
            elif attack_intensity > 0.6 and n_id in ['waf-gateway', 'core-ai-engine']:
                s_node['health'] = max(0.68, round(s_node['health'] - attack_intensity * 0.3, 3))
                s_node['status'] = 'degraded' if s_node['health'] >= 0.80 else 'compromised'
            sandbox_nodes[n_id] = s_node

        predicted_threat_level = 'CRITICAL' if attack_prob > 0.80 else ('HIGH' if attack_prob > 0.50 else 'LOW')

        return {
            'is_sandbox': True,
            'scenario': scenario,
            'sandbox_metrics': {
                'simulated_cpu': min(100.0, round(self.state['cpu_usage'] * load_factor, 1)),
                'simulated_latency': round(self.state['network_latency'] * (1.0 + attack_intensity * 2), 1),
                'risk_score': simulated_risk_score,
                'attack_probability': round(attack_prob, 3),
                'predicted_threat_level': predicted_threat_level,
                'is_anomaly': anomaly,
                'reconstruction_error': reconstruction_err
            },
            'sandbox_nodes': sandbox_nodes,
            'live_comparison': {
                'risk_delta': simulated_risk_score - self.state['risk_score'],
                'cpu_delta': round(min(100.0, self.state['cpu_usage'] * load_factor) - self.state['cpu_usage'], 1)
            }
        }