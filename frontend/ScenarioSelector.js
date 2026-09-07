/**
 * ACIS-Core — ScenarioSelector Component
 * Simplified dropdown with the 4 exact plain-English choices:
 *   1. Normal Operation (Baseline)
 *   2. DDoS Surge Attack
 *   3. Ransomware Propagation
 *   4. CPU/Memory Overload (3x Spike)
 */

import React, { useState } from 'react';
import './topology.css';

export const SCENARIOS = [
  {
    id: 'Normal Operation (Baseline)',
    label: 'Normal Operation (Baseline)',
    description: 'Optimal baseline conditions. All nodes operational (>95% health).'
  },
  {
    id: 'DDoS Surge Attack',
    label: 'DDoS Surge Attack',
    description: 'Volumetric packet flood hitting WAF Gateway. Health degrades to critical (<80%).'
  },
  {
    id: 'Ransomware Propagation',
    label: 'Ransomware Propagation',
    description: 'Lateral infection targeting Trust Ledger DB and isolated Sandbox environment.'
  },
  {
    id: 'CPU/Memory Overload (3x Spike)',
    label: 'CPU/Memory Overload (3x Spike)',
    description: '3x resource exhaustion spike degrading ACIS AI Core and Telemetry Broker.'
  }
];

const DEFAULT_API_BASE = typeof window !== 'undefined' && window.location.port === '5001'
  ? '/api'
  : 'http://127.0.0.1:5001/api';

export function ScenarioSelector({
  currentScenario = 'Normal Operation (Baseline)',
  onScenarioChange,
  apiBase = DEFAULT_API_BASE
}) {
  const [selected, setSelected] = useState(currentScenario);
  const [loading, setLoading] = useState(false);
  const [feedback, setFeedback] = useState(null);

  const handleChange = async (e) => {
    const scenarioChoice = e.target.value;
    setSelected(scenarioChoice);
    setLoading(true);
    setFeedback(null);

    try {
      const res = await fetch(`${apiBase}/twin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioChoice })
      });
      const data = await res.json();
      if (data.success) {
        setFeedback({ type: 'success', text: `Switched to: ${scenarioChoice}` });
        if (onScenarioChange) onScenarioChange(scenarioChoice, data.twin_state);
      } else {
        setFeedback({ type: 'error', text: data.error || 'Failed to switch scenario' });
      }
    } catch (err) {
      // Local fallback simulation if server is offline
      setFeedback({ type: 'warning', text: `Simulated locally: ${scenarioChoice}` });
      if (onScenarioChange) onScenarioChange(scenarioChoice, null);
    } finally {
      setLoading(false);
      setTimeout(() => setFeedback(null), 4000);
    }
  };

  const currentDesc = SCENARIOS.find((s) => s.id === selected)?.description || '';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '16px' }}>
      <div className="scenario-selector-container">
        <label
          htmlFor="scenario-select"
          style={{
            fontSize: '0.85rem',
            fontWeight: 600,
            color: '#94A3B8',
            whiteSpace: 'nowrap'
          }}
        >
          Active Scenario:
        </label>
        <select
          id="scenario-select"
          className="scenario-select"
          value={selected}
          onChange={handleChange}
          disabled={loading}
          style={{ minWidth: '280px' }}
        >
          {SCENARIOS.map((scen) => (
            <option key={scen.id} value={scen.id}>
              {scen.label}
            </option>
          ))}
        </select>

        {loading && (
          <span style={{ fontSize: '0.8rem', color: '#60A5FA' }}>
            Updating twin topology...
          </span>
        )}

        {feedback && (
          <span
            style={{
              fontSize: '0.8rem',
              fontWeight: 500,
              color:
                feedback.type === 'success'
                  ? '#10B981'
                  : feedback.type === 'warning'
                  ? '#F59E0B'
                  : '#EF4444'
            }}
          >
            {feedback.text}
          </span>
        )}
      </div>

      <div style={{ fontSize: '0.75rem', color: '#64748B', fontStyle: 'italic' }}>
        {currentDesc}
      </div>
    </div>
  );
}

export default ScenarioSelector;
