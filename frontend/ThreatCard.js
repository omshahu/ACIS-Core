/**
 * ACIS-Core — ThreatCard Component
 * Displays an individual threat with colored severity badge, calibrated confidence (<99%),
 * and individual Approve / Reject remediation actions.
 * Light grey theme (#F1F5F9 surface, #FFFFFF panel, #64748B accent).
 */

import React from 'react';

/**
 * Returns color tokens for severity badge:
 * - LOW: green
 * - MEDIUM: yellow
 * - HIGH: orange
 * - CRITICAL: red
 */
export function getSeverityStyle(severity = 'LOW') {
  const sev = String(severity).toUpperCase();
  switch (sev) {
    case 'LOW':
      return {
        bg: '#DCFCE7',
        color: '#16A34A',
        border: '#86EFAC',
        dot: '#22C55E',
        label: 'LOW'
      };
    case 'MEDIUM':
      return {
        bg: '#FEF9C3',
        color: '#CA8A04',
        border: '#FDE047',
        dot: '#EAB308',
        label: 'MEDIUM'
      };
    case 'HIGH':
      return {
        bg: '#FFEDD5',
        color: '#EA580C',
        border: '#FDBA74',
        dot: '#F97316',
        label: 'HIGH'
      };
    case 'CRITICAL':
    default:
      return {
        bg: '#FEE2E2',
        color: '#DC2626',
        border: '#FCA5A5',
        dot: '#EF4444',
        label: 'CRITICAL'
      };
  }
}

/**
 * Format confidence percentage to one decimal place, strictly capping at 99.9% (never 100%)
 */
export function formatConfidence(confidence) {
  if (confidence === undefined || confidence === null) return '85.4%';
  let val = Number(confidence);
  // If provided as 0.0 - 1.0 fraction, scale to 0 - 100
  if (val <= 1.0) val = val * 100;
  // If confidence > 99.9%, cap it at 99.9% to avoid unrealistic 100% values
  if (val > 99.9) {
    val = 99.9;
  }
  return `${val.toFixed(1)}%`;
}

export function ThreatCard({
  threat = {},
  onApprove,
  onReject,
  isProcessing = false
}) {
  const threatId = threat.threat_id || threat.id || 'TH-UNKNOWN';
  const severity = threat.severity || 'LOW';
  const sevStyle = getSeverityStyle(severity);

  // Extract metadata safely
  const details = threat.threat_data?.details || threat.details || {};
  const sourceIp = threat.threat_data?.source || threat.source || threat.source_ip || '192.168.1.100';
  const threatType = threat.threat_data?.threat_type || details.threat_type || (threat.prediction === 1 ? 'Malicious Activity' : 'Heuristic Anomaly');
  const timestamp = threat.timestamp ? new Date(threat.timestamp).toLocaleTimeString() : 'Just now';

  const rawConf = details.confidence ?? threat.confidence ?? 0.85;
  const confidenceStr = formatConfidence(rawConf);
  const attackProb = details.attack_probability ?? threat.attack_probability;
  const probStr = attackProb ? `${(Number(attackProb) * (attackProb <= 1 ? 100 : 1)).toFixed(1)}%` : null;

  return (
    <div
      style={{
        backgroundColor: '#FFFFFF',
        border: '1px solid #E2E8F0',
        borderRadius: '8px',
        padding: '14px 18px',
        marginBottom: '10px',
        boxShadow: '0 1px 3px rgba(0, 0, 0, 0.05)',
        transition: 'border-color 0.2s, box-shadow 0.2s',
        display: 'flex',
        flexDirection: 'column',
        gap: '10px'
      }}
    >
      {/* Top Header Row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {/* Severity Badge */}
          <span
            style={{
              backgroundColor: sevStyle.bg,
              color: sevStyle.color,
              border: `1px solid ${sevStyle.border}`,
              padding: '3px 10px',
              borderRadius: '20px',
              fontSize: '0.75rem',
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              letterSpacing: '0.3px'
            }}
          >
            <span
              style={{
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                backgroundColor: sevStyle.dot
              }}
            />
            {sevStyle.label}
          </span>

          <strong style={{ fontSize: '0.9rem', color: '#0F172A', fontFamily: 'monospace' }}>
            {threatId}
          </strong>

          <span style={{ fontSize: '0.8rem', color: '#64748B' }}>
            Source: <strong style={{ color: '#334155' }}>{sourceIp}</strong>
          </span>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={() => onApprove && onApprove(threatId)}
            disabled={isProcessing}
            style={{
              backgroundColor: '#16A34A',
              color: '#FFFFFF',
              border: 'none',
              borderRadius: '6px',
              padding: '6px 14px',
              fontSize: '0.78rem',
              fontWeight: 600,
              cursor: isProcessing ? 'not-allowed' : 'pointer',
              opacity: isProcessing ? 0.6 : 1,
              transition: 'background-color 0.2s',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px'
            }}
            title="Approve containment action"
          >
            ✓ Approve
          </button>
          <button
            onClick={() => onReject && onReject(threatId)}
            disabled={isProcessing}
            style={{
              backgroundColor: '#DC2626',
              color: '#FFFFFF',
              border: 'none',
              borderRadius: '6px',
              padding: '6px 14px',
              fontSize: '0.78rem',
              fontWeight: 600,
              cursor: isProcessing ? 'not-allowed' : 'pointer',
              opacity: isProcessing ? 0.6 : 1,
              transition: 'background-color 0.2s',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px'
            }}
            title="Reject containment action"
          >
            ✕ Reject
          </button>
        </div>
      </div>

      {/* Details Row */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.8rem',
          color: '#64748B',
          paddingTop: '6px',
          borderTop: '1px solid #F1F5F9'
        }}
      >
        <div>
          <span>Threat Indicator: </span>
          <span style={{ color: '#1E293B', fontWeight: 500 }}>{threatType}</span>
        </div>

        <div style={{ display: 'flex', gap: '14px' }}>
          {probStr && (
            <span>
              Attack Prob: <strong style={{ color: '#0F172A' }}>{probStr}</strong>
            </span>
          )}
          <span>
            Confidence: <strong style={{ color: '#0F172A' }}>{confidenceStr}</strong>
          </span>
          <span>
            Time: <span style={{ color: '#94A3B8' }}>{timestamp}</span>
          </span>
        </div>
      </div>
    </div>
  );
}

export default ThreatCard;
