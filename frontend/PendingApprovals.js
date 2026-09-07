/**
 * ACIS-Core — PendingApprovals Component
 * Displays the "Pending Human Approval" section with "Approve All" and "Reject All" bulk action buttons.
 * Calls /api/remediate for each pending threat upon bulk approval/rejection.
 * Light grey theme (#F1F5F9 surface, #FFFFFF panels, #64748B accent).
 */

import React, { useState, useEffect, useCallback } from 'react';
import { ThreatCard, getSeverityStyle, formatConfidence } from './ThreatCard';

export { getSeverityStyle, formatConfidence };

const DEFAULT_API_BASE = typeof window !== 'undefined' && window.location.port === '5001'
  ? '/api'
  : 'http://127.0.0.1:5001/api';

export function PendingApprovals({ apiBase = DEFAULT_API_BASE, onRefreshNeeded }) {
  const [pendingThreats, setPendingThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isProcessing, setIsProcessing] = useState(false);
  const [statusMessage, setStatusMessage] = useState(null);

  // Fetch current pending threats from backend (display only confidence > 95% and HIGH/CRITICAL)
  const fetchPending = useCallback(async () => {
    try {
      const res = await fetch(`${apiBase}/pending-threats`);
      const data = await res.json();
      if (data.success && Array.isArray(data.pending)) {
        // Display only those threats where confidence > 95% and severity is HIGH/CRITICAL
        const highConfidenceThreats = data.pending.filter((t) => {
          const sev = String(t.severity || '').toUpperCase();
          if (sev !== 'HIGH' && sev !== 'CRITICAL') return false;

          const rawConf = t.confidence ?? t.threat_data?.details?.confidence ?? t.threat_data?.confidence ?? t.details?.confidence;
          if (rawConf === undefined || rawConf === null) return false;
          const confNum = Number(rawConf);
          const confFraction = confNum > 1 ? confNum / 100 : confNum;
          return confFraction > 0.95;
        });
        setPendingThreats(highConfidenceThreats);
      }
    } catch (err) {
      console.warn('[PendingApprovals] Failed to fetch pending threats:', err);
    } finally {
      setLoading(false);
    }
  }, [apiBase]);

  useEffect(() => {
    fetchPending();
    const interval = setInterval(fetchPending, 8000);
    return () => clearInterval(interval);
  }, [fetchPending]);

  // Single Threat Remediation
  const handleSingleAction = async (threatId, action) => {
    setIsProcessing(true);
    setStatusMessage({ type: 'info', text: `Processing ${action} for ${threatId}...` });

    try {
      const res = await fetch(`${apiBase}/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threat_id: threatId, action })
      });
      const data = await res.json();
      if (data.success) {
        setStatusMessage({
          type: 'success',
          text: `Threat ${threatId} successfully ${action === 'approve' ? 'approved' : 'rejected'}.`
        });
        setPendingThreats((prev) => prev.filter((t) => t.threat_id !== threatId));
        if (onRefreshNeeded) onRefreshNeeded();
      } else {
        setStatusMessage({ type: 'error', text: data.error || 'Failed to remediate threat.' });
      }
    } catch (err) {
      setStatusMessage({ type: 'error', text: `Network error: ${err.message}` });
    } finally {
      setIsProcessing(false);
      setTimeout(() => setStatusMessage(null), 4000);
    }
  };

  // Bulk Remediation: Approve All / Reject All
  const handleBulkAction = async (action) => {
    if (pendingThreats.length === 0) return;

    const count = pendingThreats.length;
    setIsProcessing(true);
    setStatusMessage({
      type: 'info',
      text: `${action === 'approve' ? 'Approving' : 'Rejecting'} ${count} threat${count > 1 ? 's' : ''}...`
    });

    let successCount = 0;
    const threatsToProcess = [...pendingThreats];

    for (const threat of threatsToProcess) {
      const threatId = threat.threat_id || threat.id;
      if (!threatId) continue;
      try {
        const res = await fetch(`${apiBase}/remediate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ threat_id: threatId, action })
        });
        const data = await res.json();
        if (data.success) {
          successCount += 1;
        }
      } catch (err) {
        console.error(`Failed to ${action} ${threatId}:`, err);
      }
    }

    // Refresh pending list
    await fetchPending();
    if (onRefreshNeeded) onRefreshNeeded();

    setStatusMessage({
      type: 'success',
      text: `Completed: ${successCount} of ${count} threat${count > 1 ? 's' : ''} ${action === 'approve' ? 'approved' : 'rejected'}.`
    });
    setIsProcessing(false);
    setTimeout(() => setStatusMessage(null), 5000);
  };

  return (
    <div
      style={{
        backgroundColor: '#F8FAFC',
        border: '1px solid #E2E8F0',
        borderRadius: '12px',
        padding: '20px',
        marginBottom: '24px',
        fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif"
      }}
    >
      {/* Section Header with Bulk Action Buttons */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
          marginBottom: '16px',
          paddingBottom: '12px',
          borderBottom: '1px solid #E2E8F0'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700, color: '#0F172A' }}>
              Pending Human Approval
            </h3>
            <div style={{ fontSize: '0.75rem', color: '#64748B', marginTop: '2px' }}>
              HIGH & CRITICAL threats with confidence &gt; 95% awaiting admin authorization. All others (≤ 95% & LOW/MEDIUM) are auto-resolved.
            </div>
          </div>
          <span
            style={{
              backgroundColor: pendingThreats.length > 0 ? '#FEE2E2' : '#E2E8F0',
              color: pendingThreats.length > 0 ? '#DC2626' : '#64748B',
              fontSize: '0.75rem',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: '12px'
            }}
          >
            {pendingThreats.length}
          </span>
        </div>

        {/* BULK ACTION BUTTONS */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            id="btn-approve-all"
            onClick={() => handleBulkAction('approve')}
            disabled={isProcessing || pendingThreats.length === 0}
            style={{
              backgroundColor: '#16A34A',
              color: '#FFFFFF',
              border: 'none',
              borderRadius: '6px',
              padding: '8px 16px',
              fontSize: '0.82rem',
              fontWeight: 600,
              cursor: isProcessing || pendingThreats.length === 0 ? 'not-allowed' : 'pointer',
              opacity: isProcessing || pendingThreats.length === 0 ? 0.5 : 1,
              transition: 'background-color 0.2s, transform 0.1s',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)'
            }}
          >
            <span style={{ fontSize: '0.9rem' }}>✓✓</span> Approve All
          </button>

          <button
            id="btn-reject-all"
            onClick={() => handleBulkAction('reject')}
            disabled={isProcessing || pendingThreats.length === 0}
            style={{
              backgroundColor: '#DC2626',
              color: '#FFFFFF',
              border: 'none',
              borderRadius: '6px',
              padding: '8px 16px',
              fontSize: '0.82rem',
              fontWeight: 600,
              cursor: isProcessing || pendingThreats.length === 0 ? 'not-allowed' : 'pointer',
              opacity: isProcessing || pendingThreats.length === 0 ? 0.5 : 1,
              transition: 'background-color 0.2s, transform 0.1s',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)'
            }}
          >
            <span style={{ fontSize: '0.9rem' }}>✕✕</span> Reject All
          </button>
        </div>
      </div>

      {/* Status Feedback Banner */}
      {statusMessage && (
        <div
          style={{
            padding: '10px 14px',
            borderRadius: '6px',
            fontSize: '0.82rem',
            fontWeight: 500,
            marginBottom: '14px',
            backgroundColor:
              statusMessage.type === 'success'
                ? '#DCFCE7'
                : statusMessage.type === 'info'
                ? '#E0F2FE'
                : '#FEE2E2',
            color:
              statusMessage.type === 'success'
                ? '#166534'
                : statusMessage.type === 'info'
                ? '#0369A1'
                : '#991B1B',
            border: `1px solid ${
              statusMessage.type === 'success'
                ? '#86EFAC'
                : statusMessage.type === 'info'
                ? '#7DD3FC'
                : '#FCA5A5'
            }`
          }}
        >
          {statusMessage.text}
        </div>
      )}

      {/* Threats List */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '24px', color: '#64748B', fontSize: '0.85rem' }}>
          Loading pending threats...
        </div>
      ) : pendingThreats.length === 0 ? (
        <div
          style={{
            backgroundColor: '#FFFFFF',
            border: '1px dashed #CBD5E1',
            borderRadius: '8px',
            padding: '28px',
            textAlign: 'center',
            color: '#64748B',
            fontSize: '0.88rem'
          }}
        >
          <div style={{ fontSize: '1.4rem', color: '#16A34A', marginBottom: '6px' }}>✓</div>
          <strong style={{ color: '#334155' }}>No Pending Approvals</strong>
          <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: '#94A3B8' }}>
            All threats with confidence ≤ 95% and all LOW/MEDIUM threats are automatically remediated by SOAR. Only threats with confidence &gt; 95% appear here.
          </p>
        </div>
      ) : (
        <div>
          {pendingThreats.map((threat) => (
            <ThreatCard
              key={threat.threat_id || threat.id}
              threat={threat}
              onApprove={(id) => handleSingleAction(id, 'approve')}
              onReject={(id) => handleSingleAction(id, 'reject')}
              isProcessing={isProcessing}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default PendingApprovals;
