/**
 * ACIS-Core — Dashboard Component (Digital Twin & Autonomous SOAR Engine)
 * - Defaults simulation mode to "normal" (does NOT artificially inflate attack_probability).
 * - Integrates real-time SSE telemetry, metrics, topology, scenario simulation, and pending approvals.
 * - Light grey theme (#F1F5F9 surface, #FFFFFF panels, #64748B accent).
 */

import React, { useState, useCallback, useEffect } from 'react';
import { useTelemetry } from './useTelemetry';
import { Topology } from './Topology';
import { MetricsCard } from './MetricsCard';
import { ScenarioSelector } from './ScenarioSelector';
import { PendingApprovals } from './PendingApprovals';
import './topology.css';

const DEFAULT_API_BASE = typeof window !== 'undefined' && window.location.port === '5001'
  ? '/api'
  : 'http://127.0.0.1:5001/api';

export function Dashboard({ apiBase = DEFAULT_API_BASE }) {
  const { telemetry, nodes, metrics, connectionStatus, lastUpdated } = useTelemetry();
  const [selectedNode, setSelectedNode] = useState('core-ai-engine');
  
  // Requirement 3: Simulation dropdown strictly defaults to "normal"
  const [simulationMode, setSimulationMode] = useState('normal');
  const [threatAnalysis, setThreatAnalysis] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Requirement 2: Dashboard Threat Counts
  // - "Threats Blocked" includes all auto-remediated threats (LOW, MEDIUM, and HIGH/CRITICAL with confidence <= 95%)
  // - "Pending Human Approval" only shows threats with confidence > 95% and severity HIGH/CRITICAL
  const [threatCounts, setThreatCounts] = useState({
    threatsBlocked: 0,
    pendingApproval: 0,
    totalThreats: 0,
    alerts: 0
  });

  const fetchThreatCounts = useCallback(async () => {
    try {
      const [statusRes, pendingRes] = await Promise.all([
        fetch(`${apiBase}/monitoring/status`),
        fetch(`${apiBase}/pending-threats`)
      ]);
      const statusData = await statusRes.json();
      const pendingData = await pendingRes.json();

      // Filter pending list strictly for confidence > 95% and severity HIGH/CRITICAL
      const validPending = (pendingData.pending || []).filter((t) => {
        const sev = String(t.severity || '').toUpperCase();
        if (sev !== 'HIGH' && sev !== 'CRITICAL') return false;
        const rawConf = t.confidence ?? t.threat_data?.details?.confidence ?? t.threat_data?.confidence ?? t.details?.confidence;
        if (rawConf === undefined || rawConf === null) return false;
        const confNum = Number(rawConf);
        const confFraction = confNum > 1 ? confNum / 100 : confNum;
        return confFraction > 0.95;
      });

      // Threats Blocked includes all auto-remediated threats
      // (LOW, MEDIUM, and HIGH/CRITICAL with confidence <= 95%)
      const autoRemediatedCount = statusData.auto_fixes ?? statusData.threats_blocked ?? 0;

      setThreatCounts({
        threatsBlocked: autoRemediatedCount,
        pendingApproval: validPending.length,
        totalThreats: statusData.threats_detected ?? 0,
        alerts: statusData.alerts ?? 0
      });
    } catch (err) {
      console.warn('[Dashboard] Failed to fetch threat counts:', err);
    }
  }, [apiBase]);

  useEffect(() => {
    fetchThreatCounts();
    const interval = setInterval(fetchThreatCounts, 4000);
    return () => clearInterval(interval);
  }, [fetchThreatCounts]);

  // Run threat detection with current simulation mode (normal defaults to unadulterated model predictions)
  const handleDetectThreat = useCallback(async () => {
    setIsAnalyzing(true);
    try {
      const res = await fetch(`${apiBase}/threat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: simulationMode })
      });
      const data = await res.json();
      if (data.success) {
        setThreatAnalysis(data);
        fetchThreatCounts();
      }
    } catch (err) {
      console.warn('[Dashboard] Threat analysis error:', err);
    } finally {
      setIsAnalyzing(false);
    }
  }, [apiBase, simulationMode, fetchThreatCounts]);

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '24px', fontFamily: "'Inter', -apple-system, sans-serif" }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, color: '#0F172A', margin: 0 }}>
            ACIS-Core Autonomous Defense Dashboard
          </h1>
          <p style={{ color: '#64748B', fontSize: '0.875rem', marginTop: '4px' }}>
            Real-Time Cyber Digital Twin & Autonomous SOAR Engine
          </p>
        </div>

        {/* Connection Status Badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="topology-stream-badge">
            <span
              className={`health-dot ${
                connectionStatus === 'connected' ? 'green' : connectionStatus === 'polling' ? 'yellow' : 'red'
              }`}
            />
            <span style={{ textTransform: 'capitalize' }}>
              {connectionStatus === 'connected' ? 'SSE Live Stream (2000ms)' : connectionStatus}
            </span>
          </div>
          {lastUpdated && (
            <span style={{ fontSize: '0.75rem', color: '#64748B' }}>
              Updated: {lastUpdated}
            </span>
          )}
        </div>
      </div>

      {/* Simulation Controls Toolbar (Defaults to "normal") */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          backgroundColor: '#FFFFFF',
          border: '1px solid #E2E8F0',
          borderRadius: '10px',
          padding: '12px 18px',
          marginBottom: '20px',
          boxShadow: '0 1px 3px rgba(0, 0, 0, 0.04)',
          flexWrap: 'wrap',
          gap: '12px'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <label
            htmlFor="dashboard-sim-mode"
            style={{ fontSize: '0.85rem', fontWeight: 600, color: '#334155' }}
          >
            Simulation Mode:
          </label>
          <select
            id="dashboard-sim-mode"
            value={simulationMode}
            onChange={(e) => setSimulationMode(e.target.value)}
            style={{
              padding: '6px 12px',
              borderRadius: '6px',
              border: '1px solid #CBD5E1',
              backgroundColor: '#F8FAFC',
              fontSize: '0.85rem',
              color: '#0F172A',
              fontWeight: 500,
              cursor: 'pointer'
            }}
          >
            <option value="normal">Normal (Production Baseline)</option>
            <option value="low_attack">Low Attack Simulation (&lt; 0.40)</option>
            <option value="medium_attack">Medium Attack Simulation (0.40 – 0.70)</option>
            <option value="severe_attack">Severe Attack Simulation (&gt; 0.90)</option>
          </select>
          <span style={{ fontSize: '0.75rem', color: '#64748B' }}>
            {simulationMode === 'normal'
              ? '✓ Live model inference without artificial probability inflation'
              : '⚡ Simulation mode active'}
          </span>
        </div>

        <button
          onClick={handleDetectThreat}
          disabled={isAnalyzing}
          style={{
            backgroundColor: '#3B82F6',
            color: '#FFFFFF',
            border: 'none',
            borderRadius: '6px',
            padding: '7px 16px',
            fontSize: '0.82rem',
            fontWeight: 600,
            cursor: isAnalyzing ? 'wait' : 'pointer',
            boxShadow: '0 1px 2px rgba(0,0,0,0.05)'
          }}
        >
          {isAnalyzing ? 'Analyzing...' : 'Run Threat Detection'}
        </button>
      </div>

      {/* Latest Analysis Result Banner (if triggered) */}
      {threatAnalysis && (
        <div
          style={{
            backgroundColor: '#FFFFFF',
            border: '1px solid #E2E8F0',
            borderRadius: '10px',
            padding: '14px 18px',
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '12px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span
              style={{
                backgroundColor:
                  threatAnalysis.severity === 'CRITICAL'
                    ? '#FEE2E2'
                    : threatAnalysis.severity === 'HIGH'
                    ? '#FFEDD5'
                    : threatAnalysis.severity === 'MEDIUM'
                    ? '#FEF9C3'
                    : '#DCFCE7',
                color:
                  threatAnalysis.severity === 'CRITICAL'
                    ? '#DC2626'
                    : threatAnalysis.severity === 'HIGH'
                    ? '#EA580C'
                    : threatAnalysis.severity === 'MEDIUM'
                    ? '#CA8A04'
                    : '#16A34A',
                border: `1px solid ${
                  threatAnalysis.severity === 'CRITICAL'
                    ? '#FCA5A5'
                    : threatAnalysis.severity === 'HIGH'
                    ? '#FDBA74'
                    : threatAnalysis.severity === 'MEDIUM'
                    ? '#FDE047'
                    : '#86EFAC'
                }`,
                padding: '4px 10px',
                borderRadius: '16px',
                fontSize: '0.75rem',
                fontWeight: 700
              }}
            >
              ● {threatAnalysis.severity}
            </span>
            <span style={{ fontSize: '0.85rem', color: '#334155' }}>
              Attack Probability:{' '}
              <strong>{(threatAnalysis.attack_probability * 100).toFixed(1)}%</strong>
            </span>
            <span style={{ fontSize: '0.85rem', color: '#334155' }}>
              Model Confidence: <strong>{threatAnalysis.confidence_display || `${(threatAnalysis.confidence).toFixed(1)}%`}</strong>
            </span>
          </div>
          <span style={{ fontSize: '0.8rem', color: '#64748B' }}>
            {threatAnalysis.alert ? '🚨 Alert Logged (Admin Approval Required)' : '🔧 Auto-Remediated Silently (No Alert)'}
          </span>
        </div>
      )}

      {/* SOAR Threat Summary KPI Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '16px',
          marginBottom: '20px'
        }}
      >
        {/* Card 1: Threats Blocked (Auto-Remediated) */}
        <div
          style={{
            backgroundColor: '#FFFFFF',
            border: '1px solid #E2E8F0',
            borderRadius: '10px',
            padding: '16px 20px',
            boxShadow: '0 1px 3px rgba(0, 0, 0, 0.04)'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#16A34A', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Threats Blocked
            </span>
            <span style={{ fontSize: '1.2rem' }}>🛡️</span>
          </div>
          <div style={{ fontSize: '1.85rem', fontWeight: 800, color: '#0F172A' }}>
            {threatCounts.threatsBlocked}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748B', marginTop: '4px' }}>
            Auto-remediated (LOW, MEDIUM &amp; ≤95% confidence)
          </div>
        </div>

        {/* Card 2: Pending Human Approval */}
        <div
          style={{
            backgroundColor: '#FFFFFF',
            border: '1px solid #E2E8F0',
            borderRadius: '10px',
            padding: '16px 20px',
            boxShadow: '0 1px 3px rgba(0, 0, 0, 0.04)'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#DC2626', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Pending Human Approval
            </span>
            <span style={{ fontSize: '1.2rem' }}>⚠️</span>
          </div>
          <div style={{ fontSize: '1.85rem', fontWeight: 800, color: threatCounts.pendingApproval > 0 ? '#DC2626' : '#0F172A' }}>
            {threatCounts.pendingApproval}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748B', marginTop: '4px' }}>
            HIGH &amp; CRITICAL threats with confidence &gt; 95%
          </div>
        </div>

        {/* Card 3: Total Threats Scanned */}
        <div
          style={{
            backgroundColor: '#FFFFFF',
            border: '1px solid #E2E8F0',
            borderRadius: '10px',
            padding: '16px 20px',
            boxShadow: '0 1px 3px rgba(0, 0, 0, 0.04)'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#2563EB', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Total Threats Detected
            </span>
            <span style={{ fontSize: '1.2rem' }}>🔍</span>
          </div>
          <div style={{ fontSize: '1.85rem', fontWeight: 800, color: '#0F172A' }}>
            {threatCounts.totalThreats}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748B', marginTop: '4px' }}>
            Continuously scanned network events
          </div>
        </div>

        {/* Card 4: Active Alerts */}
        <div
          style={{
            backgroundColor: '#FFFFFF',
            border: '1px solid #E2E8F0',
            borderRadius: '10px',
            padding: '16px 20px',
            boxShadow: '0 1px 3px rgba(0, 0, 0, 0.04)'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#D97706', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Active Alerts
            </span>
            <span style={{ fontSize: '1.2rem' }}>🚨</span>
          </div>
          <div style={{ fontSize: '1.85rem', fontWeight: 800, color: '#0F172A' }}>
            {threatCounts.alerts}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748B', marginTop: '4px' }}>
            Triggered only for pending approvals
          </div>
        </div>
      </div>

      {/* Dynamic Floating Metrics Card (Never 100%) */}
      <MetricsCard metrics={metrics} threatsBlocked={threatCounts.threatsBlocked} />

      {/* 4 Plain-English Digital Twin Scenarios Selector */}
      <ScenarioSelector currentScenario={metrics.scenario || 'Normal Operation (Baseline)'} />

      {/* Infrastructure Topology with Solid State Health Dots */}
      <div style={{ marginBottom: '24px' }}>
        <Topology
          nodes={nodes}
          selectedNodeId={selectedNode}
          onSelectNode={(id) => setSelectedNode(id)}
        />
      </div>

      {/* SOAR: Pending Human Approval with Colored Badges & Bulk Actions */}
      <PendingApprovals apiBase={apiBase} onRefreshNeeded={fetchThreatCounts} />
    </div>
  );
}

export default Dashboard;
