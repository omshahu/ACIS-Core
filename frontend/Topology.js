/**
 * ACIS-Core — Topology Component
 * Renders the 5 core architecture nodes with Solid State Health Dots (no spinners).
 * Health rule:
 *   - Green if Health Score > 95%
 *   - Yellow if 80-95%
 *   - Red if < 80%
 */

import React, { useRef, useEffect, useState, useMemo, useCallback } from 'react';
import './topology.css';

// Target Node Metadata & 2D Canvas Positions
const NODE_DEFINITIONS = {
  'waf-gateway': {
    id: 'waf-gateway',
    name: 'WAF Gateway',
    type: 'Perimeter Gateway',
    coords: { x: 120, y: 180 },
    icon: 'fa-shield-alt'
  },
  'telemetry-broker': {
    id: 'telemetry-broker',
    name: 'Telemetry Broker',
    type: 'Event Bus',
    coords: { x: 280, y: 80 },
    icon: 'fa-network-wired'
  },
  'core-ai-engine': {
    id: 'core-ai-engine',
    name: 'ACIS AI Core',
    type: 'AI Engine',
    coords: { x: 320, y: 220 },
    icon: 'fa-brain'
  },
  'trust-ledger-db': {
    id: 'trust-ledger-db',
    name: 'Trust Ledger DB',
    type: 'Ledger DB',
    coords: { x: 500, y: 100 },
    icon: 'fa-database'
  },
  'sandbox-env': {
    id: 'sandbox-env',
    name: 'Sandbox Env',
    type: 'Isolated Runtime',
    coords: { x: 500, y: 260 },
    icon: 'fa-flask'
  }
};

const CONNECTIONS = [
  ['waf-gateway', 'telemetry-broker'],
  ['telemetry-broker', 'core-ai-engine'],
  ['core-ai-engine', 'trust-ledger-db'],
  ['core-ai-engine', 'sandbox-env'],
  ['waf-gateway', 'core-ai-engine']
];

/**
 * Returns health classification and color for solid state dot
 * - Green if Health Score > 95%
 * - Yellow if 80-95%
 * - Red if < 80%
 */
export function getHealthStatus(healthValue) {
  const score = healthValue > 1 ? healthValue : healthValue * 100;
  if (score > 95) {
    return { class: 'green', color: '#10B981', label: 'Optimal', score: score.toFixed(1) };
  } else if (score >= 80) {
    return { class: 'yellow', color: '#F59E0B', label: 'Degraded', score: score.toFixed(1) };
  } else {
    return { class: 'red', color: '#EF4444', label: 'Critical', score: score.toFixed(1) };
  }
}

export function Topology({ nodes = {}, selectedNodeId, onSelectNode, isStreaming = true }) {
  const canvasRef = useRef(null);
  const [selectedId, setSelectedId] = useState(selectedNodeId || 'core-ai-engine');
  const animationFrameRef = useRef(null);

  // Particles for subtle data flow along connections
  const particlesRef = useRef(
    Array.from({ length: 8 }, () => {
      const conn = CONNECTIONS[Math.floor(Math.random() * CONNECTIONS.length)];
      return {
        from: conn[0],
        to: conn[1],
        progress: Math.random(),
        speed: 0.006 + Math.random() * 0.008
      };
    })
  );

  const handleNodeClick = (id) => {
    setSelectedId(id);
    if (onSelectNode) onSelectNode(id);
  };

  // Canvas drawing loop: Clean, solid nodes with NO spinning circle animations
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const render = () => {
      const w = canvas.width;
      const h = canvas.height;
      ctx.clearRect(0, 0, w, h);

      const scaleX = w / 640;
      const scaleY = h / 340;

      // 1. Draw Connection Lines
      CONNECTIONS.forEach(([fromId, toId]) => {
        const p1 = NODE_DEFINITIONS[fromId]?.coords;
        const p2 = NODE_DEFINITIONS[toId]?.coords;
        if (!p1 || !p2) return;

        const x1 = p1.x * scaleX;
        const y1 = p1.y * scaleY;
        const x2 = p2.x * scaleX;
        const y2 = p2.y * scaleY;

        ctx.strokeStyle = 'rgba(71, 85, 105, 0.45)';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();
      });

      // 2. Animate Data Packets
      if (isStreaming) {
        particlesRef.current.forEach((p) => {
          p.progress += p.speed;
          if (p.progress >= 1.0) {
            p.progress = 0;
            const nextConn = CONNECTIONS[Math.floor(Math.random() * CONNECTIONS.length)];
            p.from = nextConn[0];
            p.to = nextConn[1];
          }

          const p1 = NODE_DEFINITIONS[p.from]?.coords;
          const p2 = NODE_DEFINITIONS[p.to]?.coords;
          if (p1 && p2) {
            const px = (p1.x + (p2.x - p1.x) * p.progress) * scaleX;
            const py = (p1.y + (p2.y - p1.y) * p.progress) * scaleY;

            ctx.fillStyle = '#60A5FA';
            ctx.beginPath();
            ctx.arc(px, py, 3.5, 0, Math.PI * 2);
            ctx.fill();
          }
        });
      }

      // 3. Draw Topology Nodes with Solid State Dots
      Object.keys(NODE_DEFINITIONS).forEach((nodeId) => {
        const def = NODE_DEFINITIONS[nodeId];
        const liveData = nodes[nodeId] || { health: 0.98, status: 'operational', load: 25 };
        const healthStatus = getHealthStatus(liveData.health ?? 0.98);

        const nx = def.coords.x * scaleX;
        const ny = def.coords.y * scaleY;
        const isSelected = selectedId === nodeId;

        // Base Node Outer Disk
        ctx.fillStyle = isSelected ? 'rgba(59, 130, 246, 0.25)' : 'rgba(30, 41, 59, 0.9)';
        ctx.strokeStyle = isSelected ? '#3B82F6' : '#475569';
        ctx.lineWidth = isSelected ? 2.5 : 1.5;
        ctx.beginPath();
        ctx.arc(nx, ny, 22, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();

        // Inner Core Disk
        ctx.fillStyle = '#1E293B';
        ctx.beginPath();
        ctx.arc(nx, ny, 16, 0, Math.PI * 2);
        ctx.fill();

        // SOLID STATE HEALTH DOT (No Spinning Rings)
        // Green (>95%), Yellow (80-95%), Red (<80%)
        ctx.fillStyle = healthStatus.color;
        ctx.beginPath();
        ctx.arc(nx + 14, ny - 14, 5, 0, Math.PI * 2);
        ctx.fill();

        // Node Title Label
        ctx.fillStyle = '#F8FAFC';
        ctx.font = '600 11px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(def.name, nx, ny + 36);

        // Node Type Subtitle
        ctx.fillStyle = '#94A3B8';
        ctx.font = '400 9.5px Inter, sans-serif';
        ctx.fillText(def.type, nx, ny + 48);
      });

      animationFrameRef.current = requestAnimationFrame(render);
    };

    render();

    return () => {
      if (animationFrameRef.current) cancelAnimationFrame(animationFrameRef.current);
    };
  }, [nodes, selectedId, isStreaming]);

  const activeNodeData = nodes[selectedId] || {
    id: selectedId,
    name: NODE_DEFINITIONS[selectedId]?.name || selectedId,
    health: 0.98,
    status: 'operational',
    load: 30
  };
  const activeHealth = getHealthStatus(activeNodeData.health ?? 0.98);

  return (
    <div className="topology-container">
      <div className="topology-header">
        <div className="topology-title">
          <span>Infrastructure Topology</span>
          <div className="topology-stream-badge">
            <span className="health-dot green" />
            <span>2000ms SSE Live Stream</span>
          </div>
        </div>
        <div style={{ fontSize: '0.8rem', color: '#94A3B8' }}>
          <span>Solid State Indicators: </span>
          <span style={{ color: '#10B981', fontWeight: 600 }}>● &gt;95% </span>
          <span style={{ color: '#F59E0B', fontWeight: 600 }}>● 80-95% </span>
          <span style={{ color: '#EF4444', fontWeight: 600 }}>● &lt;80%</span>
        </div>
      </div>

      {/* Viewport Canvas */}
      <div className="topology-viewport">
        <canvas
          ref={canvasRef}
          width={640}
          height={340}
          className="topology-canvas"
          onClick={(e) => {
            const rect = e.currentTarget.getBoundingClientRect();
            const clickX = (e.clientX - rect.left) * (640 / rect.width);
            const clickY = (e.clientY - rect.top) * (340 / rect.height);
            Object.keys(NODE_DEFINITIONS).forEach((nId) => {
              const p = NODE_DEFINITIONS[nId].coords;
              if (Math.hypot(clickX - p.x, clickY - p.y) < 28) {
                handleNodeClick(nId);
              }
            });
          }}
        />
      </div>

      {/* 5 Architecture Node Cards */}
      <div className="nodes-grid">
        {Object.keys(NODE_DEFINITIONS).map((nodeId) => {
          const def = NODE_DEFINITIONS[nodeId];
          const data = nodes[nodeId] || { health: 0.98, status: 'operational', load: 25 };
          const hs = getHealthStatus(data.health ?? 0.98);
          const isSelected = selectedId === nodeId;

          return (
            <div
              key={nodeId}
              className={`node-card ${isSelected ? 'selected' : ''}`}
              onClick={() => handleNodeClick(nodeId)}
            >
              <div className="node-card-header">
                <span className="node-name">{def.name}</span>
                {/* Solid State Health Dot */}
                <span
                  className={`health-dot ${hs.class}`}
                  title={`Health: ${hs.score}% (${hs.label})`}
                />
              </div>
              <div className="node-id">{nodeId}</div>
              <div className="node-stats-row">
                <span>Health Score:</span>
                <span className={`node-health-score health-text-${hs.class}`}>
                  {hs.score}%
                </span>
              </div>
              <div className="node-stats-row">
                <span>Workload:</span>
                <span style={{ color: '#F1F5F9', fontWeight: 600 }}>{data.load || 25}%</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default Topology;
