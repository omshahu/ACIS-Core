/**
 * ACIS-Core — StatusBadge Component
 * Displays real-time SSE stream connection status with:
 * - Four visual states: 'connected' | 'connecting' | 'disconnected' | 'max-retries'
 * - Pulsating live dot indicator
 * - Dedicated Reconnect/Retry button when disconnected or max-retries reached
 * - Responsive 24/7 monitoring display for mobile phones and PC
 */

import React, { useState } from 'react';

export function StatusBadge({
  status = 'connecting',
  onReconnect,
  lastUpdated,
  retryCount = 0,
  compact = false,
  className = '',
  style = {}
}) {
  const [isHovered, setIsHovered] = useState(false);
  const [isClicking, setIsClicking] = useState(false);

  // Configuration for each connection status state
  const config = {
    connected: {
      bg: 'rgba(16, 185, 129, 0.10)',
      border: '1px solid rgba(16, 185, 129, 0.35)',
      color: '#059669',
      dotColor: '#10B981',
      pulseColor: 'rgba(16, 185, 129, 0.45)',
      label: compact ? 'Live' : 'Live Stream (2s)',
      icon: null,
      showButton: false
    },
    connecting: {
      bg: 'rgba(245, 158, 11, 0.10)',
      border: '1px solid rgba(245, 158, 11, 0.35)',
      color: '#D97706',
      dotColor: '#F59E0B',
      pulseColor: 'rgba(245, 158, 11, 0.45)',
      label: retryCount > 0
        ? (compact ? `Retry #${retryCount}` : `Connecting (Attempt ${retryCount})...`)
        : (compact ? 'Connecting' : 'Connecting...'),
      icon: 'sync',
      showButton: false
    },
    disconnected: {
      bg: 'rgba(239, 68, 68, 0.10)',
      border: '1px solid rgba(239, 68, 68, 0.35)',
      color: '#DC2626',
      dotColor: '#EF4444',
      pulseColor: 'rgba(239, 68, 68, 0.30)',
      label: compact ? 'Offline' : 'Disconnected',
      icon: null,
      showButton: true,
      buttonLabel: 'Reconnect'
    },
    'max-retries': {
      bg: 'rgba(220, 38, 38, 0.15)',
      border: '1px solid rgba(220, 38, 38, 0.50)',
      color: '#B91C1C',
      dotColor: '#DC2626',
      pulseColor: 'rgba(220, 38, 38, 0.40)',
      label: compact ? 'Max Retries' : 'Stream Offline (Max Retries)',
      icon: 'alert',
      showButton: true,
      buttonLabel: 'Retry Now'
    }
  };

  const current = config[status] || config.disconnected;

  const handleReconnect = (e) => {
    e.stopPropagation();
    setIsClicking(true);
    setTimeout(() => setIsClicking(false), 500);
    if (onReconnect) {
      onReconnect();
    }
  };

  return (
    <div
      className={`acis-status-badge ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '8px',
        padding: compact ? '4px 10px' : '6px 14px',
        borderRadius: '9999px',
        backgroundColor: current.bg,
        border: current.border,
        color: current.color,
        fontFamily: "'Inter', system-ui, -apple-system, sans-serif",
        fontSize: compact ? '0.75rem' : '0.82rem',
        fontWeight: 600,
        boxShadow: '0 1px 2px rgba(0, 0, 0, 0.04)',
        transition: 'all 0.25s ease-in-out',
        userSelect: 'none',
        ...style
      }}
      title={`Live Stream Status: ${status}${lastUpdated ? ` | Updated: ${lastUpdated}` : ''}`}
    >
      {/* Dynamic Pulsating Status Indicator */}
      <span
        style={{
          position: 'relative',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: '8px',
          height: '8px'
        }}
      >
        {status === 'connected' && (
          <span
            style={{
              position: 'absolute',
              width: '16px',
              height: '16px',
              borderRadius: '50%',
              backgroundColor: current.pulseColor,
              animation: 'acisPulse 2s cubic-bezier(0, 0, 0.2, 1) infinite'
            }}
          />
        )}
        <span
          style={{
            position: 'relative',
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: current.dotColor,
            boxShadow: `0 0 6px ${current.dotColor}`
          }}
        />
      </span>

      {/* Label Text */}
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', lineHeight: 1 }}>
        {status === 'max-retries' && <span style={{ fontSize: '0.9rem' }}>⚠️</span>}
        <span>{current.label}</span>
      </span>

      {/* Timestamp tooltip / display if present */}
      {!compact && lastUpdated && status === 'connected' && (
        <span
          style={{
            fontSize: '0.72rem',
            color: '#64748B',
            fontWeight: 400,
            marginLeft: '2px',
            opacity: 0.85
          }}
        >
          {lastUpdated}
        </span>
      )}

      {/* Reconnect / Retry Button */}
      {current.showButton && (
        <button
          type="button"
          onClick={handleReconnect}
          onMouseEnter={() => setIsHovered(true)}
          onMouseLeave={() => setIsHovered(false)}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '4px',
            marginLeft: '4px',
            padding: '3px 9px',
            backgroundColor: isHovered ? current.color : '#FFFFFF',
            color: isHovered ? '#FFFFFF' : current.color,
            border: `1px solid ${current.color}`,
            borderRadius: '6px',
            fontSize: '0.72rem',
            fontWeight: 700,
            cursor: 'pointer',
            transform: isClicking ? 'scale(0.95)' : 'scale(1)',
            transition: 'all 0.15s ease',
            outline: 'none'
          }}
          title="Force immediate reconnection to telemetry stream"
        >
          <span
            style={{
              display: 'inline-block',
              transform: isClicking ? 'rotate(180deg)' : 'none',
              transition: 'transform 0.3s ease'
            }}
          >
            ↻
          </span>
          <span>{current.buttonLabel}</span>
        </button>
      )}

      {/* CSS Pulse Animation Keyframes */}
      <style>{`
        @keyframes acisPulse {
          0% {
            transform: scale(0.95);
            opacity: 0.8;
          }
          70% {
            transform: scale(2.2);
            opacity: 0;
          }
          100% {
            transform: scale(2.4);
            opacity: 0;
          }
        }
      `}</style>
    </div>
  );
}

export default StatusBadge;
