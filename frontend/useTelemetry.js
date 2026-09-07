/**
 * ACIS-Core — useTelemetry Hook
 * Real-time SSE consumer with Lodash throttle (2000ms) to eliminate UI flickering.
 */

import { useState, useEffect, useRef, useCallback } from 'react';

// Attempt to import throttle from lodash; fallback to native throttle if lodash isn't installed
let lodashThrottle;
try {
  lodashThrottle = require('lodash/throttle');
} catch (e) {
  try {
    const _ = require('lodash');
    lodashThrottle = _?.throttle;
  } catch (err) {
    // Robust fallback implementation matching lodash throttle signature
    lodashThrottle = (func, wait = 2000, options = {}) => {
      let timeout = null;
      let previous = 0;
      return function (...args) {
        const now = Date.now();
        if (!previous && options.leading === false) previous = now;
        const remaining = wait - (now - previous);
        if (remaining <= 0 || remaining > wait) {
          if (timeout) {
            clearTimeout(timeout);
            timeout = null;
          }
          previous = now;
          func.apply(this, args);
        } else if (!timeout && options.trailing !== false) {
          timeout = setTimeout(() => {
            previous = options.leading === false ? 0 : Date.now();
            timeout = null;
            func.apply(this, args);
          }, remaining);
        }
      };
    };
  }
}

const DEFAULT_API_BASE = typeof window !== 'undefined' && window.location.port === '5001'
  ? '/api'
  : 'http://127.0.0.1:5001/api';

export function useTelemetry(apiBase = DEFAULT_API_BASE, throttleInterval = 2000) {
  const [telemetry, setTelemetry] = useState(null);
  const [nodes, setNodes] = useState({
    'core-ai-engine': { id: 'core-ai-engine', name: 'ACIS AI Core', type: 'ai_core', status: 'operational', health: 0.98 },
    'waf-gateway': { id: 'waf-gateway', name: 'WAF Gateway', type: 'gateway', status: 'operational', health: 0.97 },
    'trust-ledger-db': { id: 'trust-ledger-db', name: 'Trust Ledger DB', type: 'database', status: 'operational', health: 0.99 },
    'telemetry-broker': { id: 'telemetry-broker', name: 'Telemetry Broker', type: 'broker', status: 'operational', health: 0.96 },
    'sandbox-env': { id: 'sandbox-env', name: 'Sandbox Env', type: 'sandbox', status: 'operational', health: 0.98 }
  });
  const [metrics, setMetrics] = useState({
    accuracy: 97.4,
    precision: 95.1,
    recall: 96.8,
    f1_score: 95.9,
    threats_blocked: 142,
    total_decisions: 150,
    network_health: 0.974,
    threat_level: 'LOW',
    cpu_usage: 28.5,
    memory_usage: 42.0,
    risk_score: 12
  });
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  const [lastUpdated, setLastUpdated] = useState(null);
  const [error, setError] = useState(null);

  const eventSourceRef = useRef(null);

  // Throttled state update handler to strictly limit re-render frequency to 2000ms
  const throttledUpdate = useRef(
    lodashThrottle((data) => {
      if (!data) return;
      setTelemetry(data);
      if (data.nodes) setNodes(data.nodes);
      if (data.metrics) setMetrics(data.metrics);
      setLastUpdated(new Date().toLocaleTimeString());
    }, throttleInterval, { leading: true, trailing: true })
  ).current;

  // Fallback Polling if EventSource is unsupported or blocked
  const fallbackPoll = useCallback(async () => {
    try {
      const res = await fetch(`${apiBase}/twin/state`);
      const json = await res.json();
      if (json.success && json.twin_state) {
        throttledUpdate(json.twin_state);
        setConnectionStatus('polling');
      }
    } catch (err) {
      setConnectionStatus('disconnected');
      setError(err.message);
    }
  }, [apiBase, throttledUpdate]);

  useEffect(() => {
    let sseUrl = `${apiBase}/twin/stream`;
    let isMounted = true;

    try {
      const es = new EventSource(sseUrl);
      eventSourceRef.current = es;

      es.onopen = () => {
        if (!isMounted) return;
        setConnectionStatus('connected');
        setError(null);
      };

      es.onmessage = (event) => {
        if (!isMounted) return;
        try {
          const parsed = JSON.parse(event.data);
          throttledUpdate(parsed);
        } catch (e) {
          console.warn('[useTelemetry] SSE JSON parse error:', e);
        }
      };

      es.onerror = () => {
        if (!isMounted) return;
        setConnectionStatus('reconnecting');
        // Trigger fallback poll while reconnecting
        fallbackPoll();
      };
    } catch (err) {
      console.warn('[useTelemetry] EventSource connection failed, starting fallback polling:', err);
      setConnectionStatus('polling');
      const pollTimer = setInterval(fallbackPoll, throttleInterval);
      return () => clearInterval(pollTimer);
    }

    return () => {
      isMounted = false;
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      if (throttledUpdate && throttledUpdate.cancel) {
        throttledUpdate.cancel();
      }
    };
  }, [apiBase, throttleInterval, throttledUpdate, fallbackPoll]);

  return {
    telemetry,
    nodes,
    metrics,
    connectionStatus,
    lastUpdated,
    error,
    refresh: fallbackPoll
  };
}

export default useTelemetry;
