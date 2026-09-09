/**
 * ACIS-Core — TelemetryService
 * Production-ready EventSource SSE client for 24/7 continuous live streaming with:
 * - Auto-reconnect with exponential backoff and jitter
 * - Connection status state machine: 'connecting' | 'connected' | 'disconnected' | 'max-retries'
 * - Dead stream watchdog / heartbeat liveness check
 * - Page Visibility API (immediately reconnects/resumes when tab becomes active / phone unlocked)
 * - Network online/offline event detection
 */

export class TelemetryService {
  constructor(options = {}) {
    // Resolve default endpoint based on environment
    const defaultBase = typeof window !== 'undefined' && window.location.port === '5001'
      ? '/api'
      : 'http://127.0.0.1:5001/api';

    this.endpoint = options.endpoint || `${options.apiBase || defaultBase}/telemetry/stream`;
    this.initialDelay = options.initialDelay || 1000;        // 1s starting delay
    this.maxDelay = options.maxDelay || 30000;              // 30s maximum backoff
    this.backoffMultiplier = options.backoffMultiplier || 1.5;
    this.maxRetries = options.maxRetries || 10;             // Max attempts before switching to 'max-retries'
    this.watchdogTimeout = options.watchdogTimeout || 10000; // 10s watchdog (2s stream expected)

    // State
    this.status = 'disconnected'; // 'connecting' | 'connected' | 'disconnected' | 'max-retries'
    this.retries = 0;
    this.lastMessageTime = 0;
    this.eventSource = null;
    this.reconnectTimer = null;
    this.watchdogTimer = null;
    this.isManualDisconnect = false;

    // Listeners
    this.dataListeners = new Set();
    this.statusListeners = new Set();
    this.errorListeners = new Set();

    // Bind event handlers for page visibility and network connectivity
    this.handleVisibilityChange = this.handleVisibilityChange.bind(this);
    this.handleOnline = this.handleOnline.bind(this);
    this.handleOffline = this.handleOffline.bind(this);

    this.initBrowserEvents();
  }

  /**
   * Set up browser-level lifecycle hooks (Page Visibility API & Network events)
   */
  initBrowserEvents() {
    if (typeof window === 'undefined' || typeof document === 'undefined') return;

    document.addEventListener('visibilitychange', this.handleVisibilityChange);
    window.addEventListener('online', this.handleOnline);
    window.addEventListener('offline', this.handleOffline);
  }

  /**
   * Clean up browser event listeners
   */
  destroyBrowserEvents() {
    if (typeof window === 'undefined' || typeof document === 'undefined') return;

    document.removeEventListener('visibilitychange', this.handleVisibilityChange);
    window.removeEventListener('online', this.handleOnline);
    window.removeEventListener('offline', this.handleOffline);
  }

  /**
   * Page Visibility API handler:
   * When user switches back to the tab or unlocks their phone screen,
   * immediately verify connection health and reconnect if stale or disconnected.
   */
  handleVisibilityChange() {
    if (document.visibilityState === 'visible') {
      const now = Date.now();
      const isStale = (now - this.lastMessageTime) > (this.watchdogTimeout - 2000);

      if (this.status === 'disconnected' || this.status === 'max-retries' || isStale) {
        console.log('[TelemetryService] Tab became visible. Re-establishing live telemetry stream...');
        this.reconnect(true);
      }
    }
  }

  /**
   * Network online handler:
   * Instantly re-establishes SSE stream when device regains connectivity.
   */
  handleOnline() {
    console.log('[TelemetryService] Network online detected. Reconnecting stream...');
    this.reconnect(true);
  }

  /**
   * Network offline handler
   */
  handleOffline() {
    console.warn('[TelemetryService] Network offline detected.');
    this.setStatus('disconnected');
    this.cleanupEventSource();
  }

  /**
   * Update internal status and notify subscribers
   */
  setStatus(newStatus) {
    if (this.status === newStatus) return;
    this.status = newStatus;
    this.statusListeners.forEach((fn) => {
      try {
        fn(this.status, { retries: this.retries, maxRetries: this.maxRetries });
      } catch (err) {
        console.error('[TelemetryService] Status listener error:', err);
      }
    });
  }

  /**
   * Initiate SSE connection with EventSource
   */
  connect() {
    if (typeof window === 'undefined' || typeof EventSource === 'undefined') {
      console.warn('[TelemetryService] EventSource is not supported in this environment.');
      this.setStatus('disconnected');
      return;
    }

    // Prevent duplicate connection attempts
    if (this.eventSource && (this.status === 'connected' || this.status === 'connecting')) {
      return;
    }

    this.isManualDisconnect = false;
    this.cleanupTimers();
    this.setStatus('connecting');

    try {
      this.eventSource = new EventSource(this.endpoint);

      this.eventSource.onopen = () => {
        console.log(`[TelemetryService] Connected to SSE live stream (${this.endpoint})`);
        this.retries = 0;
        this.lastMessageTime = Date.now();
        this.setStatus('connected');
        this.startWatchdog();
      };

      this.eventSource.onmessage = (event) => {
        this.lastMessageTime = Date.now();

        // If status was somehow not connected, update to connected
        if (this.status !== 'connected') {
          this.retries = 0;
          this.setStatus('connected');
        }

        try {
          const data = JSON.parse(event.data);
          this.notifyData(data);
        } catch (err) {
          console.warn('[TelemetryService] SSE payload parse error:', err, event.data);
        }
      };

      this.eventSource.onerror = (err) => {
        if (this.isManualDisconnect) return;

        this.notifyError(err);
        this.cleanupEventSource();

        // Check retry thresholds
        if (this.retries >= this.maxRetries) {
          console.warn(`[TelemetryService] Reached maximum retries (${this.maxRetries}). Switching to max-retries.`);
          this.setStatus('max-retries');
        } else {
          this.setStatus('connecting');
          this.scheduleReconnect();
        }
      };
    } catch (err) {
      console.error('[TelemetryService] EventSource initialization failed:', err);
      this.notifyError(err);
      this.scheduleReconnect();
    }
  }

  /**
   * Schedule reconnect with exponential backoff and jitter
   */
  scheduleReconnect() {
    this.cleanupTimers();

    if (this.isManualDisconnect) return;

    this.retries += 1;
    if (this.retries > this.maxRetries) {
      this.setStatus('max-retries');
      return;
    }

    // Exponential backoff: initialDelay * (backoffMultiplier ^ retries) + random jitter
    const backoff = this.initialDelay * Math.pow(this.backoffMultiplier, this.retries - 1);
    const jitter = Math.floor(Math.random() * 500);
    const delay = Math.min(this.maxDelay, Math.floor(backoff + jitter));

    console.log(`[TelemetryService] Reconnecting in ${delay}ms (attempt ${this.retries}/${this.maxRetries})...`);

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  /**
   * Watchdog timer to detect stalled / dead SSE connections
   */
  startWatchdog() {
    this.stopWatchdog();
    this.watchdogTimer = setInterval(() => {
      if (this.status === 'connected') {
        const elapsed = Date.now() - this.lastMessageTime;
        if (elapsed > this.watchdogTimeout) {
          console.warn(`[TelemetryService] Dead connection watchdog triggered (${elapsed}ms since last packet). Reconnecting...`);
          this.reconnect(false);
        }
      }
    }, 4000);
  }

  stopWatchdog() {
    if (this.watchdogTimer) {
      clearInterval(this.watchdogTimer);
      this.watchdogTimer = null;
    }
  }

  /**
   * Force an immediate reconnection
   * @param {boolean} resetRetries - Whether to clear the retry counter
   */
  reconnect(resetRetries = false) {
    if (resetRetries) {
      this.retries = 0;
    }
    this.cleanupEventSource();
    this.cleanupTimers();
    this.connect();
  }

  /**
   * Explicitly disconnect from the SSE stream
   */
  disconnect() {
    this.isManualDisconnect = true;
    this.cleanupEventSource();
    this.cleanupTimers();
    this.setStatus('disconnected');
  }

  cleanupEventSource() {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    this.stopWatchdog();
  }

  cleanupTimers() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.stopWatchdog();
  }

  /**
   * Subscription APIs
   */
  subscribe(callback) {
    this.dataListeners.add(callback);
    return () => this.dataListeners.delete(callback);
  }

  onStatusChange(callback) {
    this.statusListeners.add(callback);
    // Immediately call with current status
    callback(this.status, { retries: this.retries, maxRetries: this.maxRetries });
    return () => this.statusListeners.delete(callback);
  }

  onError(callback) {
    this.errorListeners.add(callback);
    return () => this.errorListeners.delete(callback);
  }

  notifyData(data) {
    this.dataListeners.forEach((fn) => {
      try {
        fn(data);
      } catch (err) {
        console.error('[TelemetryService] Subscriber data callback error:', err);
      }
    });
  }

  notifyError(err) {
    this.errorListeners.forEach((fn) => {
      try {
        fn(err);
      } catch (e) {
        console.error('[TelemetryService] Subscriber error callback error:', e);
      }
    });
  }

  /**
   * Teardown entire service instance
   */
  destroy() {
    this.disconnect();
    this.destroyBrowserEvents();
    this.dataListeners.clear();
    this.statusListeners.clear();
    this.errorListeners.clear();
  }
}

// Export singleton instance as default or class as named
let defaultInstance = null;
export function getTelemetryService(options) {
  if (!defaultInstance) {
    defaultInstance = new TelemetryService(options);
  }
  return defaultInstance;
}

export default TelemetryService;
