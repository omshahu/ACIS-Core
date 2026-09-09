/**
 * ACIS-Core — Unified Frontend Configuration & Environment Resolver
 * Manages production cloud vs local development API resolution,
 * manual endpoint switching, and connection state persistence.
 */

const ACIS_CONFIG = {
    // Default production cloud backend (Render) and local development endpoint
    DEFAULT_PROD_API: 'https://acis-core-backend.onrender.com/api',
    DEFAULT_LOCAL_API: 'http://127.0.0.1:5001/api',

    /**
     * Resolves the active API base URL.
     * Priority:
     * 1. Explicit user override in localStorage ('acis_api_base')
     * 2. Localhost / loopback -> http://127.0.0.1:5001/api
     * 3. Cloud hosted (e.g. Vercel, Render) -> Production API URL
     */
    getApiBase() {
        const stored = localStorage.getItem('acis_api_base');
        if (stored && typeof stored === 'string' && stored.trim().length > 0) {
            return stored.trim().replace(/\/+$/, '');
        }

        const isLocal = typeof window !== 'undefined' && (
            window.location.hostname === 'localhost' ||
            window.location.hostname === '127.0.0.1' ||
            window.location.hostname.startsWith('192.168.') ||
            window.location.hostname.startsWith('10.') ||
            window.location.port === '5001'
        );

        if (isLocal) {
            return window.location.port === '5001' ? '/api' : this.DEFAULT_LOCAL_API;
        }

        return this.DEFAULT_PROD_API;
    },

    /**
     * Allows operator to override the target backend URL from the UI.
     */
    setApiBase(url) {
        if (!url || typeof url !== 'string' || !url.trim()) {
            localStorage.removeItem('acis_api_base');
        } else {
            let clean = url.trim().replace(/\/+$/, '');
            if (!clean.endsWith('/api') && !clean.includes('/api/')) {
                clean = `${clean}/api`;
            }
            localStorage.setItem('acis_api_base', clean);
        }
        window.dispatchEvent(new CustomEvent('acis:config-updated', { detail: { apiBase: this.getApiBase() } }));
    },

    /**
     * Resets backend target back to automatic detection.
     */
    resetApiBase() {
        localStorage.removeItem('acis_api_base');
        window.dispatchEvent(new CustomEvent('acis:config-updated', { detail: { apiBase: this.getApiBase() } }));
    },

    /**
     * Checks if current connection is targeting a remote cloud backend.
     */
    isCloud() {
        return !this.getApiBase().includes('127.0.0.1') && !this.getApiBase().includes('localhost');
    }
};

if (typeof window !== 'undefined') {
    window.ACIS_CONFIG = ACIS_CONFIG;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = ACIS_CONFIG;
}
