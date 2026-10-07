'use strict';

// ════════════════════════════════════════════════════════════════════
//  Shared HTTP helpers — loaded once per page, used by all modules
// ════════════════════════════════════════════════════════════════════
(function() {
    async function apiGet(url) {
        const r = await fetch(url);
        if (!r.ok) throw new Error(await r.text());
        return r.json();
    }

    async function apiPost(url, body) {
        const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        // Handle non-JSON responses (e.g., HTML 500 errors)
        const contentType = r.headers.get('content-type') || '';
        let data;
        if (contentType.includes('application/json')) {
            data = await r.json();
        } else {
            const text = await r.text();
            throw new Error(r.ok ? 'Unexpected response' : `Server error (${r.status}): ${text.substring(0, 200)}`);
        }
        if (!r.ok) throw new Error(data.error || 'Request failed');
        return data;
    }

// Make available globally for inline scripts & app.js (also on App namespace)
globalThis.apiGet  = apiGet;
globalThis.apiPost = apiPost;

// Expose to global App namespace so other modules can call them
window.App = Object.assign(window.App || {}, { apiGet, apiPost });
})();
