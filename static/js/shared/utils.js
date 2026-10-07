'use strict';

// ════════════════════════════════════════════════════════════════════
//  Shared utility functions — loaded before any other module.
//  Provides basic DOM helpers and formatting used across all modules.
// ════════════════════════════════════════════════════════════════════

(function() {
    // ── Basic DOM helpers (used everywhere) ────────────────────────
    function show(id) { document.getElementById(id).style.display = ''; }
    function hide(id) { document.getElementById(id).style.display = 'none'; }

    // ── HTML escaping ──────────────────────────────────────────────
    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    // ── File size formatting ───────────────────────────────────────
    function humanSize(bytes) {
        if (bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        const v = bytes / Math.pow(1024, i);
        return v.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
    }

    // ── Relative time formatting ───────────────────────────────────
    function relTime(iso) {
        if (!iso) return '';
        try { var d = new Date(iso); } catch { return iso; }
        if (isNaN(d.getTime())) return iso;
        const now = new Date();
        const diff = (now - d) / 1000;
        if (diff < 60) return 'just now';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
        return d.toLocaleDateString();
    }

    // ── File icon class mapping ────────────────────────────────────
    function getIconClass(f) {
        if (f.is_directory) return { icon: 'fa-folder', cls: 'folder' };
        const m = (f.mime_type || '').toLowerCase();
        const n = (f.name || '').toLowerCase();
        if (m.startsWith('video/')) return { icon: 'fa-file-video', cls: 'video' };
        if (m.startsWith('audio/')) return { icon: 'fa-file-audio', cls: 'audio' };
        if (m.startsWith('image/')) return { icon: 'fa-file-image', cls: 'image' };
        if (m === 'application/pdf') return { icon: 'fa-file-pdf', cls: 'pdf' };
        if (m.startsWith('text/')) return { icon: 'fa-file-lines', cls: 'text' };
        if (/\.(zip|rar|7z|tar|gz)$/i.test(n)) return { icon: 'fa-file-zipper', cls: 'archive' };
        return { icon: 'fa-file', cls: 'other' };
    }

    // ── Bootstrap modal helper ─────────────────────────────────────
    function bootstrapModal(id) {
        return bootstrap.Modal.getOrCreateInstance(document.getElementById(id));
    }

    // Expose everything globally (used by all other modules directly or via App namespace)
    globalThis.show = show;
    globalThis.hide = hide;
    globalThis.esc = esc;
    globalThis.humanSize = humanSize;
    globalThis.relTime = relTime;
    globalThis.getIconClass = getIconClass;
    globalThis.bootstrapModal = bootstrapModal;

    // Also expose via App namespace for consistency with dialog.js pattern
    window.App = Object.assign(window.App || {}, {
        show, hide, esc, humanSize, relTime, getIconClass
    });
})();
