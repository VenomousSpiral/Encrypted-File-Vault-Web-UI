"use strict";

(function() {
    const FILE_ID = window.__EDITOR_CONFIG.fileId;
    const textUrl = '/api/file/' + FILE_ID + '/text';

    const editor       = document.getElementById('editor');
    const lineNumbers  = document.getElementById('lineNumbers');
    const saveStatus   = document.getElementById('saveStatus');
    const cursorPos    = document.getElementById('cursorPos');
    const fileSize     = document.getElementById('fileSize');
    const lineCount    = document.getElementById('lineCount');
    const wrapToggle   = document.getElementById('wrapToggle');

    let originalContent = '';
    let lastSavedContent = '';
    let autoSaveTimer = null;
    let saving = false;

    // ── Status helpers ──────────────────────────────────────────────
    function setStatus(state, text) {
        saveStatus.className = 'save-status ' + state;
        saveStatus.querySelector('.save-text').textContent = text || state;
    }

    // ── Load content ────────────────────────────────────────────────
    async function loadContent() {
        setStatus('loading', 'Loading…');
        try {
            const r = await fetch(textUrl, { credentials: 'same-origin' });
            const data = await r.json();
            if (data.error) { setStatus('error', 'Error: ' + data.error); return; }
            editor.value = data.content;
            originalContent = data.content;
            lastSavedContent = data.content;
            updateLineNumbers();
            updateFooter();
            setStatus('saved', 'Saved');
        } catch (e) {
            setStatus('error', 'Load failed');
            console.error(e);
        }
    }

    // ── Save content ────────────────────────────────────────────────
    async function saveContent() {
        if (saving) return;
        const content = editor.value;
        if (content === lastSavedContent) {
            setStatus('saved', 'Saved');
            return;
        }
        saving = true;
        setStatus('saving', 'Saving…');
        try {
            const r = await fetch(textUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ content }),
            });
            const data = await r.json();
            if (data.error) {
                setStatus('error', 'Save failed');
                console.error('Save error:', data.error);
            } else {
                lastSavedContent = content;
                setStatus('saved', 'Saved');
                updateFooter();
            }
        } catch (e) {
            setStatus('error', 'Save failed');
            console.error(e);
        } finally {
            saving = false;
        }
    }

    // ── Auto-save (debounced 2s) ────────────────────────────────────
    function scheduleAutoSave() {
        clearTimeout(autoSaveTimer);
        if (editor.value !== lastSavedContent) {
            setStatus('unsaved', 'Unsaved');
        }
        autoSaveTimer = setTimeout(() => saveContent(), 2000);
    }

    // ── Line numbers ────────────────────────────────────────────────
    function updateLineNumbers() {
        const lines = editor.value.split('\n').length;
        const nums = [];
        for (let i = 1; i <= lines; i++) nums.push(i);
        lineNumbers.textContent = nums.join('\n');
    }

    // ── Footer info ─────────────────────────────────────────────────
    function updateFooter() {
        const text = editor.value;
        const bytes = new Blob([text]).size;
        const lines = text.split('\n').length;
        fileSize.textContent = humanSize(bytes);
        lineCount.textContent = lines + ' line' + (lines !== 1 ? 's' : '');
    }

    function updateCursor() {
        const pos = editor.selectionStart;
        const before = editor.value.substring(0, pos);
        const line = before.split('\n').length;
        const col = pos - before.lastIndexOf('\n');
        cursorPos.textContent = 'Ln ' + line + ', Col ' + col;
    }

    function humanSize(bytes) {
        if (bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        const v = bytes / Math.pow(1024, i);
        return v.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
    }

    // ── Link detection ──────────────────────────────────────────────
    const linkBar    = document.getElementById('linkBar');
    const linkBarUrl = document.getElementById('linkBarUrl');
    const linkHint   = document.getElementById('linkHint');
    const urlRegex   = /https?:\/\/[^\s<>"'`\)\]]+/gi;
    const isMobile   = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
    linkHint.textContent = isMobile ? 'Tap link to open' : 'Ctrl+click to open';

    function getUrlAtPosition(text, pos) {
        // Find the line containing the cursor
        const lineStart = text.lastIndexOf('\n', pos - 1) + 1;
        let lineEnd = text.indexOf('\n', pos);
        if (lineEnd === -1) lineEnd = text.length;
        const line = text.substring(lineStart, lineEnd);
        const cursorInLine = pos - lineStart;

        // Find URLs in this line
        urlRegex.lastIndex = 0;
        let match;
        while ((match = urlRegex.exec(line)) !== null) {
            const start = match.index;
            const end = start + match[0].length;
            if (cursorInLine >= start && cursorInLine <= end) {
                // Strip trailing punctuation that isn't part of the URL
                let url = match[0].replace(/[.,;:!?)\]]+$/, '');
                return url;
            }
        }
        return null;
    }

    function updateLinkBar() {
        const url = getUrlAtPosition(editor.value, editor.selectionStart);
        if (url) {
            linkBarUrl.href = url;
            linkBarUrl.textContent = url;
            linkBar.classList.add('visible');
            // Position near cursor line
            positionLinkBar();
        } else {
            linkBar.classList.remove('visible');
        }
    }

    function positionLinkBar() {
        // Compute which line the cursor is on
        const pos = editor.selectionStart;
        const before = editor.value.substring(0, pos);
        const cursorLine = before.split('\n').length;
        const lineHeight = parseFloat(getComputedStyle(editor).lineHeight);
        const editorRect = editor.getBoundingClientRect();
        const wrapRect = editor.parentElement.getBoundingClientRect();

        // Y offset: line position minus scroll, relative to editor-wrap
        const lineTop = (cursorLine - 1) * lineHeight + parseFloat(getComputedStyle(editor).paddingTop);
        const relY = lineTop - editor.scrollTop + (editorRect.top - wrapRect.top);
        // Place below the line; if near bottom, place above
        const barHeight = 36;
        const spaceBelow = wrapRect.height - relY - lineHeight;
        if (spaceBelow > barHeight + 8) {
            linkBar.style.top = (relY + lineHeight + 4) + 'px';
            linkBar.style.bottom = 'auto';
        } else {
            linkBar.style.top = Math.max(4, relY - barHeight - 4) + 'px';
            linkBar.style.bottom = 'auto';
        }
    }

    // Ctrl+click / Cmd+click opens URL (desktop); tap link bar on mobile
    editor.addEventListener('click', (e) => {
        updateCursor();
        updateLinkBar();
        if (e.ctrlKey || e.metaKey) {
            const url = getUrlAtPosition(editor.value, editor.selectionStart);
            if (url) {
                window.open(url, '_blank', 'noopener,noreferrer');
            }
        }
    });
    // On mobile, update link bar after touch selection changes
    editor.addEventListener('touchend', () => {
        setTimeout(() => { updateCursor(); updateLinkBar(); }, 50);
    });

    // ── Sync scroll between line numbers and editor ─────────────────
    editor.addEventListener('scroll', () => {
        lineNumbers.scrollTop = editor.scrollTop;
    });

    // ── Event listeners ─────────────────────────────────────────────
    editor.addEventListener('input', () => {
        updateLineNumbers();
        updateFooter();
        updateLinkBar();
        scheduleAutoSave();
    });
    editor.addEventListener('keyup', (e) => {
        updateCursor();
        updateLinkBar();
    });
    editor.addEventListener('select', () => {
        updateCursor();
        updateLinkBar();
    });

    // Tab key inserts a tab instead of moving focus
    editor.addEventListener('keydown', (e) => {
        if (e.key === 'Tab') {
            e.preventDefault();
            const start = editor.selectionStart;
            const end = editor.selectionEnd;
            if (e.shiftKey) {
                // Un-indent: remove leading tab/spaces on current line
                const before = editor.value.substring(0, start);
                const lineStart = before.lastIndexOf('\n') + 1;
                const linePrefix = editor.value.substring(lineStart, start);
                if (linePrefix.startsWith('\t')) {
                    editor.value = editor.value.substring(0, lineStart) + editor.value.substring(lineStart + 1);
                    editor.selectionStart = editor.selectionEnd = start - 1;
                } else if (linePrefix.startsWith('    ')) {
                    editor.value = editor.value.substring(0, lineStart) + editor.value.substring(lineStart + 4);
                    editor.selectionStart = editor.selectionEnd = start - 4;
                }
            } else {
                editor.value = editor.value.substring(0, start) + '\t' + editor.value.substring(end);
                editor.selectionStart = editor.selectionEnd = start + 1;
            }
            updateLineNumbers();
            scheduleAutoSave();
        }

        // Ctrl+S / Cmd+S — manual save
        if ((e.ctrlKey || e.metaKey) && e.key === 's') {
            e.preventDefault();
            clearTimeout(autoSaveTimer);
            saveContent();
        }
    });

    // Word wrap toggle
    let wordWrap = false;
    wrapToggle.addEventListener('click', () => {
        wordWrap = !wordWrap;
        wrapToggle.classList.toggle('active', wordWrap);
        editor.style.whiteSpace = wordWrap ? 'pre-wrap' : 'pre';
        editor.style.overflowX = wordWrap ? 'hidden' : 'auto';
    });

    // Save before leaving
    window.addEventListener('beforeunload', (e) => {
        if (editor.value !== lastSavedContent) {
            // Fire off a save via sendBeacon
            navigator.sendBeacon(textUrl, new Blob(
                [JSON.stringify({ content: editor.value })],
                { type: 'application/json' }
            ));
        }
    });

    // Save on visibility change (tab switch, minimize)
    document.addEventListener('visibilitychange', () => {
        if (document.hidden && editor.value !== lastSavedContent) {
            saveContent();
        }
    });

    // ── Init ────────────────────────────────────────────────────────
    loadContent();
})();