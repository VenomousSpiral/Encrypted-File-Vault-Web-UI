'use strict';

// ════════════════════════════════════════════════════════════════════
//  Explorer core: file listing, rendering, navigation (openFile),
//  search & sort setup/execution.
//
// Shared state variables are defined at top of app.js; this module
// reads/writes them directly to maintain exact behavioral equivalence.
// ════════════════════════════════════════════════════════════════════

(function() {
    // ── Validators (unchanged from original) ───────────────────────
    const Validators = {
        folderName(name) {
            if (!name || !name.trim()) return 'Name is required.';
            if (/[\\/:*?"<>|]/.test(name)) return 'Name contains invalid character: / \\ : * ? " < > |';
            // Reject names that are just dots or spaces
            const trimmed = name.replace(/[\s\.]+$/g, '');
            if (!trimmed) return 'Name cannot be only whitespace/dots.';
            return null;
        }
    };

// ── Text-editable MIME types and extensions (mirrors server-side _is_text_editable) ──
const _TEXT_MIMES = new Set([
    'application/json', 'application/xml', 'application/javascript',
    'application/x-yaml', 'application/yaml', 'application/toml',
    'application/x-sh', 'application/x-shellscript',
    'application/sql', 'application/xhtml+xml', 'application/x-httpd-php',
]);
const _TEXT_EXTS = new Set([
    '.txt', '.md', '.markdown', '.json', '.yaml', '.yml', '.toml',
    '.xml', '.html', '.htm', '.css', '.js', '.ts', '.jsx', '.tsx',
    '.py', '.rb', '.rs', '.go', '.java', '.c', '.cpp', '.h', '.hpp',
    '.cs', '.sh', '.bash', '.zsh', '.fish', '.bat', '.ps1',
    '.sql', '.ini', '.cfg', '.conf', '.env', '.gitignore',
    '.dockerfile', '.makefile', '.cmakelists.txt', '.gradle',
    '.lua', '.pl', '.php', '.r', '.swift', '.kt', '.scala',
    '.log', '.csv', '.tsv', '.rst', '.tex', '.srt', '.vtt', '.sub',
    '.svg',
]);

function isTextEditable(f) {
    const mime = (f.mime_type || '').toLowerCase();
    if (mime.startsWith('text/')) return true;
    if (_TEXT_MIMES.has(mime)) return true;
    const name = (f.name || '').toLowerCase();
    const dot = name.lastIndexOf('.');
    if (dot >= 0 && _TEXT_EXTS.has(name.substring(dot))) return true;
    const base = name.split('/').pop();
    if (['dockerfile', 'makefile', 'cmakelists.txt', 'vagrantfile', 'gemfile', 'rakefile', 'procfile'].includes(base)) return true;
    return false;
}

// ════════════════════════════════════════════════════════════════════
//  FILE LISTING
// ════════════════════════════════════════════════════════════════════
async function loadFiles(parentId) {
    window._currentParentId = parentId;
    window._searchActive = false;
    // Exit select mode when navigating
    if (window._selectMode) App.exitSelectMode();
    show('loadingState'); hide('emptyState'); hide('fileList');
    // Clear search input when navigating
    const searchInput = document.getElementById('searchInput');
    if (searchInput) { searchInput.value = ''; }
    const searchClear = document.getElementById('searchClear');
    if (searchClear) searchClear.classList.add('d-none');

    const url = parentId !== null
        ? `/api/files?parent_id=${parentId}`
        : '/api/files';

    try {
        const data = await apiGet(url);
        renderBreadcrumbs(data.breadcrumbs);
        window._currentFiles = data.files;
        renderFiles(sortFiles(window._currentFiles));
    } catch (e) {
        console.error(e);
    }
}

function renderBreadcrumbs(crumbs) {
    const el = document.getElementById('breadcrumbs');
    el.innerHTML = '';
    crumbs.forEach((c, i) => {
        if (i > 0) {
            const sep = document.createElement('span');
            sep.className = 'crumb-sep';
            sep.textContent = '/';
            el.appendChild(sep);
        }
        const span = document.createElement('span');
        span.className = 'crumb' + (i === crumbs.length - 1 ? ' active' : '');
        span.textContent = c.name;
        if (i < crumbs.length - 1) {
            span.onclick = () => loadFiles(c.id);
        }
        el.appendChild(span);
    });
}

function renderFiles(files) {
    const list = document.getElementById('fileList');
    list.setAttribute('role', 'list');
    list.innerHTML = '';

    hide('loadingState');
    if (!files.length) { show('emptyState'); return; }
    hide('emptyState');

    files.forEach(f => {
        const row = document.createElement('div');
        row.className = 'file-row' + (window._selectedIds.has(f.id) ? ' selected' : '');
        row.dataset.id = f.id;
        row.setAttribute('role', 'listitem');
        row.setAttribute('aria-label', `${esc(f.name)} — ${f.is_directory ? 'Folder' : humanSize(f.size)}`);

        const iconCls = getIconClass(f);
        const pathHtml = (window._searchActive && f.path)
            ? `<div class="file-path text-secondary small text-truncate">${esc(f.path)}</div>`
            : '';

        const checkboxHtml = `<div class="select-checkbox ${window._selectMode ? 'visible' : ''}" data-fid="${f.id}">
            <i class="fas ${window._selectedIds.has(f.id) ? 'fa-check-square' : 'fa-square'}"></i>
        </div>`;

        row.innerHTML = `
            ${checkboxHtml}
            <div class="file-icon ${iconCls.cls}"><i class="fas ${iconCls.icon}"></i></div>
            <div class="file-name">
                ${esc(f.name)}
                ${pathHtml}
            </div>
            <div class="file-meta">
                ${f.is_directory ? '' : `<span class="size">${humanSize(f.size)}</span>`}
                <span class="dir-size" style="
                    display: ${window._showDirSize && f.is_directory && (f.recursive_size || 0) > 0
                        ? 'inline' : 'none'
                    }"
                >(${humanSize(f.recursive_size)})</span>
                <span class="date ms-3">${relTime(f.modified_at || f.created_at)}</span>
            </div>`;

        // Checkbox click
        row.querySelector('.select-checkbox').addEventListener('click', (e) => {
            e.stopPropagation();
            App.toggleSelect(f.id);
        });

        row.addEventListener('dblclick', () => { if (!window._selectMode) openFile(f); });
        row.addEventListener('click', (e) => {
            // Ctrl+Click or Meta+Click (Cmd on Mac) toggles selection on desktop
            if (e.ctrlKey || e.metaKey) {
                e.preventDefault();
                App.toggleSelect(f.id);
                return;
            }
            // Shift+Click selects a range
            if (e.shiftKey && window._selectMode && window._selectedIds.size > 0) {
                e.preventDefault();
                App.rangeSelect(f.id);
                return;
            }
            if (window._selectMode) { App.toggleSelect(f.id); return; }
        });
        row.addEventListener('contextmenu', e => {
            console.log('[DEBUG] contextmenu event fired for file:', f.name || 'unknown');
            if (window._selectMode) { e.preventDefault(); return; }
            console.log('[DEBUG] calling App.showCtx, window._selectMode:', window._selectMode);
            App.showCtx(e, f);
        });

        // Long-press for context menu on mobile
        let _lpTimer = null;
        let _lpFired = false;
        let _lpTouch = null;
        row.addEventListener('touchstart', (e) => {
            _lpFired = false;
            _lpTouch = e.touches[0];
            _lpTimer = setTimeout(() => {
                _lpFired = true;
                _lpTimer = null;
                if (window._selectMode) {
                    App.toggleSelect(f.id);
                } else {
                    // Simulate context menu at touch point
                    const fakeEvt = {
                        preventDefault() { }, stopPropagation() { },
                        clientX: _lpTouch.clientX, clientY: _lpTouch.clientY
                    };
                    App.showCtx(fakeEvt, f);
                }
            }, 500);
        }, { passive: true });
        row.addEventListener('touchend', () => { if (_lpTimer) { clearTimeout(_lpTimer); _lpTimer = null; } });
        row.addEventListener('touchmove', () => { if (_lpTimer) { clearTimeout(_lpTimer); _lpTimer = null; } });

        // Single tap opens file on touch devices (dblclick doesn't work well on mobile)
        const isTouchDevice = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
        if (isTouchDevice) {
            row.addEventListener('click', (e) => {
                if (_lpFired) { _lpFired = false; e.preventDefault(); return; }
                if (window._selectMode) { App.toggleSelect(f.id); return; }
                openFile(f);
            });
        }

        list.appendChild(row);
    });

    show('fileList');
}

// ════════════════════════════════════════════════════════════════════
//  OPEN / NAVIGATE
// ════════════════════════════════════════════════════════════════════
function openFile(f) {
    if (f.is_directory) {
        loadFiles(f.id);
        return;
    }
    // Text-editable files → editor
    if (isTextEditable(f)) {
        const fromParam = window._currentParentId !== null ? `?from=${window._currentParentId}` : '?from=root';
        const extraParams = '&sort_by=' + encodeURIComponent(window._currentSort || 'name');
        window.location.href = `/editor/${f.id}${fromParam}${extraParams}`;
        return;
    }
    // CBZ files → CBZ reader
    const mime = f.mime_type || '';
    const name = (f.name || '').toLowerCase();
    if (mime === 'application/vnd.comicbook+zip' || name.endsWith('.cbz')) {
        const fromParam = window._currentParentId !== null ? `?from=${window._currentParentId}` : '?from=root';
        const extraParams = '&sort_by=' + encodeURIComponent(window._currentSort || 'name');
        window.location.href = `/cbz/${f.id}${fromParam}${extraParams}`;
        return;
    }
    if (mime.startsWith('video/') || mime.startsWith('audio/') ||
        mime.startsWith('image/') || mime === 'application/pdf') {
        const fromParam = window._currentParentId !== null ? `?from=${window._currentParentId}` : '?from=root';
        // Pass sort preference and recursion state so player navigation respects explorer settings
        const extraParams = [
            '&sort_by=' + encodeURIComponent(window._currentSort || 'name'),
            '&shuffle=' + (localStorage.getItem('vault_shuffle') === '1' ? 1 : 0),
            '&recurse=' + (localStorage.getItem('vault_recurse') !== '0' ? 1 : 0)
        ].join('');
        window.location.href = `/player/${f.id}${fromParam}${extraParams}`;
    } else {
        window.location.href = '/download/' + f.id;
    }
}

// ════════════════════════════════════════════════════════════════════
//  SEARCH
// ════════════════════════════════════════════════════════════════════
let _searchTimer = null;

function setupSearch() {
    const input = document.getElementById('searchInput');
    const clearBtn = document.getElementById('searchClear');
    if (!input) return;

    input.addEventListener('input', () => {
        const q = input.value.trim();
        clearBtn.classList.toggle('d-none', !q);
        clearTimeout(_searchTimer);
        if (!q) {
            // Restore normal file listing
            if (window._searchActive) {
                window._searchActive = false;
                loadFiles(window._currentParentId);
            }
            return;
        }
        _searchTimer = setTimeout(() => doSearch(q), 300);
    });

    input.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
            input.value = '';
            clearBtn.classList.add('d-none');
            if (window._searchActive) {
                window._searchActive = false;
                loadFiles(window._currentParentId);
            }
        }
    });

    clearBtn.addEventListener('click', () => {
        input.value = '';
        clearBtn.classList.add('d-none');
        if (window._searchActive) {
            window._searchActive = false;
            loadFiles(window._currentParentId);
        }
        input.focus();
    });
}

async function doSearch(query) {
    show('loadingState'); hide('emptyState'); hide('fileList');
    try {
        const data = await apiGet(`/api/search?q=${encodeURIComponent(query)}&parent_id=${encodeURIComponent(window._currentParentId)}`);
        window._searchActive = true;
        window._currentFiles = data.files;

        // Show search breadcrumb
        const el = document.getElementById('breadcrumbs');
        el.innerHTML = '';
        const span = document.createElement('span');
        span.className = 'crumb active';
        span.textContent = `Search: "${query}" (${data.files.length} result${data.files.length !== 1 ? 's' : ''})`;
        el.appendChild(span);

        renderFiles(sortFiles(window._currentFiles));
    } catch (e) {
        console.error('Search error:', e);
    }
}

// ════════════════════════════════════════════════════════════════════
//  SORT
// ════════════════════════════════════════════════════════════════════
const SORT_LABELS = { name: 'Name', recent: 'Recent', added: 'Added', size: 'Size' };

function setupSort() {
    const menu = document.querySelector('#sortBtn + .dropdown-menu');
    if (!menu) return;

    // Apply persisted sort on load
    if (window._currentSort !== 'name') {
        menu.querySelectorAll('.dropdown-item').forEach(el =>
            el.classList.toggle('active', el.dataset.sort === window._currentSort));
    }

    const label = document.getElementById('sortLabel');
    if (label) label.textContent = SORT_LABELS[window._currentSort] || window._currentSort;

    menu.addEventListener('click', e => {
        e.preventDefault();
        const link = e.target.closest('[data-sort]');
        if (!link) return;

        window._currentSort = link.dataset.sort;
        // Persist sort preference to server
        fetch('/api/preferences', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ sort_preference: window._currentSort }),
        }).catch(() => { });
        // Update active class
        menu.querySelectorAll('.dropdown-item').forEach(el =>
            el.classList.toggle('active', el.dataset.sort === window._currentSort));
        // Update label
        const lbl = document.getElementById('sortLabel');
        if (lbl) lbl.textContent = SORT_LABELS[window._currentSort] || window._currentSort;

        // Re-render with new sort
        renderFiles(sortFiles(window._currentFiles));
    });
}

function sortFiles(files) {
    const sorted = [...files];
    switch (window._currentSort) {
        case 'name':
            sorted.sort((a, b) => {
                // Directories first, then alphabetical
                if (a.is_directory !== b.is_directory) return a.is_directory ? -1 : 1;
                return (a.name || '').localeCompare(b.name || '', undefined, { sensitivity: 'base' });
            });
            break;
        case 'recent':
            sorted.sort((a, b) => {
                // Directories first, then by last_accessed desc (no access = end)
                if (a.is_directory !== b.is_directory) return a.is_directory ? -1 : 1;
                const aa = a.last_accessed || '';
                const bb = b.last_accessed || '';
                if (!aa && !bb) return (a.name || '').localeCompare(b.name || '');
                if (!aa) return 1;
                if (!bb) return -1;
                return bb.localeCompare(aa);
            });
            break;
        case 'added':
            sorted.sort((a, b) => {
                // Directories first, then by created_at desc
                if (a.is_directory !== b.is_directory) return a.is_directory ? -1 : 1;
                const aa = a.created_at || '';
                const bb = b.created_at || '';
                return bb.localeCompare(aa);
            });
            break;
        case 'size':
            sorted.sort((a, b) => {
                // Directories first, then by size desc
                if (a.is_directory !== b.is_directory) return a.is_directory ? -1 : 1;
                return (b.size || 0) - (a.size || 0);
            });
            break;
    }
    return sorted;
}

// ════════════════════════════════════════════════════════════════════
//  ENTER KEY IN MODALS
// ════════════════════════════════════════════════════════════════════
function setupModalEnter() {
    document.getElementById('folderNameInput')
        .addEventListener('keydown', e => { if (e.key === 'Enter') App.createFolder(); });
    document.getElementById('renameInput')
        .addEventListener('keydown', e => { if (e.key === 'Enter') App.doRename(); });
    const newFileInput = document.getElementById('newFileNameInput');
    if (newFileInput) newFileInput.addEventListener('keydown', e => { if (e.key === 'Enter') App.createTextFile(); });
}

// ════════════════════════════════════════════════════════════════════
//  INITIALIZATION — runs on DOMContentLoaded in app.js
// ════════════════════════════════════════════════════════════════════
function initExplorer() {
    // Check URL for initial parent_id (e.g. returning from player)
    const params = new URLSearchParams(window.location.search);
    const initParent = params.has('parent_id') ? parseInt(params.get('parent_id')) : null;
    loadFiles(isNaN(initParent) ? null : initParent);
}

// ════════════════════════════════════════════════════════════════════
//  PUBLIC API — exposed via window.App for template onclicks
// ════════════════════════════════════════════════════════════════════
    // Expose Validators so other modules (context-menu.js) can call App.Validators.folderName()
    window.App = Object.assign(window.App || {}, { Validators });

    const FileManager = {
        loadFiles, renderBreadcrumbs, renderFiles,
        openFile, isTextEditable, sortFiles, setupSearch, doSearch, setupSort,
        setupModalEnter
    };

    window.App = Object.assign(window.App || {}, FileManager);
})();
