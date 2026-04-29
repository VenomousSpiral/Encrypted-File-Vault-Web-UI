/* ═══════════════════════════════════════════════════════════════════
   Encrypted Vault – frontend logic
   ═══════════════════════════════════════════════════════════════════ */

// ── state ───────────────────────────────────────────────────────────
let currentParentId = null;   // null = root
let contextFile = null;   // file object for context-menu target
let moveParentId = null;   // current folder inside Move dialog
let moveNavHistory = [];   // back-stack for Move dialog navigation
let uploadQueue = [];
let uploading = false;
let currentSort = (typeof window.__SORT_PREF !== 'undefined' ? window.__SORT_PREF : 'name');
let currentFiles = [];     // raw file list from server (for re-sorting)
let searchActive = false;  // true when showing search results

// ── multi-select state ──────────────────────────────────────────────
let selectMode = false;  // true when multi-select is active
let selectedIds = new Set();  // set of selected file IDs

// ── bootstrap modal helpers ─────────────────────────────────────────
const modal = id => bootstrap.Modal.getOrCreateInstance(document.getElementById(id));

// ── init ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Check URL for initial parent_id (e.g. returning from player)
    const params = new URLSearchParams(window.location.search);
    const initParent = params.has('parent_id') ? parseInt(params.get('parent_id')) : null;
    loadFiles(isNaN(initParent) ? null : initParent);
    setupDragDrop();
    setupContextMenu();
    setupModalEnter();
    setupSearch();
    setupSort();

    // Keyboard shortcuts for multi-select
    document.addEventListener('keydown', (e) => {
        // Escape exits select mode
        if (e.key === 'Escape' && selectMode) {
            exitSelectMode();
            e.preventDefault();
        }
        // Ctrl+A / Cmd+A selects all when in select mode (or file list focused)
        if ((e.ctrlKey || e.metaKey) && e.key === 'a' && !e.target.closest('input, textarea, [contenteditable]')) {
            e.preventDefault();
            selectAll();
        }
    });
});

// ════════════════════════════════════════════════════════════════════
//  FILE LISTING
// ════════════════════════════════════════════════════════════════════
async function loadFiles(parentId) {
    currentParentId = parentId;
    searchActive = false;
    // Exit select mode when navigating
    if (selectMode) exitSelectMode();
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
        currentFiles = data.files;
        renderFiles(sortFiles(currentFiles));
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
    list.innerHTML = '';
    hide('loadingState');

    if (!files.length) { show('emptyState'); return; }
    hide('emptyState');

    files.forEach(f => {
        const row = document.createElement('div');
        row.className = 'file-row' + (selectedIds.has(f.id) ? ' selected' : '');
        row.dataset.id = f.id;

        const iconCls = getIconClass(f);
        const pathHtml = (searchActive && f.path)
            ? `<div class="file-path text-secondary small text-truncate">${esc(f.path)}</div>`
            : '';

        const checkboxHtml = `<div class="select-checkbox ${selectMode ? 'visible' : ''}" data-fid="${f.id}">
            <i class="fas ${selectedIds.has(f.id) ? 'fa-check-square' : 'fa-square'}"></i>
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
                <span class="date ms-3">${relTime(f.modified_at || f.created_at)}</span>
            </div>`;

        // Checkbox click
        row.querySelector('.select-checkbox').addEventListener('click', (e) => {
            e.stopPropagation();
            toggleSelect(f.id);
        });

        row.addEventListener('dblclick', () => { if (!selectMode) openFile(f); });
        row.addEventListener('click', (e) => {
            // Ctrl+Click or Meta+Click (Cmd on Mac) toggles selection on desktop
            if (e.ctrlKey || e.metaKey) {
                e.preventDefault();
                toggleSelect(f.id);
                return;
            }
            // Shift+Click selects a range
            if (e.shiftKey && selectMode && selectedIds.size > 0) {
                e.preventDefault();
                rangeSelect(f.id);
                return;
            }
            if (selectMode) { toggleSelect(f.id); return; }
        });
        row.addEventListener('contextmenu', e => {
            if (selectMode) { e.preventDefault(); return; }
            showCtx(e, f);
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
                if (selectMode) {
                    toggleSelect(f.id);
                } else {
                    // Simulate context menu at touch point
                    const fakeEvt = {
                        preventDefault() { }, stopPropagation() { },
                        clientX: _lpTouch.clientX, clientY: _lpTouch.clientY
                    };
                    showCtx(fakeEvt, f);
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
                if (selectMode) { toggleSelect(f.id); return; }
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
// Text-editable MIME types and extensions (mirrors server-side _is_text_editable)
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
    '.dockerfile', '.makefile', '.cmake', '.gradle',
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

function openFile(f) {
    if (f.is_directory) {
        loadFiles(f.id);
        return;
    }
    // Text-editable files → editor
    if (isTextEditable(f)) {
        const fromParam = currentParentId !== null ? `?from=${currentParentId}` : '?from=root';
        window.location.href = `/editor/${f.id}${fromParam}`;
        return;
    }
    // CBZ files → CBZ reader
    const mime = f.mime_type || '';
    const name = (f.name || '').toLowerCase();
    if (mime === 'application/vnd.comicbook+zip' || name.endsWith('.cbz')) {
        const fromParam = currentParentId !== null ? `?from=${currentParentId}` : '?from=root';
        window.location.href = `/cbz/${f.id}${fromParam}`;
        return;
    }
    if (mime.startsWith('video/') || mime.startsWith('audio/') ||
        mime.startsWith('image/') || mime === 'application/pdf') {
        const fromParam = currentParentId !== null ? `?from=${currentParentId}` : '?from=root';
        window.location.href = `/player/${f.id}${fromParam}`;
    } else {
        window.location.href = `/download/${f.id}`;
    }
}

// ════════════════════════════════════════════════════════════════════
//  UPLOAD
// ════════════════════════════════════════════════════════════════════
function uploadFiles(fileList) {
    if (!fileList || !fileList.length) return;
    // Check if this is a folder upload (files have webkitRelativePath)
    const hasRelativePaths = fileList[0] && fileList[0].webkitRelativePath;
    if (hasRelativePaths) {
        uploadFolder(fileList);
    } else {
        for (const f of fileList) uploadQueue.push({ file: f, parentId: currentParentId });
        document.getElementById('fileInput').value = '';
        processQueue();
    }
}

async function uploadFolder(fileList) {
    // Collect unique directory paths and create them first
    const dirCache = {};   // relative path → server folder id
    const rootParent = currentParentId;

    // Build sorted unique dir paths
    const dirPaths = new Set();
    for (const f of fileList) {
        const parts = f.webkitRelativePath.split('/');
        // All but the last part are directories
        for (let i = 1; i <= parts.length - 1; i++) {
            dirPaths.add(parts.slice(0, i).join('/'));
        }
    }
    // Sort so parents come first
    const sortedDirs = [...dirPaths].sort();

    // Create directories on server
    for (const dirPath of sortedDirs) {
        const parts = dirPath.split('/');
        const dirName = parts[parts.length - 1];
        const parentPath = parts.slice(0, -1).join('/');
        const parentId = parentPath ? (dirCache[parentPath] || rootParent) : rootParent;

        try {
            const data = await apiPost('/api/mkdirp', { name: dirName, parent_id: parentId });
            dirCache[dirPath] = data.id;
        } catch (e) {
            console.error('Failed to create dir:', dirPath, e);
        }
    }

    // Queue files with their correct parent
    for (const f of fileList) {
        const parts = f.webkitRelativePath.split('/');
        const dirPath = parts.slice(0, -1).join('/');
        const parentId = dirPath ? (dirCache[dirPath] || rootParent) : rootParent;
        uploadQueue.push({ file: f, parentId });
    }

    document.getElementById('folderInput').value = '';
    processQueue();
}

async function processQueue() {
    if (uploading || !uploadQueue.length) return;
    uploading = true;
    show('uploadProgress');

    while (uploadQueue.length) {
        const item = uploadQueue.shift();
        await uploadOne(item.file, item.parentId);
    }

    hide('uploadProgress');
    uploading = false;
    loadFiles(currentParentId);
}

function uploadOne(file, parentId) {
    return new Promise((resolve) => {
        const fd = new FormData();
        fd.append('file', file);
        if (parentId !== null && parentId !== undefined) fd.append('parent_id', parentId);

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload');

        xhr.upload.onprogress = e => {
            if (!e.lengthComputable) return;
            const pct = Math.round(e.loaded / e.total * 100);
            document.getElementById('uploadBar').style.width = pct + '%';
            document.getElementById('uploadPercent').textContent = pct + '%';
            document.getElementById('uploadFileName').textContent = file.name;
        };

        xhr.onload = () => {
            if (xhr.status !== 200) {
                try {
                    const err = JSON.parse(xhr.responseText);
                    alert('Upload failed: ' + (err.error || 'unknown error'));
                } catch { alert('Upload failed'); }
            }
            resolve();
        };
        xhr.onerror = () => { alert('Upload network error'); resolve(); };
        xhr.send(fd);
    });
}

// ── drag & drop ─────────────────────────────────────────────────────
function setupDragDrop() {
    let dragCounter = 0;
    const zone = document.getElementById('dropZone');

    document.addEventListener('dragenter', e => {
        e.preventDefault();
        dragCounter++;
        if (dragCounter === 1) show('dropZone');
    });
    document.addEventListener('dragleave', e => {
        e.preventDefault();
        dragCounter--;
        if (dragCounter <= 0) { dragCounter = 0; hide('dropZone'); }
    });
    document.addEventListener('dragover', e => e.preventDefault());
    document.addEventListener('drop', e => {
        e.preventDefault();
        dragCounter = 0;
        hide('dropZone');
        // Use DataTransferItem API to detect dropped folders
        if (e.dataTransfer.items && e.dataTransfer.items.length) {
            handleDropItems(e.dataTransfer.items);
        } else if (e.dataTransfer.files.length) {
            uploadFiles(e.dataTransfer.files);
        }
    });
}

// ── drag & drop folder traversal ────────────────────────────────────
async function handleDropItems(items) {
    const entries = [];
    for (let i = 0; i < items.length; i++) {
        const entry = items[i].webkitGetAsEntry ? items[i].webkitGetAsEntry() : null;
        if (entry) entries.push(entry);
    }

    // Check if any entry is a directory
    const hasDir = entries.some(e => e.isDirectory);
    if (!hasDir) {
        // Plain files — use simple upload
        const files = [];
        for (let i = 0; i < items.length; i++) {
            const f = items[i].getAsFile();
            if (f) files.push(f);
        }
        for (const f of files) uploadQueue.push({ file: f, parentId: currentParentId });
        processQueue();
        return;
    }

    // Traverse directory tree and collect all files with their paths
    const collected = [];  // { file, path: 'dir/subdir' }
    async function traverseEntry(entry, path) {
        if (entry.isFile) {
            const file = await new Promise(resolve => entry.file(resolve));
            collected.push({ file, path });
        } else if (entry.isDirectory) {
            const dirPath = path ? path + '/' + entry.name : entry.name;
            const reader = entry.createReader();
            const subEntries = await new Promise(resolve => {
                const all = [];
                (function readBatch() {
                    reader.readEntries(batch => {
                        if (batch.length === 0) { resolve(all); return; }
                        all.push(...batch);
                        readBatch();
                    });
                })();
            });
            for (const sub of subEntries) {
                await traverseEntry(sub, dirPath);
            }
        }
    }

    for (const entry of entries) {
        if (entry.isDirectory) {
            await traverseEntry(entry, '');
        } else {
            const file = await new Promise(resolve => entry.file(resolve));
            collected.push({ file, path: '' });
        }
    }

    // Create directories on server, then queue files
    const dirCache = {};
    const rootParent = currentParentId;

    const dirPaths = new Set();
    for (const { path } of collected) {
        if (!path) continue;
        const parts = path.split('/');
        for (let i = 1; i <= parts.length; i++) {
            dirPaths.add(parts.slice(0, i).join('/'));
        }
    }

    for (const dirPath of [...dirPaths].sort()) {
        const parts = dirPath.split('/');
        const dirName = parts[parts.length - 1];
        const parentPath = parts.slice(0, -1).join('/');
        const parentId = parentPath ? (dirCache[parentPath] || rootParent) : rootParent;
        try {
            const data = await apiPost('/api/mkdirp', { name: dirName, parent_id: parentId });
            dirCache[dirPath] = data.id;
        } catch (e) {
            console.error('Failed to create dir:', dirPath, e);
        }
    }

    for (const { file, path } of collected) {
        const parentId = path ? (dirCache[path] || rootParent) : rootParent;
        uploadQueue.push({ file, parentId });
    }
    processQueue();
}

// ════════════════════════════════════════════════════════════════════
//  CONTEXT MENU
// ════════════════════════════════════════════════════════════════════
function setupContextMenu() {
    // delegate clicks on ctx-items
    document.getElementById('contextMenu').addEventListener('click', e => {
        const item = e.target.closest('.ctx-item');
        if (!item) return;
        hideCtx();
        handleCtxAction(item.dataset.action);
    });
    // hide on click/touch elsewhere
    document.addEventListener('click', () => hideCtx());
    document.addEventListener('touchstart', (e) => {
        const menu = document.getElementById('contextMenu');
        if (menu.style.display !== 'none' && !menu.contains(e.target)) hideCtx();
    }, { passive: true });
    window.addEventListener('scroll', () => hideCtx(), true);
}

function showCtx(e, file) {
    e.preventDefault();
    e.stopPropagation();
    contextFile = file;

    // Show/hide Edit option based on whether file is text-editable
    const editItem = document.getElementById('ctxEdit');
    if (editItem) {
        editItem.style.display = (!file.is_directory && isTextEditable(file)) ? '' : 'none';
    }

    // Show download for both files and folders
    const dlItem = document.getElementById('ctxDownload');
    if (dlItem) dlItem.style.display = '';

    // Show/hide video-only options
    const isVideo = !file.is_directory && (file.mime_type || '').startsWith('video/');
    const isDir = file.is_directory;
    const reEl = document.getElementById('ctxReencode');
    const rdEl = document.getElementById('ctxReencodeDir');
    const ccEl = document.getElementById('ctxClearAudioCache');
    const vsEl = document.getElementById('ctxVideoSep');
    if (reEl) reEl.style.display = isVideo ? '' : 'none';
    if (rdEl) rdEl.style.display = isDir ? '' : 'none';
    if (ccEl) ccEl.style.display = isVideo ? '' : 'none';
    if (vsEl) vsEl.style.display = (isVideo || isDir) ? '' : 'none';

    const menu = document.getElementById('contextMenu');
    menu.style.display = 'block';

    // position (keep inside viewport)
    let x = e.clientX, y = e.clientY;
    const mw = menu.offsetWidth, mh = menu.offsetHeight;
    if (x + mw > window.innerWidth) x = window.innerWidth - mw - 8;
    if (y + mh > window.innerHeight) y = window.innerHeight - mh - 8;
    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
}

function hideCtx() {
    document.getElementById('contextMenu').style.display = 'none';
}

function handleCtxAction(action) {
    if (!contextFile) return;
    const f = contextFile;

    switch (action) {
        case 'open':
            openFile(f);
            break;
        case 'edit':
            if (!f.is_directory) window.location.href = `/editor/${f.id}`;
            break;
        case 'download':
            if (f.is_directory) {
                window.location.href = `/download-folder/${f.id}`;
            } else {
                window.location.href = `/download/${f.id}`;
            }
            break;
        case 'rename':
            document.getElementById('renameInput').value = f.name;
            modal('renameModal').show();
            setTimeout(() => {
                const inp = document.getElementById('renameInput');
                inp.focus();
                // select name without extension
                const dot = f.name.lastIndexOf('.');
                inp.setSelectionRange(0, dot > 0 && !f.is_directory ? dot : f.name.length);
            }, 200);
            break;
        case 'move':
            moveNavHistory = [];
            loadMoveFolders(currentParentId);
            modal('moveModal').show();
            break;
        case 'delete':
            document.getElementById('deleteFileName').textContent = f.name;
            modal('deleteModal').show();
            break;
        case 'reencode':
            if (confirm('Re-encode "' + f.name + '" to H.264 + AAC for browser playback?\n\nThis will permanently replace the original file. This may take a long time for large files.')) {
                reencodeFile(f);
            }
            break;
        case 'reencode-dir':
            if (confirm('Re-encode ALL video files in "' + f.name + '" to H.264 + AAC?\n\nThis processes files one at a time and may take a very long time.')) {
                reencodeDir(f);
            }
            break;
        case 'clear-audio-cache':
            clearAudioCache(f);
            break;
    }
}

async function reencodeFile(f) {
    try {
        const resp = await fetch('/api/overwrite-audio/' + f.id, {
            method: 'POST', credentials: 'same-origin',
        });
        const data = await resp.json();
        if (data.success) {
            showToast(data.message || 'Re-encode started.', 'info');
            startReencodePoller();
        } else {
            showToast('Error: ' + (data.error || 'Unknown error'), 'error');
        }
    } catch (e) { showToast('Request failed: ' + e.message, 'error'); }
}

async function reencodeDir(f) {
    try {
        const resp = await fetch('/api/reencode-dir/' + f.id, {
            method: 'POST', credentials: 'same-origin',
        });
        const data = await resp.json();
        if (data.success) {
            showToast(data.message || 'Batch re-encode started.', 'info');
            startReencodePoller();
        } else {
            showToast('Error: ' + (data.error || 'Unknown error'), 'error');
        }
    } catch (e) { showToast('Request failed: ' + e.message, 'error'); }
}

async function clearAudioCache(f) {
    try {
        const resp = await fetch('/api/audio-cache/' + f.id + '/clear', {
            method: 'POST', credentials: 'same-origin',
        });
        const data = await resp.json();
        if (data.success) {
            alert('Cleared ' + (data.cleared || 0) + ' cached audio track(s).');
        } else {
            alert('Error: ' + (data.error || 'Unknown'));
        }
    } catch (e) { alert('Request failed: ' + e.message); }
}

// ════════════════════════════════════════════════════════════════════
//  NEW FOLDER
// ════════════════════════════════════════════════════════════════════
function showNewFolderModal() {
    document.getElementById('folderNameInput').value = '';
    modal('newFolderModal').show();
    setTimeout(() => document.getElementById('folderNameInput').focus(), 200);
}

function showNewFileModal() {
    document.getElementById('newFileNameInput').value = '';
    modal('newFileModal').show();
    setTimeout(() => document.getElementById('newFileNameInput').focus(), 200);
}

async function createTextFile() {
    const name = document.getElementById('newFileNameInput').value.trim();
    if (!name) return;
    try {
        const data = await apiPost('/api/create-text', { name, parent_id: currentParentId });
        modal('newFileModal').hide();
        // Open directly in editor
        window.location.href = `/editor/${data.id}`;
    } catch (e) { alert(e.message); }
}

async function createFolder() {
    const name = document.getElementById('folderNameInput').value.trim();
    if (!name) return;
    try {
        await apiPost('/api/mkdir', { name, parent_id: currentParentId });
        modal('newFolderModal').hide();
        loadFiles(currentParentId);
    } catch (e) { alert(e.message); }
}

// ════════════════════════════════════════════════════════════════════
//  RENAME
// ════════════════════════════════════════════════════════════════════
async function doRename() {
    if (!contextFile) return;
    const name = document.getElementById('renameInput').value.trim();
    if (!name) return;
    try {
        await apiPost('/api/rename', { id: contextFile.id, name });
        modal('renameModal').hide();
        loadFiles(currentParentId);
    } catch (e) { alert(e.message); }
}

// ════════════════════════════════════════════════════════════════════
//  DELETE
// ════════════════════════════════════════════════════════════════════
async function doDelete() {
    if (!contextFile) return;
    try {
        await apiPost('/api/delete', { id: contextFile.id });
        modal('deleteModal').hide();
        loadFiles(currentParentId);
    } catch (e) { alert(e.message); }
}

// ════════════════════════════════════════════════════════════════════
//  MULTI-SELECT
// ════════════════════════════════════════════════════════════════════
function enterSelectMode() {
    selectMode = true;
    document.querySelectorAll('.select-checkbox').forEach(el => el.classList.add('visible'));
    updateBulkBar();
}

function exitSelectMode() {
    selectMode = false;
    selectedIds.clear();
    document.querySelectorAll('.select-checkbox').forEach(el => el.classList.remove('visible'));
    document.querySelectorAll('.file-row.selected').forEach(el => el.classList.remove('selected'));
    // Update checkbox icons
    document.querySelectorAll('.select-checkbox i').forEach(el => {
        el.className = 'fas fa-square';
    });
    updateBulkBar();
}

function toggleSelect(fileId) {
    if (!selectMode) enterSelectMode();
    if (selectedIds.has(fileId)) {
        selectedIds.delete(fileId);
    } else {
        selectedIds.add(fileId);
    }
    // Update visual
    const row = document.querySelector(`.file-row[data-id="${fileId}"]`);
    if (row) {
        row.classList.toggle('selected', selectedIds.has(fileId));
        const icon = row.querySelector('.select-checkbox i');
        if (icon) icon.className = selectedIds.has(fileId) ? 'fas fa-check-square' : 'fas fa-square';
    }
    if (selectedIds.size === 0) {
        exitSelectMode();
    } else {
        updateBulkBar();
    }
}

function rangeSelect(targetId) {
    // Select all files between the last selected and the target
    const rows = [...document.querySelectorAll('.file-row')];
    const rowIds = rows.map(r => parseInt(r.dataset.id));

    // Find boundaries: last selected item and the target
    let lastIdx = -1;
    for (let i = rows.length - 1; i >= 0; i--) {
        if (selectedIds.has(rowIds[i]) && rowIds[i] !== targetId) {
            lastIdx = i;
            break;
        }
    }
    const targetIdx = rowIds.indexOf(targetId);
    if (lastIdx === -1 || targetIdx === -1) {
        toggleSelect(targetId);
        return;
    }

    const start = Math.min(lastIdx, targetIdx);
    const end = Math.max(lastIdx, targetIdx);
    for (let i = start; i <= end; i++) {
        const fid = rowIds[i];
        selectedIds.add(fid);
        rows[i].classList.add('selected');
        const icon = rows[i].querySelector('.select-checkbox i');
        if (icon) icon.className = 'fas fa-check-square';
    }
    updateBulkBar();
}

function selectAll() {
    if (!selectMode) enterSelectMode();
    currentFiles.forEach(f => selectedIds.add(f.id));
    document.querySelectorAll('.file-row').forEach(row => {
        row.classList.add('selected');
        const icon = row.querySelector('.select-checkbox i');
        if (icon) icon.className = 'fas fa-check-square';
    });
    updateBulkBar();
}

function updateBulkBar() {
    const bar = document.getElementById('bulkActionBar');
    if (!bar) return;
    if (selectMode && selectedIds.size > 0) {
        bar.style.display = '';
        document.getElementById('bulkCount').textContent = `${selectedIds.size} selected`;
    } else {
        bar.style.display = 'none';
    }
}

async function bulkDelete() {
    if (!selectedIds.size) return;
    const count = selectedIds.size;
    if (!confirm(`Delete ${count} item${count > 1 ? 's' : ''}? This cannot be undone.`)) return;
    try {
        await apiPost('/api/bulk-delete', { ids: [...selectedIds] });
        exitSelectMode();
        loadFiles(currentParentId);
    } catch (e) { alert(e.message); }
}

let bulkMoveParentId = null;
let bulkMoveNavHistory = [];

function showBulkMoveModal() {
    if (!selectedIds.size) return;
    bulkMoveNavHistory = [];
    loadBulkMoveFolders(currentParentId);
    modal('bulkMoveModal').show();
}

async function loadBulkMoveFolders(parentId) {
    bulkMoveParentId = parentId;
    const url = parentId !== null
        ? `/api/folders?parent_id=${parentId}`
        : '/api/folders';
    const data = await apiGet(url);
    const list = document.getElementById('bulkMoveFolderList');
    list.innerHTML = '';

    // Get full breadcrumb path
    let breadcrumbs = [];
    if (parentId !== null) {
        try {
            const bcData = await apiGet(`/api/folder-breadcrumbs/${parentId}`);
            breadcrumbs = bcData.breadcrumbs || [];
        } catch (e) {
            console.warn('Could not load breadcrumbs:', e);
        }
    }

    // Display breadcrumbs with clickable path
    const bc = document.getElementById('bulkMoveBreadcrumbs');
    bc.innerHTML = '';
    
    // Build breadcrumb display with clickable components
    const crumbContainer = document.createElement('div');
    crumbContainer.style.display = 'flex';
    crumbContainer.style.alignItems = 'center';
    crumbContainer.style.flexWrap = 'wrap';
    crumbContainer.style.gap = '4px';
    crumbContainer.style.fontSize = '0.9rem';
    
    // Use breadcrumbs array directly (already includes Root from API)
    if (breadcrumbs.length === 0) {
        // Fallback to just showing Root if no breadcrumbs
        const rootCrumb = document.createElement('a');
        rootCrumb.href = '#';
        rootCrumb.style.cursor = 'pointer';
        rootCrumb.className = 'text-primary';
        rootCrumb.textContent = 'Root';
        rootCrumb.onclick = (e) => { e.preventDefault(); loadBulkMoveFolders(null); };
        crumbContainer.appendChild(rootCrumb);
    } else {
        breadcrumbs.forEach((crumb, index) => {
            if (index > 0) {
                const sep = document.createElement('span');
                sep.textContent = '/';
                sep.className = 'text-secondary';
                crumbContainer.appendChild(sep);
            }
            
            const crumbLink = document.createElement('a');
            crumbLink.href = '#';
            crumbLink.style.cursor = 'pointer';
            crumbLink.className = index === breadcrumbs.length - 1 ? 'text-primary' : 'text-info';
            crumbLink.textContent = crumb.name;
            crumbLink.onclick = (e) => { 
                e.preventDefault(); 
                loadBulkMoveFolders(crumb.id); 
            };
            crumbContainer.appendChild(crumbLink);
        });
    }
    
    bc.appendChild(crumbContainer);

    // Navigation buttons container
    const navButtons = document.createElement('div');
    navButtons.style.marginTop = '8px';
    navButtons.style.display = 'flex';
    navButtons.style.gap = '8px';
    navButtons.style.flexWrap = 'wrap';
    
    // Back button - always show if there's history
    if (bulkMoveNavHistory && bulkMoveNavHistory.length > 0) {
        const back = document.createElement('button');
        back.className = 'btn btn-sm btn-outline-secondary';
        back.innerHTML = '<i class="fas fa-arrow-left fa-fw"></i> Back';
        back.style.cursor = 'pointer';
        back.onclick = () => loadBulkMoveFolders(bulkMoveNavHistory.pop() ?? null);
        navButtons.appendChild(back);
    }

    // Up button if not at root
    if (parentId !== null) {
        const up = document.createElement('button');
        up.className = 'btn btn-sm btn-outline-secondary';
        up.innerHTML = '<i class="fas fa-arrow-up fa-fw"></i> Up';
        up.style.cursor = 'pointer';
        up.onclick = async () => {
            try {
                const parentInfo = await apiGet(`/api/folder/${parentId}/parent`);
                bulkMoveNavHistory.push(parentId);
                loadBulkMoveFolders(parentInfo.parent_id);
            } catch (e) {
                console.warn('Could not navigate up:', e);
            }
        };
        navButtons.appendChild(up);
    }
    
    if (navButtons.children.length > 0) {
        list.appendChild(navButtons);
    }

    if (!data.folders.length && parentId === null) {
        list.innerHTML += '<p class="text-secondary small mb-0">No folders yet</p>';
    }

    data.folders.forEach(f => {
        // don't show folders that are being moved
        if (selectedIds.has(f.id)) return;
        const item = document.createElement('div');
        item.className = 'move-folder-item';
        item.innerHTML = `<i class="fas fa-folder fa-fw" style="color:#e3b341"></i> ${esc(f.name)}`;
        item.onclick = () => { bulkMoveNavHistory.push(bulkMoveParentId); loadBulkMoveFolders(f.id); };
        list.appendChild(item);
    });
}

async function doBulkMove() {
    if (!selectedIds.size) return;
    try {
        await apiPost('/api/bulk-move', { ids: [...selectedIds], parent_id: bulkMoveParentId });
        modal('bulkMoveModal').hide();
        exitSelectMode();
        loadFiles(currentParentId);
    } catch (e) { alert(e.message); }
}

// ════════════════════════════════════════════════════════════════════
//  MOVE
// ════════════════════════════════════════════════════════════════════
async function loadMoveFolders(parentId) {
    moveParentId = parentId;
    const url = parentId !== null
        ? `/api/folders?parent_id=${parentId}`
        : '/api/folders';
    const data = await apiGet(url);
    const list = document.getElementById('moveFolderList');
    list.innerHTML = '';

    // Get full breadcrumb path
    let breadcrumbs = [];
    if (parentId !== null) {
        try {
            const bcData = await apiGet(`/api/folder-breadcrumbs/${parentId}`);
            breadcrumbs = bcData.breadcrumbs || [];
        } catch (e) {
            console.warn('Could not load breadcrumbs:', e);
        }
    }

    // Display breadcrumbs with clickable path
    const bc = document.getElementById('moveBreadcrumbs');
    bc.innerHTML = '';
    
    // Build breadcrumb display with clickable components
    const crumbContainer = document.createElement('div');
    crumbContainer.style.display = 'flex';
    crumbContainer.style.alignItems = 'center';
    crumbContainer.style.flexWrap = 'wrap';
    crumbContainer.style.gap = '4px';
    crumbContainer.style.fontSize = '0.9rem';
    
    // Use breadcrumbs array directly (already includes Root from API)
    if (breadcrumbs.length === 0) {
        // Fallback to just showing Root if no breadcrumbs
        const rootCrumb = document.createElement('a');
        rootCrumb.href = '#';
        rootCrumb.style.cursor = 'pointer';
        rootCrumb.className = 'text-primary';
        rootCrumb.textContent = 'Root';
        rootCrumb.onclick = (e) => { e.preventDefault(); loadMoveFolders(null); };
        crumbContainer.appendChild(rootCrumb);
    } else {
        breadcrumbs.forEach((crumb, index) => {
            if (index > 0) {
                const sep = document.createElement('span');
                sep.textContent = '/';
                sep.className = 'text-secondary';
                crumbContainer.appendChild(sep);
            }
            
            const crumbLink = document.createElement('a');
            crumbLink.href = '#';
            crumbLink.style.cursor = 'pointer';
            crumbLink.className = index === breadcrumbs.length - 1 ? 'text-primary' : 'text-info';
            crumbLink.textContent = crumb.name;
            crumbLink.onclick = (e) => { 
                e.preventDefault(); 
                loadMoveFolders(crumb.id); 
            };
            crumbContainer.appendChild(crumbLink);
        });
    }
    
    bc.appendChild(crumbContainer);

    // Navigation buttons container
    const navButtons = document.createElement('div');
    navButtons.style.marginTop = '8px';
    navButtons.style.display = 'flex';
    navButtons.style.gap = '8px';
    navButtons.style.flexWrap = 'wrap';
    
    // Back button - always show if there's history
    if (moveNavHistory && moveNavHistory.length > 0) {
        const back = document.createElement('button');
        back.className = 'btn btn-sm btn-outline-secondary';
        back.innerHTML = '<i class="fas fa-arrow-left fa-fw"></i> Back';
        back.style.cursor = 'pointer';
        back.onclick = () => loadMoveFolders(moveNavHistory.pop() ?? null);
        navButtons.appendChild(back);
    }

    // Up button if not at root
    if (parentId !== null) {
        const up = document.createElement('button');
        up.className = 'btn btn-sm btn-outline-secondary';
        up.innerHTML = '<i class="fas fa-arrow-up fa-fw"></i> Up';
        up.style.cursor = 'pointer';
        up.onclick = async () => {
            try {
                const parentInfo = await apiGet(`/api/folder/${parentId}/parent`);
                moveNavHistory.push(parentId);
                loadMoveFolders(parentInfo.parent_id);
            } catch (e) {
                console.warn('Could not navigate up:', e);
            }
        };
        navButtons.appendChild(up);
    }
    
    if (navButtons.children.length > 0) {
        list.appendChild(navButtons);
    }

    if (!data.folders.length && parentId === null) {
        list.innerHTML += '<p class="text-secondary small mb-0">No folders yet</p>';
    }

    data.folders.forEach(f => {
        // don't show the file being moved (if it's a folder)
        if (contextFile && f.id === contextFile.id) return;
        const item = document.createElement('div');
        item.className = 'move-folder-item';
        item.innerHTML = `<i class="fas fa-folder fa-fw" style="color:#e3b341"></i> ${esc(f.name)}`;
        item.onclick = () => { moveNavHistory.push(moveParentId); loadMoveFolders(f.id); };
        list.appendChild(item);
    });
}

async function doMove() {
    if (!contextFile) return;
    try {
        await apiPost('/api/move', { id: contextFile.id, parent_id: moveParentId });
        modal('moveModal').hide();
        loadFiles(currentParentId);
    } catch (e) { alert(e.message); }
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
            if (searchActive) {
                searchActive = false;
                loadFiles(currentParentId);
            }
            return;
        }
        _searchTimer = setTimeout(() => doSearch(q), 300);
    });

    input.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
            input.value = '';
            clearBtn.classList.add('d-none');
            if (searchActive) {
                searchActive = false;
                loadFiles(currentParentId);
            }
        }
    });

    clearBtn.addEventListener('click', () => {
        input.value = '';
        clearBtn.classList.add('d-none');
        if (searchActive) {
            searchActive = false;
            loadFiles(currentParentId);
        }
        input.focus();
    });
}

async function doSearch(query) {
    show('loadingState'); hide('emptyState'); hide('fileList');
    try {
        const data = await apiGet(`/api/search?q=${encodeURIComponent(query)}&parent_id=${encodeURIComponent(currentParentId)}`);
        searchActive = true;
        currentFiles = data.files;

        // Show search breadcrumb
        const el = document.getElementById('breadcrumbs');
        el.innerHTML = '';
        const span = document.createElement('span');
        span.className = 'crumb active';
        span.textContent = `Search: "${query}" (${data.files.length} result${data.files.length !== 1 ? 's' : ''})`;
        el.appendChild(span);

        renderFiles(sortFiles(currentFiles));
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
    if (currentSort !== 'name') {
        menu.querySelectorAll('.dropdown-item').forEach(el =>
            el.classList.toggle('active', el.dataset.sort === currentSort));
        const label = document.getElementById('sortLabel');
        if (label) label.textContent = SORT_LABELS[currentSort] || currentSort;
    }

    menu.addEventListener('click', e => {
        e.preventDefault();
        const link = e.target.closest('[data-sort]');
        if (!link) return;

        currentSort = link.dataset.sort;
        // Persist sort preference to server
        fetch('/api/preferences', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ sort_preference: currentSort }),
        }).catch(() => { });
        // Update active class
        menu.querySelectorAll('.dropdown-item').forEach(el =>
            el.classList.toggle('active', el.dataset.sort === currentSort));
        // Update label
        const label = document.getElementById('sortLabel');
        if (label) label.textContent = SORT_LABELS[currentSort] || currentSort;

        // Re-render with new sort
        renderFiles(sortFiles(currentFiles));
    });
}

function sortFiles(files) {
    const sorted = [...files];
    switch (currentSort) {
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
        .addEventListener('keydown', e => { if (e.key === 'Enter') createFolder(); });
    document.getElementById('renameInput')
        .addEventListener('keydown', e => { if (e.key === 'Enter') doRename(); });
    const newFileInput = document.getElementById('newFileNameInput');
    if (newFileInput) newFileInput.addEventListener('keydown', e => { if (e.key === 'Enter') createTextFile(); });
}

// ════════════════════════════════════════════════════════════════════
//  API HELPERS
// ════════════════════════════════════════════════════════════════════
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
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Request failed');
    return data;
}

// ════════════════════════════════════════════════════════════════════
//  UTILITIES
// ════════════════════════════════════════════════════════════════════
function show(id) { document.getElementById(id).style.display = ''; }
function hide(id) { document.getElementById(id).style.display = 'none'; }

function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function humanSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const v = bytes / Math.pow(1024, i);
    return v.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

function relTime(iso) {
    if (!iso) return '';
    const d = new Date(iso + 'Z');  // assume UTC from SQLite
    const now = new Date();
    const diff = (now - d) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
    return d.toLocaleDateString();
}

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

// ════════════════════════════════════════════════════════════════════
//  TOAST NOTIFICATIONS
// ════════════════════════════════════════════════════════════════════
function showToast(message, type = 'info', duration = 6000) {
    const container = document.getElementById('toastContainer');
    if (!container) { alert(message); return; }

    const colors = {
        info: { bg: '#1e3a5f', border: '#3b82f6', icon: 'fa-info-circle', iconColor: '#60a5fa' },
        success: { bg: '#1a3a2a', border: '#22c55e', icon: 'fa-check-circle', iconColor: '#4ade80' },
        error: { bg: '#3a1a1a', border: '#ef4444', icon: 'fa-exclamation-circle', iconColor: '#f87171' },
        warning: { bg: '#3a2f1a', border: '#f59e0b', icon: 'fa-exclamation-triangle', iconColor: '#fbbf24' },
    };
    const c = colors[type] || colors.info;

    const toast = document.createElement('div');
    toast.style.cssText = `
        background:${c.bg}; border:1px solid ${c.border}; border-radius:8px;
        padding:12px 16px; color:#e0e0e0; font-size:13px; max-width:380px;
        box-shadow:0 4px 12px rgba(0,0,0,.4); display:flex; align-items:flex-start;
        gap:10px; opacity:0; transform:translateY(20px); transition:all .3s ease;
    `;
    toast.innerHTML = `
        <i class="fas ${c.icon}" style="color:${c.iconColor};margin-top:2px;flex-shrink:0"></i>
        <span style="flex:1;line-height:1.4">${message}</span>
        <i class="fas fa-times" style="cursor:pointer;opacity:.5;margin-top:2px;flex-shrink:0"
           onclick="this.parentElement.remove()"></i>
    `;
    container.appendChild(toast);
    requestAnimationFrame(() => {
        toast.style.opacity = '1';
        toast.style.transform = 'translateY(0)';
    });
    if (duration > 0) {
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(20px)';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
}

// ════════════════════════════════════════════════════════════════════
//  RE-ENCODE STATUS POLLER
// ════════════════════════════════════════════════════════════════════
let _reencodePollerInterval = null;

function startReencodePoller() {
    if (_reencodePollerInterval) return; // already running
    _reencodePollerInterval = setInterval(pollReencodeStatus, 5000);
}

async function pollReencodeStatus() {
    try {
        const resp = await fetch('/api/reencode-status', { credentials: 'same-origin' });
        const data = await resp.json();
        for (const job of (data.jobs || [])) {
            const name = job.file_name || `file #${job.file_id}`;
            if (job.status === 'done') {
                showToast(`✓ Re-encode complete: ${name}`, 'success', 8000);
            } else if (job.status === 'skipped') {
                showToast(`⊘ Already browser-compatible: ${name}`, 'warning', 6000);
            } else if (job.status === 'error') {
                showToast(`✗ Re-encode failed: ${name}` + (job.error ? ` — ${job.error}` : ''), 'error', 10000);
            }
        }
        // Update badge with active count
        updateQueueBadge((data.running || 0) + (data.queued || 0));
        // Stop polling only when no finished AND no running/queued jobs
        if ((!data.jobs || !data.jobs.length) && !data.running && !data.queued) {
            clearInterval(_reencodePollerInterval);
            _reencodePollerInterval = null;
        }
    } catch (e) {
        console.error('Re-encode status poll failed:', e);
    }
}

// ════════════════════════════════════════════════════════════════════
//  QUEUE PANEL
// ════════════════════════════════════════════════════════════════════
let _queueRefreshInterval = null;

function openQueuePanel() {
    modal('queueModal').show();
    refreshQueuePanel();
    // Auto-refresh while modal is open
    _queueRefreshInterval = setInterval(refreshQueuePanel, 3000);
    document.getElementById('queueModal').addEventListener('hidden.bs.modal', () => {
        clearInterval(_queueRefreshInterval);
        _queueRefreshInterval = null;
    }, { once: true });
}

async function refreshQueuePanel() {
    try {
        const resp = await fetch('/api/reencode-jobs', { credentials: 'same-origin' });
        const data = await resp.json();
        const list = document.getElementById('queueJobList');
        const jobs = data.jobs || [];

        if (!jobs.length) {
            list.innerHTML = '<p class="text-secondary small mb-0 text-center py-3"><i class="fas fa-inbox me-2"></i>No re-encode jobs</p>';
            document.getElementById('queueSummary').textContent = '';
            document.getElementById('clearFinishedBtn').style.display = 'none';
            updateQueueBadge(0);
            return;
        }

        // Sort: running first, then queued, then finished
        const order = { running: 0, queued: 1, done: 2, skipped: 3, error: 4 };
        jobs.sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9));

        const running = jobs.filter(j => j.status === 'running').length;
        const queued = jobs.filter(j => j.status === 'queued').length;
        const finished = jobs.filter(j => ['done', 'error', 'skipped'].includes(j.status)).length;

        list.innerHTML = jobs.map(j => {
            const name = esc(j.file_name || `file #${j.file_id}`);
            const s = j.status;
            let badge, icon, borderColor;

            if (s === 'running') {
                badge = '<span class="badge bg-primary">Running</span>';
                icon = '<div class="spinner-border spinner-border-sm text-primary" role="status"></div>';
                borderColor = '#3b82f6';
            } else if (s === 'queued') {
                badge = '<span class="badge bg-secondary">Queued</span>';
                icon = '<i class="fas fa-clock text-secondary"></i>';
                borderColor = '#6b7280';
            } else if (s === 'done') {
                badge = '<span class="badge bg-success">Done</span>';
                icon = '<i class="fas fa-check-circle text-success"></i>';
                borderColor = '#22c55e';
            } else if (s === 'skipped') {
                badge = '<span class="badge bg-warning text-dark">Skipped</span>';
                icon = '<i class="fas fa-forward text-warning"></i>';
                borderColor = '#f59e0b';
            } else {
                badge = '<span class="badge bg-danger">Error</span>';
                icon = '<i class="fas fa-exclamation-circle text-danger"></i>';
                borderColor = '#ef4444';
            }

            let timeInfo = '';
            if (j.started) {
                const elapsed = j.finished
                    ? Math.round(j.finished - j.started)
                    : Math.round(Date.now() / 1000 - j.started);
                const min = Math.floor(elapsed / 60);
                const sec = elapsed % 60;
                timeInfo = min > 0 ? `${min}m ${sec}s` : `${sec}s`;
                timeInfo = j.finished ? `took ${timeInfo}` : `${timeInfo} elapsed`;
            }

            const errorLine = j.error
                ? `<div class="small text-danger mt-1" style="font-size:.75rem">${esc(j.error)}</div>`
                : '';

            return `
                <div style="border-left:3px solid ${borderColor};background:#1a1d23;border-radius:6px;padding:10px 14px">
                    <div class="d-flex align-items-center gap-2">
                        ${icon}
                        <span class="flex-grow-1 text-truncate" style="font-size:.9rem">${name}</span>
                        ${badge}
                    </div>
                    ${timeInfo ? `<div class="text-secondary mt-1" style="font-size:.75rem">${timeInfo}</div>` : ''}
                    ${errorLine}
                </div>
            `;
        }).join('');

        // Summary
        const parts = [];
        if (running) parts.push(`${running} running`);
        if (queued) parts.push(`${queued} queued`);
        if (finished) parts.push(`${finished} finished`);
        document.getElementById('queueSummary').textContent = parts.join(' · ');

        // Show/hide clear button
        document.getElementById('clearFinishedBtn').style.display = finished ? '' : 'none';

        updateQueueBadge(running + queued);
    } catch (e) {
        console.error('Queue panel refresh failed:', e);
    }
}

async function clearFinishedJobs() {
    try {
        await fetch('/api/reencode-clear', { method: 'POST', credentials: 'same-origin' });
        refreshQueuePanel();
    } catch (e) {
        console.error('Clear finished jobs failed:', e);
    }
}

function updateQueueBadge(activeCount) {
    const badge = document.getElementById('queueBadge');
    if (!badge) return;
    if (activeCount > 0) {
        badge.textContent = activeCount;
        badge.style.display = '';
    } else {
        badge.style.display = 'none';
    }
}
