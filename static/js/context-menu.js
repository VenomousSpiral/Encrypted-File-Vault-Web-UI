'use strict';

// ════════════════════════════════════════════════════════════════════
//  Context menu + modal dialogs: show/hide context menus, action routing,
//  new folder/file modals, rename/delete confirmations, move operations.
//
// Shared state variables are defined at top of app.js; this module
// reads/writes them directly to maintain exact behavioral equivalence.
// ════════════════════════════════════════════════════════════════════

(function() {
    // ── Bootstrap modal helper (local to this module) ────────────
    const modal = id => bootstrap.Modal.getOrCreateInstance(document.getElementById(id));

    // ── Toast notifications (local to this module, matches original app.js behavior) ──
    function showToast(message, type = 'info', duration = 6000) {
        const container = document.getElementById('toastContainer');
        if (!container) { console.warn('[Toast]', message); return; }

        const colors = {
            info:     { bg:'#1e3a5f', border:'#3b82f6', icon:'fa-info-circle',   color:'#60a5fa' },
            success:  { bg:'#1a3a2a', border:'#22c55e', icon:'fa-check-circle', color:'#4ade80' },
            error:    { bg:'#3a1a1a', border:'#ef4444', icon:'fa-exclamation-circle',color:'#f87171' },
            warning:  { bg:'#3a2f1a', border:'#f59e0b', icon:'fa-exclamation-triangle',color:'#fbbf24' },
        };
        const c = colors[type] || colors.info;

        const toast = document.createElement('div');
        Object.assign(toast.style, {
            background:c.bg, border:`1px solid ${c.border}`, borderRadius:'8px',
            padding:'12px 16px', color:'#e0e0e0', fontSize:'13px', maxWidth:'380px',
            boxShadow:'0 4px 12px rgba(0,0,0,.4)', display:'flex', alignItems:'flex-start',
            gap:'10px', opacity:0, transform:'translateY(20px)', transition:'all .3s ease'
        });
        toast.innerHTML = `
            <i class="fas ${c.icon}" style="color:${c.color};margin-top:2px;flex-shrink:0"></i>
            <span style="flex:1;line-height:1.4">${message}</span>
            <i class="fas fa-times" style="cursor:pointer;opacity:.5;margin-top:2px;flex-shrink:0"
               onclick="this.parentElement.remove()"></i>`;

        container.appendChild(toast);
        requestAnimationFrame(() => { toast.style.opacity='1'; toast.style.transform='translateY(0)'; });
        if (duration > 0) {
            setTimeout(()=>{ toast.style.opacity='0'; toast.style.transform='translateY(20px)'; }, duration);
        }
    }

// ── CONTEXT MENU SETUP & ACTIONS ───────────────────────────────
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
    window._contextFile = file;
    console.log('[DEBUG] showCtx called, setting window._contextFile:', file?.name || 'unknown');

    // Show/hide Edit option based on whether file is text-editable
    const editItem = document.getElementById('ctxEdit');
    if (editItem) {
        editItem.style.display = (!file.is_directory && App.isTextEditable(file)) ? '' : 'none';
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

    // Show the context menu
    console.log('[DEBUG] showCtx: showing menu for', file.name);
    const menu = document.getElementById('contextMenu');
    if (!menu) { console.error('[ERROR] #contextMenu not found in DOM!'); return; }
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

async function handleCtxAction(action) {
    if (!window._contextFile) return;
    const f = window._contextFile;

    switch (action) {
        case 'open':
            App.openFile(f);
            break;
        case 'edit':
            if (!f.is_directory) window.location.href = '/editor/' + f.id;
            break;
        case 'download':
            if (f.is_directory) {
                window.location.href = '/download-folder/' + f.id;
            } else {
                window.location.href = '/download/' + f.id;
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
            window._moveNavHistory = [];
            loadMoveFolders(window._currentParentId);
            modal('moveModal').show();
            break;
        case 'delete':
            document.getElementById('deleteFileName').textContent = f.name;
            modal('deleteModal').show();
            break;
        case 'reencode':
            const ok1 = await App.confirmDialog('Re-encode Video', 'Re-encode "' + f.name + '" to H.264 + AAC for browser playback?\n\nThis will permanently replace the original file.');
            if (!ok1) break;
            App.reencodeFile(f);
            break;
        case 'reencode-dir':
            const ok2 = await App.confirmDialog('Re-encode Directory', 'Re-encode ALL video files in "' + f.name + '" to H.264 + AAC?\n\nThis processes files one at a time.');
            if (!ok2) break;
            App.reencodeDir(f);
            break;
        case 'clear-audio-cache':
            App.clearAudioCache(f);
            break;
    }
}

// ════════════════════════════════════════════════════════════════════
//  NEW FOLDER / TEXT FILE MODALS
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
        const data = await apiPost('/api/create-text', { name, parent_id: window._currentParentId });
        modal('newFileModal').hide();
        // Open directly in editor
        window.location.href = '/editor/' + data.id;
    } catch (e) { showToast(e.message, 'error'); }
}

async function createFolder() {
    const name = document.getElementById('folderNameInput').value.trim();
    const err = App.Validators.folderName(name);
    if (err) { showToast(err, 'warning'); return; }
    try {
        await apiPost('/api/mkdir', { name, parent_id: window._currentParentId });
        modal('newFolderModal').hide();
        App.loadFiles(window._currentParentId);
    } catch (e) { showToast(e.message, 'error'); }
}

// ════════════════════════════════════════════════════════════════════
//  RENAME / DELETE MODALS
// ════════════════════════════════════════════════════════════════════
async function doRename() {
    if (!window._contextFile) return;
    const name = document.getElementById('renameInput').value.trim();
    const err = App.Validators.folderName(name);
    if (err) { showToast(err, 'warning'); return; }
    try {
        await apiPost('/api/rename', { id: window._contextFile.id, name });
        modal('renameModal').hide();
        App.loadFiles(window._currentParentId);
    } catch (e) { showToast(e.message, 'error'); }
}

async function doDelete() {
    if (!window._contextFile) return;
    try {
        await apiPost('/api/delete', { id: window._contextFile.id });
        modal('deleteModal').hide();
        App.loadFiles(window._currentParentId);
    } catch (e) { showToast(e.message, 'error'); }
}

// ════════════════════════════════════════════════════════════════════
//  MOVE OPERATIONS (single file + bulk move share similar folder picker)
// ════════════════════════════════════════════════════════════════════
async function loadMoveFolders(parentId) {
    window._moveParentId = parentId;
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
    if (window._moveNavHistory && window._moveNavHistory.length > 0) {
        const back = document.createElement('button');
        back.className = 'btn btn-sm btn-outline-secondary';
        back.innerHTML = '<i class="fas fa-arrow-left fa-fw"></i> Back';
        back.style.cursor = 'pointer';
        back.onclick = () => loadMoveFolders(window._moveNavHistory.pop() ?? null);
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
                window._moveNavHistory.push(parentId);
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
        if (window._contextFile && f.id === window._contextFile.id) return;
        const item = document.createElement('div');
        item.className = 'move-folder-item';
        item.innerHTML = `<i class="fas fa-folder fa-fw" style="color:#e3b341"></i> ${esc(f.name)}`;
        item.onclick = () => { window._moveNavHistory.push(window._moveParentId); loadMoveFolders(f.id); };
        list.appendChild(item);
    });
}

async function doMove() {
    if (!window._contextFile) return;
    try {
        await apiPost('/api/move', { id: window._contextFile.id, parent_id: window._moveParentId });
        modal('moveModal').hide();
        App.loadFiles(window._currentParentId);
    } catch (e) { showToast(e.message, 'error'); }
}

// ════════════════════════════════════════════════════════════════════
//  PUBLIC API — exposed via window.App for template onclicks
// ════════════════════════════════════════════════════════════════════
    const DialogManager = {
        setupContextMenu, showNewFolderModal, showNewFileModal, createTextFile, createFolder,
        showCtx, hideCtx, handleCtxAction, doRename, doDelete,
        loadMoveFolders, doMove
    };

    window.App = Object.assign(window.App || {}, DialogManager);
})();
