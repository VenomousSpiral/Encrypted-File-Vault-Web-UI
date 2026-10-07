'use strict';

// ════════════════════════════════════════════════════════════════════
//  Multi-select mode: enter/exit, toggle/range/select-all, bulk actions.
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

function enterSelectMode() {
    window._selectMode = true;
    document.querySelectorAll('.select-checkbox').forEach(el => el.classList.add('visible'));
    updateBulkBar();
}

function exitSelectMode() {
    window._selectMode = false;
    window._selectedIds.clear();
    document.querySelectorAll('.select-checkbox').forEach(el => el.classList.remove('visible'));
    document.querySelectorAll('.file-row.selected').forEach(el => el.classList.remove('selected'));
    // Update checkbox icons
    document.querySelectorAll('.select-checkbox i').forEach(el => {
        el.className = 'fas fa-square';
    });
    updateBulkBar();
}

function toggleSelect(fileId) {
    if (!window._selectMode) enterSelectMode();
    if (window._selectedIds.has(fileId)) {
        window._selectedIds.delete(fileId);
    } else {
        window._selectedIds.add(fileId);
    }
    // Update visual
    const row = document.querySelector(`.file-row[data-id="${fileId}"]`);
    if (row) {
        row.classList.toggle('selected', window._selectedIds.has(fileId));
        const icon = row.querySelector('.select-checkbox i');
        if (icon) icon.className = window._selectedIds.has(fileId) ? 'fas fa-check-square' : 'fas fa-square';
    }
    if (window._selectedIds.size === 0) {
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
        if (window._selectedIds.has(rowIds[i]) && rowIds[i] !== targetId) {
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
        window._selectedIds.add(fid);
        rows[i].classList.add('selected');
        const icon = rows[i].querySelector('.select-checkbox i');
        if (icon) icon.className = 'fas fa-check-square';
    }
    updateBulkBar();
}

function selectAll() {
    if (!window._selectMode) enterSelectMode();
    window._currentFiles.forEach(f => window._selectedIds.add(f.id));
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
    if (window._selectMode && window._selectedIds.size > 0) {
        bar.style.display = '';
        document.getElementById('bulkCount').textContent = `${window._selectedIds.size} selected`;
    } else {
        bar.style.display = 'none';
    }
}

async function bulkDelete() {
    if (!window._selectedIds.size) { showToast('No items selected', 'info'); return; }
    const count = window._selectedIds.size;
    const ok3 = await App.confirmDialog('Delete Items', `Delete ${count} item${count > 1 ? 's' : ''}?\nThis cannot be undone.`);
        if (!ok3) return;
    try {
        await apiPost('/api/bulk-delete', { ids: [...window._selectedIds] });
        App.exitSelectMode();
        App.loadFiles(window._currentParentId);
    } catch (e) { showToast(e.message, 'error'); }
}

    let _bulkMoveParentId = null;
    let _bulkMoveNavHistory = [];

async function showBulkMoveModal() {
    if (!window._selectedIds.size) return;
    _bulkMoveNavHistory = [];
    await loadBulkMoveFolders(null);
    modal('bulkMoveModal').show();
}

async function loadBulkMoveFolders(parentId) {
    _bulkMoveParentId = parentId;
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
    if (_bulkMoveNavHistory && _bulkMoveNavHistory.length > 0) {
        const back = document.createElement('button');
        back.className = 'btn btn-sm btn-outline-secondary';
        back.innerHTML = '<i class="fas fa-arrow-left fa-fw"></i> Back';
        back.style.cursor = 'pointer';
        back.onclick = () => loadBulkMoveFolders(_bulkMoveNavHistory.pop() ?? null);
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
                _bulkMoveNavHistory.push(parentId);
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
        if (window._selectedIds.has(f.id)) return;
        const item = document.createElement('div');
        item.className = 'move-folder-item';
        item.innerHTML = `<i class="fas fa-folder fa-fw" style="color:#e3b341"></i> ${esc(f.name)}`;
        item.onclick = () => { _bulkMoveNavHistory.push(_bulkMoveParentId); loadBulkMoveFolders(f.id); };
        list.appendChild(item);
    });
}

async function doBulkMove() {
    if (!window._selectedIds.size) return;
    try {
        await apiPost('/api/bulk-move', { ids: [...window._selectedIds], parent_id: _bulkMoveParentId });
        modal('bulkMoveModal').hide();
        App.exitSelectMode();
        App.loadFiles(window._currentParentId);
    } catch (e) { showToast(e.message, 'error'); }
}

// ════════════════════════════════════════════════════════════════════
//  PUBLIC API — exposed via window.App for template onclicks
// ════════════════════════════════════════════════════════════════════
    const SelectionManager = {
        enterSelectMode, exitSelectMode, toggleSelect, rangeSelect, selectAll,
        updateBulkBar, bulkDelete, showBulkMoveModal, doBulkMove
    };

    window.App = Object.assign(window.App || {}, SelectionManager);
})();
