'use strict';

// ════════════════════════════════════════════════════════════════════
//  Upload handling: single file upload, folder upload with dir creation,
//  drag-and-drop setup and traversal.
//
// Shared state variables are defined at top of app.js; this module
// reads/writes them directly to maintain exact behavioral equivalence.
// ════════════════════════════════════════════════════════════════════

(function() {
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

function uploadFiles(fileList) {
    if (!fileList || !fileList.length) return;
    // Check if this is a folder upload (files have webkitRelativePath)
    const hasRelativePaths = fileList[0] && fileList[0].webkitRelativePath;
    if (hasRelativePaths) {
        uploadFolder(fileList);
    } else {
        for (const f of fileList) window._uploadQueue.push({ file: f, parentId: window._currentParentId });
        document.getElementById('fileInput').value = '';
        processQueue();
    }
}

async function uploadFolder(fileList) {
    // Collect unique directory paths and create them first
    const dirCache = {};   // relative path → server folder id
    const rootParent = window._currentParentId;

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
        window._uploadQueue.push({ file: f, parentId });
    }

    document.getElementById('folderInput').value = '';
    processQueue();
}

async function processQueue() {
    if (window._uploading || !window._uploadQueue.length) return;
    window._uploading = true;
    show('uploadProgress');

    while (window._uploadQueue.length) {
        const item = window._uploadQueue.shift();
        await uploadOne(item.file, item.parentId);
    }

    hide('uploadProgress');
    window._uploading = false;
    App.loadFiles(window._currentParentId);
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
                    showToast('Upload failed: ' + (err.error || 'unknown error'), 'error');
                } catch { showToast('Upload failed', 'error'); }
            }
            resolve();
        };
        xhr.onerror = () => { showToast('Upload network error', 'error'); resolve(); };
        xhr.send(fd);
    });
}

// ── drag & drop ────────────────────────────────────────────────
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

// ── drag & drop folder traversal ───────────────────────────────
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
        for (const f of files) window._uploadQueue.push({ file: f, parentId: window._currentParentId });
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
    const rootParent = window._currentParentId;

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
        window._uploadQueue.push({ file, parentId });
    }
    processQueue();
}

// ════════════════════════════════════════════════════════════════════
//  PUBLIC API — exposed via window.App for template onclicks
// ════════════════════════════════════════════════════════════════════
    const UploadManager = { uploadFiles, processQueue, handleDropItems, setupDragDrop };

    window.App = Object.assign(window.App || {}, UploadManager);
})();
