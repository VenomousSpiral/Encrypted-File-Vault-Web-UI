'use strict';

// ════════════════════════════════════════════════════════════════════
//  Re-encode operations + queue panel / status polling.
// ════════════════════════════════════════════════════════════════════

(function() {
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
            showToast('Cleared ' + (data.cleared || 0) + ' cached audio track(s).', 'success');
        } else {
            showToast('Error: ' + (data.error || 'Unknown'), 'error');
        }
    } catch (e) { showToast('Request failed: ' + e.message, 'error'); }
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

function updateQueueBadge(count) {
    const badge = document.getElementById('queueBadge');
    if (!badge) return;
    if (count > 0) {
        badge.style.display = '';
        badge.textContent = count > 9 ? '9+' : String(count);
    } else {
        badge.style.display = 'none';
    }
}

// ════════════════════════════════════════════════════════════════════
//  PUBLIC API — exposed via window.App for template onclicks
// ════════════════════════════════════════════════════════════════════
    const ReencodeManager = { reencodeFile, reencodeDir, clearAudioCache };
    const QueueManager  = { openQueuePanel, refreshQueuePanel, startReencodePoller, pollReencodeStatus, clearFinishedJobs };

    window.App = Object.assign(window.App || {}, ReencodeManager, QueueManager);
})();
