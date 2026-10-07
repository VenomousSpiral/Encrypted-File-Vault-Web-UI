'use strict';

// ════════════════════════════════════════════════════════════════════
//  Unified Dialog / Toast System — replaces alert()/confirm() scattered in app.js
// ════════════════════════════════════════════════════════════════════
(function(){

    // ── Toast notifications (moved from app.js) ────────────────
    function showToast(message, type = 'info', duration = 6000) {
        const container = document.getElementById('toastContainer');
        if (!container) return;

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
        setTimeout(()=>{ toast.style.opacity='0'; toast.style.transform='translateY(-20px)'; }, duration);
        setTimeout(()=>{ if (toast.parentElement) toast.remove(); }, duration + 350);
    }

    // ── Async confirmation dialog (replaces window.confirm) ────
    function confirmDialog(title, message, okText = 'Confirm', cancelText = 'Cancel') {
        return new Promise(resolve => {
            const overlay = document.createElement('div');
            Object.assign(overlay.style, {
                position:'fixed', top:0, left:0, width:'100vw', height:'100vh',
                background:'rgba(0,0,0,.5)', display:'flex', alignItems:'center',
                justifyContent:'center', zIndex:9999
            });

            const dialog = document.createElement('div');
            Object.assign(dialog.style, {
                background:'#1e2d3d', borderRadius:'12px', padding:'24px 28px',
                minWidth:'360px', maxWidth:'520px', boxShadow:'0 8px 32px rgba(0,0,0,.5)',
                display:'flex', flexDirection:'column', gap:'16px'
            });

            dialog.innerHTML = `
                <h4 style="margin:0;color:#e0e0e0;font-size:17px">${title}</h4>
                <p style="margin:0;color:#a0aec0;font-size:14px;line-height:1.5;white-space:pre-line">${message}</p>
                <div style="display:flex;justify-content:flex-end;gap:8px">
                    <button class="btn btn-sm btn-outline-secondary" data-action="cancel">${cancelText}</button>
                    <button class="btn btn-sm btn-primary" data-action="ok">${okText}</button>
                </div>`;

            overlay.appendChild(dialog);
            document.body.appendChild(overlay);

            const close = (result) => {
                if (document.body.contains(overlay)) overlay.remove();
                resolve(result);
            };

            dialog.addEventListener('click', e => {
                if (e.target.dataset.action === 'ok')  close(true);
                else                                    close(false);
            });

            // Close on backdrop click or Escape key  
            overlay.addEventListener('click', e => { if (e.target === overlay) close(false); });
            const handler = (ev) => { if (ev.key === 'Escape') { document.removeEventListener('keydown', handler); close(false); }; };
            document.addEventListener('keydown', handler);
        });
    }

    // Expose to global App namespace  
    window.App = Object.assign(window.App || {}, { showToast, confirmDialog });

})();
