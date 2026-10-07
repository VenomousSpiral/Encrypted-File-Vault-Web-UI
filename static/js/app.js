'use strict';

// ════════════════════════════════════════════════════════════════════
//  Encrypted Vault – main entry point.
//
// Orchestrates shared state and initializes all extracted modules:
//   explorer-core.js  — file listing, rendering, search/sort
//   uploader.js        — drag-drop + upload queue
//   selection.js       — multi-select mode
//   context-menu.js    — context menus + modals (rename/delete/move)
//   reencode-queue.js  — re-encode operations + status polling
//
// Shared state: all modules read/write these globals directly.
// ════════════════════════════════════════════════════════════════════

(function() {
    // ── shared state (all other modules read/write these) ───────
    window._currentParentId  = null;   // null = root
    window._contextFile      = null;       // file object for context-menu target
    window._moveParentId     = null;      // current folder inside Move dialog
    window._moveNavHistory   = [];      // back-stack for Move dialog navigation
    window._uploadQueue      = [];         // pending upload items
    window._uploading        = false;
    window._currentSort      = (typeof window.__SORT_PREF    !== 'undefined' ? window.__SORT_PREF    : 'name');
    window._showDirSize      = typeof window.__SHOW_DIR_SIZE === 'boolean'   ? window.__SHOW_DIR_SIZE : false;
    window._currentFiles     = [];     // raw file list from server (for re-sorting)
    window._searchActive     = false;  // true when showing search results
    window._selectMode       = false;         // true when multi-select is active
    window._selectedIds      = new Set();   // set of selected file IDs

// ── DOMContentLoaded bootstrap ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Check URL for initial parent_id (e.g. returning from player)
    const params = new URLSearchParams(window.location.search);
    const initParent = params.has('parent_id') ? parseInt(params.get('parent_id')) : null;

    // Start file listing
    App.loadFiles(isNaN(initParent) ? null : initParent);

    // Wire up event handlers (order doesn't matter for correctness, but matches original)
    App.setupDragDrop();
    App.setupContextMenu();
    App.setupModalEnter();
    App.setupSearch();
    App.setupSort();
    setupGlobalActionDelegation();

        // Keyboard shortcuts for multi-select
    document.addEventListener('keydown', (e) => {
        // Escape exits select mode
        if (e.key === 'Escape' && _selectMode) {
            App.exitSelectMode();
            e.preventDefault();
        }
        // Ctrl+A / Cmd+A selects all when in select mode (or file list focused)
        if ((e.ctrlKey || e.metaKey) && e.key === 'a' && !e.target.closest('input, textarea, [contenteditable]')) {
            e.preventDefault();
            App.selectAll();
        }
    });
});

// ════════════════════════════════════════════════════════════════════
//  GLOBAL ACTION DELEGATION — replaces onclick attributes in templates
// ════════════════════════════════════════════════════════════════════
function setupGlobalActionDelegation() {
    document.addEventListener('click', e => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;

        switch (btn.dataset.action) {
            // Explorer toolbar buttons (open modals)
            case 'new-folder':          App.showNewFolderModal(); break;
            case 'new-file':            App.showNewFileModal(); break;
            case 'do-rename':           App.doRename(); break;
            case 'do-move':             App.doMove(); break;
            case 'do-delete':           App.doDelete(); break;
            case 'delete-selected':     App.bulkDelete(); break;
            case 'bulk-delete':         App.bulkDelete(); break;
            case 'select-all':          App.selectAll(); break;
            case 'exit-select-mode':    App.exitSelectMode(); break;

            // Folder/file creation (inside modals)
            case 'create-folder':       App.createFolder(); break;
            case 'create-text-file':    App.createTextFile(); break;

            // Selection actions
            case 'enter-select-mode':   App.enterSelectMode(); break;
            case 'show-bulk-move-modal':App.showBulkMoveModal(); break;
            case 'do-bulk-move':        App.doBulkMove(); break;

            // Queue / reencode
            case 'open-queue-panel':    App.openQueuePanel(); break;
            case 'clear-finished-jobs': App.clearFinishedJobs(); break;

            default: console.warn('Unknown action:', btn.dataset.action);
        }
    });

    // Handle [data-toggle] buttons (upload files / folder)
    document.addEventListener('click', e => {
        const btn = e.target.closest('[data-toggle]');
        if (!btn) return;

        switch (btn.dataset.toggle) {
            case 'upload-files':
                document.getElementById('fileInput').click(); break;
            case 'upload-folder':
                document.getElementById('folderInput').click(); break;
            default:
                console.warn('Unknown toggle:', btn.dataset.toggle);
        }
    });
}

// ════════════════════════════════════════════════════════════════════
//  PUBLIC API — exposed via window.App for template onclicks
// Each group is a named object; functions also available as App.functionName()
// ════════════════════════════════════════════════════════════════════

    // Modal actions are defined by their respective modules (context-menu.js, etc.)
    // and exported via window.App. No stubs needed here.

    window.App = Object.assign(window.App || {},
        // Utilities (also available as App.esc(), etc.)
        { show, hide, esc, humanSize, relTime, getIconClass }
    );
})();
