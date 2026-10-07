"use strict";
/* ═══════════════════════════════════════════════════════════
   Shared file navigation module (prev / next / shuffle / recurse)
   Works for ALL file types: video, audio, images, PDFs, text.

   Supports two button naming conventions:
     - Standard:  #prevBtn, #nextBtn, #shuffleBtn, #recurseBtn, #navPos
     - Audio:     #audioPrevBtn, #audioNextBtn, #audioShuffleBtn, #audioRecurseBtn, #navStatus

   Reads settings from URL params → localStorage; persists to
   sessionStorage across page navigations.

   Exposes public API via window.FileNav for other scripts that need
   to trigger navigation programmatically (e.g., video player controls).
   ═══════════════════════════════════════════════════════════ */
(function() {

    // ── Config from server-side template ────────────────────────
    var fileId = window.__PLAYER_CONFIG ? parseInt(window.__PLAYER_CONFIG.fileId, 10) : null;
    if (!fileId || isNaN(fileId)) return;  // not a navigable file

    /* Detect which button naming convention is used */
    var standardButtons = document.getElementById('prevBtn') && document.getElementById('nextBtn');
    var audioButtons    = document.getElementById('audioPrevBtn') && document.getElementById('audioNextBtn');

    if (!standardButtons && !audioButtons) return;  // no nav elements on this page

    /* Resolve button references based on naming convention */
    var prevBtn   = standardButtons ? document.getElementById('prevBtn') : null;
    var nextBtn   = standardButtons ? document.getElementById('nextBtn') : null;
    var shuffleBtn = standardButtons ? document.getElementById('shuffleBtn') : (audioButtons ? document.getElementById('audioShuffleBtn') : null);
    var recurseBtn = standardButtons ? document.getElementById('recurseBtn') : (audioButtons ? document.getElementById('audioRecurseBtn') : null);
    var navPos   = standardButtons ? document.getElementById('navPos') : (audioButtons ? document.getElementById('navStatus') : null);

    // ── Read state: URL params → localStorage, with sensible defaults ──
    var urlParams = new URLSearchParams(window.location.search);

    /* Shuffle: default OFF */
    var shuffleOn = false;
    if (urlParams.has('shuffle')) {
        shuffleOn = !['0', 'no', 'false'].includes(urlParams.get('shuffle').trim());
    } else {
        shuffleOn = localStorage.getItem('vault_shuffle') === '1';
    }

    /* Recurse: default ON */
    var recurseOn = true;
    if (urlParams.has('recurse')) {
        recurseOn = !['0', 'no', 'false'].includes(urlParams.get('recurse').trim());
    } else {
        recurseOn = localStorage.getItem('vault_recurse') !== '0';
    }

    /* Sort: default "name" */
    var currentSort = 'name';
    if (urlParams.has('sort_by')) {
        var sv = urlParams.get('sort_by').trim().toLowerCase();
        if (['name', 'recent', 'added', 'size'].indexOf(sv) !== -1) {
            currentSort = sv;
            localStorage.setItem('vault_sort_pref', currentSort);
        }
    } else {
        var storedSort = localStorage.getItem('vault_sort_pref');
        if (storedSort && ['name', 'recent', 'added', 'size'].indexOf(storedSort) !== -1) {
            currentSort = storedSort;
        }
    }

    /* Root context: where the browsing tree started */
    var rootParentId = null;
    if (urlParams.has('from')) {
        rootParentId = urlParams.get('from') === 'root' ? 'null' : urlParams.get('from');
        localStorage.setItem('vault_shuffle_root', rootParentId);
    } else {
        var storedRoot = localStorage.getItem('vault_shuffle_root');
        if (storedRoot !== null) rootParentId = storedRoot;
    }

    // ── Initialise UI state from current settings ───────────────
    function updateButtonStates() {
        /* Standard buttons */
        if (shuffleBtn && standardButtons) shuffleBtn.classList.toggle('active', shuffleOn);
        if (recurseBtn && standardButtons) recurseBtn.classList.toggle('active', recurseOn);

        var labelEl = null;
        if (recurseBtn && standardButtons) {
            labelEl = recurseBtn.querySelector('.d-none.d-md-inline, span');
        } else if (recurseBtn && audioButtons) {
            // Audio buttons don't have labels but use active-recurse class
            recurseBtn.classList.toggle('active-recurse', recurseOn);
        }

        /* Audio-specific shuffle styling */
        if (shuffleBtn && audioButtons) {
            shuffleBtn.classList.toggle('active-shuffle', shuffleOn);
        }

        // Update label text for standard buttons
        if (labelEl) {
            labelEl.textContent = recurseOn ? 'Recursive' : 'Current Dir Only';
        }
    }
    updateButtonStates();

    // ── Session history stacks (survive page navigations via sessionStorage) ─
    function loadHistory(mode) {
        try { return JSON.parse(sessionStorage.getItem('vault_nav_' + mode)); } catch(e) { return null; }
    }
    function saveHistory(mode, data) { sessionStorage.setItem('vault_nav_' + mode, JSON.stringify(data)); }

    var normalNav = loadHistory('normal') || { history: [], idx: -1 };
    var shuffleNav = loadHistory('shuffle')  || { history: [], idx: -1 };

    // ── Initialise history when entering from explorer (first visit) ─
    if (urlParams.has('from')) {
        normalNav.history.push(fileId);
        normalNav.idx   = normalNav.history.length - 1;
        shuffleNav.history.push(fileId);
        shuffleNav.idx  = shuffleNav.history.length - 1;
        saveHistory('normal', normalNav);
        saveHistory('shuffle', shuffleNav);
    }

    // ── Sibling data (prev / next from sort order) ──────────────
    var siblingData = null;

    /* Build query string with all params */
    function buildParams(sortOverride) {
        var qs = new URLSearchParams();
        if (sortOverride || currentSort) {
            qs.set('sort_by', sortOverride || currentSort);
        }
        qs.set('recurse', recurseOn ? '1' : '0');
        if (rootParentId !== null && rootParentId !== undefined) {
            qs.set('root', rootParentId === 'null' ? '' : String(rootParentId));
        }
        return '?' + qs.toString();
    }

    /* Load siblings from API — sets prev_id, next_id, position, total */
    function loadSiblings(fid, sortOverride) {
        if (!fid || !Number.isFinite(fid)) return;
        var url = '/api/siblings/' + fid + buildParams(sortOverride);

        fetch(url, { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                siblingData = data;
                // Resolve root if not yet known (from API response)
                if (rootParentId === null && data.root_parent_id !== undefined) {
                    rootParentId = (data.root_parent_id === null) ? 'null' : String(data.root_parent_id);
                    localStorage.setItem('vault_shuffle_root', rootParentId);
                }
                // Update position counter ("1 / 42") or status text for audio
                if (navPos && data.total > 0) {
                    navPos.textContent = data.position + ' / ' + data.total;
                } else if (navPos) {
                    navPos.textContent = '';
                }
                // Enable/disable prev/next based on actual navigation targets
                // When shuffle is ON: check session history; when OFF: use prev_id from siblings
                var hasPrev = siblingData.prev_id != null || (shuffleOn && canGoBack());
                if (prevBtn) prevBtn.disabled = !hasPrev;

                var hasNext = siblingData.next_id !== null && siblingData.next_id !== undefined;
                if (nextBtn) nextBtn.disabled = !hasNext;
            })
            .catch(function(err) { console.error('[file-nav] Siblings load error:', err); });
    }

    // ── Navigation helpers (session history tracking) ───────────
    function advanceHistory(stack, idx, fid) {
        if (idx < stack.history.length - 1) {
            // Truncate future entries after going back then forward again
            stack.history = stack.history.slice(0, idx + 1);
        }
        stack.history.push(fid);
        stack.idx = stack.history.length - 1;
    }

    function canGoBack() {
        // Only relevant for shuffle mode; sort-mode uses prev_id from sibling data
        if (!normalNav) return false;
        var idx = parseInt(normalNav.idx, 10);
        return !isNaN(idx) && idx > 0;
    }

    // ── goBack: shuffle uses history, sort-order uses prev_id ───
    function goBack() {
        if (prevBtn) prevBtn.disabled = true;

        if (shuffleOn && shuffleNav.idx > 0) {
            var target = shuffleNav.history[shuffleNav.idx - 1];
            shuffleNav.idx--;
            normalNav.idx--;
            saveHistory('shuffle', shuffleNav);
            saveHistory('normal', normalNav);
            /* Route to the correct page based on context */
            var isEditor = window.__EDITOR_CONFIG && parseInt(window.__EDITOR_CONFIG.fileId, 10) === fileId;
            if (isEditor) {
                window.location.href = '/editor/' + target;
            } else {
                window.location.href = '/player/' + target;
            }
        } else {
            // Sort-order: always use prev_id from sibling data (not session history)
            if (siblingData && siblingData.prev_id != null) {
                navigateTo(siblingData.prev_id);
            }
        }
    }

    function getPrevEntry(idx) {
        return normalNav.history[idx] || null;
    }

    // ── goNext: shuffle or sort-order ───────────────────────────
    function goNext() {
        if (nextBtn) nextBtn.disabled = true;
        var currentFid = parseInt(window.__PLAYER_CONFIG.fileId, 10);

        if (shuffleOn) {
            fetch('/api/random-sibling/' + currentFid + buildParams(), { credentials: 'same-origin' })
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (data.file_id) navigateTo(data.file_id);
                })
                .catch(function(err) { console.error('[file-nav] Shuffle error:', err); });
        } else {
            // Use sort-order sibling from API
            if (siblingData && siblingData.next_id != null) {
                navigateTo(siblingData.next_id);
            }
        }
    }

    // ── Navigate to file + track in history ─────────────────────
    function navigateTo(fidTarget) {
        var target = parseInt(fidTarget, 10);
        if (!target || isNaN(target)) return;
        currentFid = target;
        window.__PLAYER_CONFIG.fileId = target;

        advanceHistory(normalNav, normalNav.idx, target);
        advanceHistory(shuffleNav, shuffleNav.idx, target);
        saveHistory('shuffle', shuffleNav);
        saveHistory('normal', normalNav);

        /* Route to the correct page based on context */
        var isEditor = window.__EDITOR_CONFIG && parseInt(window.__EDITOR_CONFIG.fileId, 10) === fileId;
        if (isEditor) {
            window.location.href = '/editor/' + target;
        } else {
            window.location.href = '/player/' + target;
        }
    }

    var currentFid = fileId;  // track current file for navigation comparisons

    // ── Shuffle toggle button ───────────────────────────────────
    if (shuffleBtn) {
        shuffleBtn.addEventListener('click', function() {
            shuffleOn = !shuffleOn;
            updateButtonStates();
            localStorage.setItem('vault_shuffle', shuffleOn ? '1' : '0');
        });
    }

    // ── Recursive toggle button (update label + reload siblings) ─
    if (recurseBtn) {
        recurseBtn.addEventListener('click', function() {
            recurseOn = !recurseOn;
            updateButtonStates();
            localStorage.setItem('vault_recurse', recurseOn ? '1' : '0');
            // Re-fetch siblings with new recursion setting to get correct prev/next targets
            loadSiblings(fileId);
        });
    }

    // ── Wire up prev / next buttons ─────────────────────────────
    if (prevBtn) {
        prevBtn.addEventListener('click', goBack);
    }
    if (nextBtn) {
        nextBtn.addEventListener('click', function() {
            goNext();
        });
    }

    // ── Keyboard shortcuts: left / right arrows for navigation ──
    document.addEventListener('keydown', function(e) {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;
        var isVideo = window.__PLAYER_CONFIG && window.__PLAYER_CONFIG.mime && window.__PLAYER_CONFIG.mime.startsWith("video");

        // Allow arrow keys for all non-video contexts (audio, images, PDFs, text)
        if (!isVideo) {
            if (e.key === 'ArrowRight') { e.preventDefault(); goNext(); }
            if (e.key === 'ArrowLeft')  { e.preventDefault(); goBack(); }
        } else {
            // For video: only allow arrows when not in input fields (video player handles its own)
            var isVideoInput = window.__PLAYER_CONFIG && window.__PLAYER_CONFIG.mime && !window.__PLAYER_CONFIG.mime.startsWith("audio");
            if (!isVideoInput) {
                if (e.key === 'ArrowRight') { e.preventDefault(); goNext(); }
                if (e.key === 'ArrowLeft')  { e.preventDefault(); goBack(); }
            }
        }
    });

    // ── Initial siblings fetch ──────────────────────────────────
    loadSiblings(fileId);

    // ── Public API: expose navigation functions for other scripts ─
    window.FileNav = {
        goNext:   goNext,
        goBack:   goBack,
        navigateTo: function(id) { navigateTo(parseInt(id, 10)); },
        getSettings: function() { return { shuffleOn: shuffleOn, recurseOn: recurseOn, sort: currentSort }; }
    };

})();
