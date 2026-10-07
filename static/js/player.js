"use strict";

    (function() {
        const FILE_ID   = window.__PLAYER_CONFIG.fileId;
        const masterUrl = '/api/hls/' + FILE_ID + '/master.m3u8';
        const statusUrl = '/api/hls/' + FILE_ID + '/status';
        const tracksUrl = '/api/hls/' + FILE_ID + '/tracks';
        const vpUrl     = '/api/video/' + FILE_ID + '/prefs';

        // ── Loading progress poller ─────────────────────────────────
        const loadingTitle   = document.getElementById('loadingTitle');
        const loadingDetail  = document.getElementById('loadingDetail');
        const loadingProgress = document.getElementById('loadingProgress');
        const loadingPct     = document.getElementById('loadingPct');

        function fmtBytes(b) {
            if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
            if (b >= 1048576) return (b / 1048576).toFixed(0) + ' MB';
            if (b >= 1024) return (b / 1024).toFixed(0) + ' KB';
            return b + ' B';
        }

        let _progressTimer = null;
        function pollProgress() {
            _progressTimer = setInterval(() => {
                fetch(statusUrl, {credentials: 'same-origin'})
                    .then(r => r.json())
                    .then(d => {
                        if (d.status === 'error') {
                            clearInterval(_progressTimer);
                            loadingTitle.textContent = 'Error';
                            loadingDetail.textContent = d.error_msg || 'Unknown error';
                            loadingProgress.style.width = '0%';
                            loadingPct.textContent = '';
                            return;
                        }
                        if (d.status === 'ready') {
                            clearInterval(_progressTimer);
                            loadingTitle.textContent = 'Starting playback…';
                            loadingDetail.textContent = 'Buffering first segments';
                            loadingProgress.style.width = '100%';
                            loadingPct.textContent = '';
                            return;
                        }
                        // Initializing — show stage-specific progress
                        const stage = d.stage || 'starting';
                        if (stage === 'decrypting') {
                            const pct = Math.round((d.decrypt_progress || 0) * 100);
                            loadingTitle.textContent = 'Decrypting…';
                            loadingDetail.textContent = fmtBytes(d.bytes_decrypted || 0) + ' / ' + fmtBytes(d.file_size || 0);
                            loadingProgress.style.width = pct + '%';
                            loadingPct.textContent = pct + '%';
                        } else if (stage === 'probing') {
                            loadingTitle.textContent = 'Analyzing…';
                            loadingDetail.textContent = 'Scanning video streams';
                            loadingProgress.classList.add('progress-bar-striped', 'progress-bar-animated');
                            loadingProgress.style.width = '100%';
                            loadingPct.textContent = '';
                        } else if (stage === 'transcoding') {
                            loadingTitle.textContent = 'Preparing stream…';
                            loadingDetail.textContent = 'Starting FFmpeg';
                            loadingProgress.classList.add('progress-bar-striped', 'progress-bar-animated');
                            loadingProgress.style.width = '100%';
                            loadingPct.textContent = '';
                        } else {
                            loadingTitle.textContent = 'Preparing…';
                            loadingDetail.textContent = 'Starting session';
                            loadingProgress.style.width = '0%';
                            loadingPct.textContent = '';
                        }
                    })
                    .catch(() => {});
            }, 500);
        }
        pollProgress();

        // ── Audio cache: check and wire clear button ────────────────
        (function() {
            const cacheGroup = document.getElementById('audioCacheGroup');
            const clearBtn   = document.getElementById('clearCacheBtn');
            const cacheUrl   = '/api/audio-cache/' + FILE_ID;
            fetch(cacheUrl, {credentials: 'same-origin'})
                .then(r => r.json())
                .then(data => {
                    if (data.has_cache) cacheGroup.classList.remove('d-none');
                })
                .catch(() => {});
            clearBtn.addEventListener('click', () => {
                clearBtn.disabled = true;
                clearBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Clearing…';
                fetch(cacheUrl + '/clear', {
                    method: 'POST',
                    credentials: 'same-origin',
                })
                .then(r => r.json())
                .then(data => {
                    clearBtn.innerHTML = '<i class="fas fa-check me-1"></i>Cleared';
                    setTimeout(() => cacheGroup.classList.add('d-none'), 1500);
                })
                .catch(() => {
                    clearBtn.innerHTML = '<i class="fas fa-times me-1"></i>Error';
                    clearBtn.disabled = false;
                });
            });
        })();

        // Per-video state loaded from DB via __PLAYER_CONFIG
        const cfg = window.__PLAYER_CONFIG || {};
        const VP = {
            position:   cfg.position ?? 0,
            sub_offset: cfg.sub_offset ?? 0,
        };

        // Account-level defaults (rendered server-side)
        const PREFS = {
            audioLang:  'en',
            subLang:    '',
            skipAmount: 15,
            subOffset:  0,
        };

        // Save per-video prefs to server
        let _saveTimer = null;
        function saveVideoPrefs(obj) {
            Object.assign(VP, obj);
            // Debounce rapid saves (100ms) but send full state
            clearTimeout(_saveTimer);
            _saveTimer = setTimeout(() => _flushVideoPrefs(), 100);
        }
        function _flushVideoPrefs() {
            clearTimeout(_saveTimer);
            fetch(vpUrl, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'same-origin',
                body: JSON.stringify(VP),
            }).then(r => {
                if (!r.ok) console.error('Failed to save video prefs:', r.status);
            }).catch(err => console.error('Video prefs save error:', err));
        }

        // Save user-level prefs to server (fire-and-forget)
        function saveUserPrefs(obj) {
            Object.assign(PREFS, obj);
            fetch('/api/preferences', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'same-origin',
                body: JSON.stringify(obj),
            }).catch(() => {});
        }

        const loadingDiv    = document.getElementById('hlsLoading');
        const errorDiv      = document.getElementById('hlsError');
        const errorMsg      = document.getElementById('hlsErrorMsg');
        const video         = document.getElementById('hlsVideo');
        const settingsBtn   = document.getElementById('settingsBtn');
        const settingsPanel = document.getElementById('settingsPanel');
        const settingsClose = document.getElementById('settingsClose');
        const audioGroup    = document.getElementById('audioTrackGroup');
        const audioSelect   = document.getElementById('audioTrackSelect');
        const subGroup      = document.getElementById('subtitleTrackGroup');
        const subSelect     = document.getElementById('subtitleTrackSelect');
        const subOffsetGroup  = document.getElementById('subOffsetGroup');
        const subOffsetValue  = document.getElementById('subOffsetValue');

        let hls = null;
        let subtitleOffset = (VP.sub_offset !== 0) ? VP.sub_offset : PREFS.subOffset;
        subOffsetValue.textContent = (subtitleOffset >= 0 ? '+' : '') + subtitleOffset.toFixed(1) + 's';

        // ── Custom controls references ──────────────────────────────
        const playPauseBtn  = document.getElementById('playPauseBtn');
        const playIcon      = document.getElementById('playIcon');
        const progressBar   = document.getElementById('progressBar');
        const progressFill  = document.getElementById('progressFill');
        const bufferBar     = document.getElementById('bufferBar');
        const timeDisplay   = document.getElementById('timeDisplay');
        const muteBtn       = document.getElementById('muteBtn');
        const volIcon       = document.getElementById('volIcon');
        const volSlider     = document.getElementById('volSlider');
        const fullscreenBtn = document.getElementById('fullscreenBtn');
        const fsIcon        = document.getElementById('fsIcon');
        const hlsContainer  = document.getElementById('hlsContainer');

        function fmtTime(s) {
            if (!isFinite(s) || s < 0) s = 0;
            const h = Math.floor(s / 3600);
            const m = Math.floor((s % 3600) / 60);
            const sec = Math.floor(s % 60);
            return h > 0
                ? h + ':' + String(m).padStart(2,'0') + ':' + String(sec).padStart(2,'0')
                : m + ':' + String(sec).padStart(2,'0');
        }

        // Play / Pause
        playPauseBtn.addEventListener('click', () => {
            if (video.paused) video.play(); else video.pause();
        });
        video.addEventListener('click', () => {
            if (video.paused) video.play(); else video.pause();
        });
        video.addEventListener('play',  () => { playIcon.className = 'fas fa-pause'; });
        video.addEventListener('pause', () => { playIcon.className = 'fas fa-play'; });

        // Progress bar
        video.addEventListener('timeupdate', () => {
            if (!video.duration) return;
            const pct = (video.currentTime / video.duration) * 100;
            progressFill.style.width = pct + '%';
            timeDisplay.textContent = fmtTime(video.currentTime) + ' / ' + fmtTime(video.duration);
        });
        video.addEventListener('progress', () => {
            if (video.buffered.length && video.duration) {
                const end = video.buffered.end(video.buffered.length - 1);
                bufferBar.style.width = (end / video.duration * 100) + '%';
            }
        });
        let seeking = false;
        function seekFromEvent(e) {
            const rect = progressBar.getBoundingClientRect();
            const pct = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
            video.currentTime = pct * (video.duration || 0);
        }
        progressBar.addEventListener('mousedown', (e) => { seeking = true; seekFromEvent(e); });
        document.addEventListener('mousemove', (e) => { if (seeking) seekFromEvent(e); });
        document.addEventListener('mouseup', () => { seeking = false; });

        // Volume
        volSlider.addEventListener('input', () => {
            video.volume = parseFloat(volSlider.value);
            video.muted = false;
            updateVolIcon();
        });
        muteBtn.addEventListener('click', () => {
            video.muted = !video.muted;
            updateVolIcon();
        });
        function updateVolIcon() {
            if (video.muted || video.volume === 0) volIcon.className = 'fas fa-volume-mute';
            else if (video.volume < 0.5) volIcon.className = 'fas fa-volume-down';
            else volIcon.className = 'fas fa-volume-up';
        }

        // Fullscreen
        fullscreenBtn.addEventListener('click', () => {
            if (!document.fullscreenElement) hlsContainer.requestFullscreen();
            else document.exitFullscreen();
        });
        document.addEventListener('fullscreenchange', () => {
            fsIcon.className = document.fullscreenElement ? 'fas fa-compress' : 'fas fa-expand';
        });

        // ── Skip forward / back ─────────────────────────────────────
        let skipAmount = PREFS.skipAmount;
        const skipBackLabel = document.getElementById('skipBackLabel');
        const skipFwdLabel  = document.getElementById('skipFwdLabel');
        const skipAmtValue  = document.getElementById('skipAmtValue');
        function refreshSkipLabels() {
            const txt = skipAmount + 's';
            skipBackLabel.textContent = skipAmount;
            skipFwdLabel.textContent  = skipAmount;
            skipAmtValue.textContent  = txt;
        }
        refreshSkipLabels();
        document.getElementById('skipBackBtn').addEventListener('click', () => {
            video.currentTime = Math.max(0, video.currentTime - skipAmount);
        });
        document.getElementById('skipFwdBtn').addEventListener('click', () => {
            video.currentTime = Math.min(video.duration || Infinity, video.currentTime + skipAmount);
        });
        document.getElementById('skipAmtDown').addEventListener('click', () => {
            skipAmount = Math.max(5, skipAmount - 5);
            saveUserPrefs({ skip_amount: skipAmount });
            refreshSkipLabels();
        });
        document.getElementById('skipAmtUp').addEventListener('click', () => {
            skipAmount = Math.min(120, skipAmount + 5);
            saveUserPrefs({ skip_amount: skipAmount });
            refreshSkipLabels();
        });

        // ── Keyboard shortcuts ──────────────────────────────────────
        document.addEventListener('keydown', (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
            switch(e.key) {
                case ' ': case 'k':
                    e.preventDefault();
                    if (video.paused) video.play(); else video.pause();
                    break;
                case 'ArrowLeft':  e.preventDefault(); video.currentTime = Math.max(0, video.currentTime - skipAmount); break;
                case 'ArrowRight': e.preventDefault(); video.currentTime = Math.min(video.duration||Infinity, video.currentTime + skipAmount); break;
                case 'ArrowUp':    e.preventDefault(); video.volume = Math.min(1, video.volume + 0.1); volSlider.value = video.volume; updateVolIcon(); break;
                case 'ArrowDown':  e.preventDefault(); video.volume = Math.max(0, video.volume - 0.1); volSlider.value = video.volume; updateVolIcon(); break;
                case 'm': video.muted = !video.muted; updateVolIcon(); break;
                case 'f': fullscreenBtn.click(); break;
            }
        });

        // ── Resume position ─────────────────────────────────────────
        const savedPos = VP.position || 0;

        function savePosition() {
            if (video.currentTime > 2 && video.duration && video.currentTime < video.duration - 5) {
                VP.position = Math.floor(video.currentTime);
                saveVideoPrefs({ position: VP.position });
            }
        }
        // Save every 5 seconds
        setInterval(savePosition, 5000);
        // Save on page leave — use sendBeacon for reliability
        window.addEventListener('beforeunload', () => {
            if (video.currentTime > 2 && video.duration && video.currentTime < video.duration - 5) {
                VP.position = Math.floor(video.currentTime);
            }
            navigator.sendBeacon(vpUrl, new Blob([JSON.stringify(VP)], {type: 'application/json'}));
        });
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) { savePosition(); _flushVideoPrefs(); }
        });
        // Clear saved position when finished
        video.addEventListener('ended', () => saveVideoPrefs({ position: 0 }));

        // ── Hide loading once first frame renders ───────────────────
        video.addEventListener('loadeddata', () => {
            clearInterval(_progressTimer);
            loadingDiv.classList.add('d-none');
            // Restore saved position
            if (savedPos > 2 && video.duration && savedPos < video.duration - 5) {
                video.currentTime = savedPos;
            }
        });

        // ── Settings panel toggle ───────────────────────────────────
        settingsBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            settingsPanel.classList.toggle('d-none');
        });
        settingsClose.addEventListener('click', () => settingsPanel.classList.add('d-none'));
        document.addEventListener('click', (e) => {
            if (!settingsPanel.contains(e.target) && e.target !== settingsBtn && !settingsBtn.contains(e.target))
                settingsPanel.classList.add('d-none');
        });

        // ── Subtitle offset ─────────────────────────────────────────
        function updateSubOffset(delta) {
            subtitleOffset = Math.round((subtitleOffset + delta) * 10) / 10;
            subOffsetValue.textContent = (subtitleOffset >= 0 ? '+' : '') + subtitleOffset.toFixed(1) + 's';
            saveVideoPrefs({ sub_offset: subtitleOffset });
            applySubOffset();
        }
        document.getElementById('subOffsetDown').addEventListener('click', () => updateSubOffset(-0.5));
        document.getElementById('subOffsetUp').addEventListener('click', () => updateSubOffset(0.5));

        function applySubOffset() {
            if (!hls) return;
            const cur = hls.subtitleTrack;
            if (cur < 0) return;
            hls.subtitleTrack = -1;
            setTimeout(() => {
                hls.subtitleTrack = cur;
                hls.subtitleDisplay = true;
                setTimeout(() => shiftLoadedCues(), 500);
            }, 50);
        }
        function shiftLoadedCues() {
            for (let i = 0; i < video.textTracks.length; i++) {
                const track = video.textTracks[i];
                if ((track.kind === 'subtitles' || track.kind === 'captions') && track.cues) {
                    for (let j = 0; j < track.cues.length; j++) {
                        const cue = track.cues[j];
                        if (cue._origStart === undefined) {
                            cue._origStart = cue.startTime;
                            cue._origEnd = cue.endTime;
                        }
                        cue.startTime = cue._origStart + subtitleOffset;
                        cue.endTime   = cue._origEnd   + subtitleOffset;
                    }
                }
            }
        }

        // ── Show error ──────────────────────────────────────────────
        function showError(msg) {
            loadingDiv.classList.add('d-none');
            errorMsg.textContent = msg;
            errorDiv.classList.remove('d-none');
        }

        // ── Start playback immediately ──────────────────────────────
        if (!Hls.isSupported()) {
            // Safari native HLS
            video.src = masterUrl;
            video.addEventListener('loadedmetadata', () => {
                fetch(tracksUrl, {credentials:'same-origin'}).then(r => r.json()).then(setupNativeTracks);
            });
        } else {
            hls = new Hls({
                maxBufferLength: 30,
                maxMaxBufferLength: 60,
                renderTextTracksNatively: true,
                xhrSetup: function(xhr) { xhr.withCredentials = true; },
            });
            hls.loadSource(masterUrl);
            hls.attachMedia(video);

            hls.on(Hls.Events.MANIFEST_PARSED, function() {
                video.muted = true;
                video.play().then(() => { video.muted = false; }).catch(() => {});
                setupHlsTrackControls();
            });
            hls.on(Hls.Events.AUDIO_TRACKS_UPDATED, setupHlsTrackControls);
            hls.on(Hls.Events.SUBTITLE_TRACKS_UPDATED, setupHlsTrackControls);

            hls.on(Hls.Events.ERROR, function(event, data) {
                if (data.fatal) {
                    console.error('HLS fatal error:', data.type, data.details);
                    if (data.type === Hls.ErrorTypes.NETWORK_ERROR) {
                        hls.startLoad();
                    } else {
                        showError('Fatal playback error: ' + data.details);
                        hls.destroy();
                    }
                }
            });
        }

        // ── Track controls (hls.js) ────────────────────────────────
        let audioInitialized = false;
        let subInitialized   = false;

        function setupHlsTrackControls() {
            const audioTracks = hls.audioTracks;
            if (audioTracks.length >= 1) {
                audioGroup.classList.remove('d-none');
                audioSelect.innerHTML = '';
                let bestAudioIdx = 0;
                audioTracks.forEach((t, i) => {
                    const opt = document.createElement('option');
                    opt.value = i;
                    const lang = (t.lang || '').toLowerCase();
                    opt.textContent = t.name || lang || ('Track ' + (i+1));
                    opt.dataset.lang = lang;
                    if (i === hls.audioTrack) opt.selected = true;
                    audioSelect.appendChild(opt);
                });
                if (!audioInitialized) {
                    audioInitialized = true;
                    if (PREFS.audioLang) {
                        const m = audioTracks.findIndex(t => {
                            const l = (t.lang||'').toLowerCase();
                            return l.startsWith(PREFS.audioLang) || PREFS.audioLang.startsWith(l);
                        });
                        if (m >= 0) bestAudioIdx = m;
                    }
                    if (bestAudioIdx !== hls.audioTrack) hls.audioTrack = bestAudioIdx;
                    audioSelect.value = bestAudioIdx;
                }
                audioSelect.onchange = () => {
                    const idx = parseInt(audioSelect.value);
                    hls.audioTrack = idx;
                };
            }

            const subTracks = hls.subtitleTracks;
            if (subTracks.length > 0) {
                subGroup.classList.remove('d-none');
                subOffsetGroup.classList.remove('d-none');
                subSelect.innerHTML = '<option value="-1">Off</option>';
                let bestSubIdx = -1;
                subTracks.forEach((t, i) => {
                    const opt = document.createElement('option');
                    opt.value = i;
                    const lang = (t.lang || '').toLowerCase();
                    opt.textContent = t.name || lang || ('Subtitle ' + (i+1));
                    opt.dataset.lang = lang;
                    subSelect.appendChild(opt);
                });
                if (!subInitialized) {
                    subInitialized = true;
                    if (PREFS.subLang) {
                        const m = subTracks.findIndex(t => {
                            const l = (t.lang||'').toLowerCase();
                            return l.startsWith(PREFS.subLang) || PREFS.subLang.startsWith(l);
                        });
                        if (m >= 0) bestSubIdx = m;
                    }
                    if (bestSubIdx >= 0) { hls.subtitleTrack = bestSubIdx; hls.subtitleDisplay = true; }
                    subSelect.value = bestSubIdx;
                    if (subtitleOffset !== 0) setTimeout(() => applySubOffset(), 800);
                }
                subSelect.onchange = () => {
                    const val = parseInt(subSelect.value);
                    hls.subtitleTrack = val;
                    hls.subtitleDisplay = (val >= 0);
                    if (val >= 0 && subtitleOffset !== 0) setTimeout(() => applySubOffset(), 500);
                };
            }
        }

        // ── Track controls (Safari native) ──────────────────────────
        function setupNativeTracks(data) {
            if (data.audio && data.audio.length >= 1) {
                audioGroup.classList.remove('d-none');
                audioSelect.innerHTML = '';
                data.audio.forEach(t => {
                    const opt = document.createElement('option');
                    opt.value = t.track_index;
                    opt.textContent = t.label || t.language || ('Track ' + t.track_index);
                    if (t.is_default) opt.selected = true;
                    audioSelect.appendChild(opt);
                });
                if (PREFS.audioLang) {
                    const m = data.audio.find(t => (t.language||'').toLowerCase().startsWith(PREFS.audioLang));
                    if (m) audioSelect.value = m.track_index;
                }
                audioSelect.onchange = () => {};  // no per-video save
            }
            if (data.subtitles && data.subtitles.length > 0) {
                subGroup.classList.remove('d-none');
                subOffsetGroup.classList.remove('d-none');
                subSelect.innerHTML = '<option value="-1">Off</option>';
                data.subtitles.forEach(t => {
                    const opt = document.createElement('option');
                    opt.value = t.track_index;
                    opt.textContent = t.label || t.language || ('Subtitle ' + t.track_index);
                    subSelect.appendChild(opt);
                });
                if (PREFS.subLang) {
                    const m = data.subtitles.find(t => (t.language||'').toLowerCase().startsWith(PREFS.subLang));
                    if (m) subSelect.value = m.track_index;
                }
                subSelect.onchange = () => {};  // no per-video save
            }
        }
    })();

