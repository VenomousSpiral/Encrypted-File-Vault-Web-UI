"use strict";

(function() {
    var audio = document.getElementById('nativeAudio');
    var playBtn = document.getElementById('audioPlayBtn');
    var playIcon = document.getElementById('audioPlayIcon');
    var progressBar = document.getElementById('audioProgressBar');
    var progressFill = document.getElementById('audioProgressFill');
    var currentTimeEl = document.getElementById('audioCurrentTime');
    var durationEl = document.getElementById('audioDuration');
    var volumeSlider = document.getElementById('audioVolumeSlider');
    var muteBtn = document.getElementById('audioMuteBtn');
    var volIcon = document.getElementById('audioVolIcon');
    var visualArea = document.getElementById('audioVisualArea');
    var eqContainer = document.getElementById('eqContainer');

    // ── Equalizer bars (25 bars for full-width look) ────────────
    for (var i = 0; i < 25; i++) {
        var bar = document.createElement('div');
        bar.className = 'eq-bar';
        bar.style.height = '8px';
        eqContainer.appendChild(bar);
    }

    // ── Format time ─────────────────────────────────────────────
    function fmtTime(s) {
        if (!isFinite(s) || s < 0) s = 0;
        var h = Math.floor(s / 3600);
        var m = Math.floor((s % 3600) / 60);
        var sec = Math.floor(s % 60);
        return h > 0
            ? h + ':' + String(m).padStart(2, '0') + ':' + String(sec).padStart(2, '0')
            : m + ':' + String(sec).padStart(2, '0');
    }

    // ── Play / Pause ────────────────────────────────────────────
    function togglePlay() {
        if (audio.paused) audio.play(); else audio.pause();
    }
    playBtn.addEventListener('click', togglePlay);

    audio.addEventListener('play', function() {
        playIcon.className = 'fas fa-pause';
        visualArea.classList.remove('paused');
    });
    audio.addEventListener('pause', function() {
        playIcon.className = 'fas fa-play';
        visualArea.classList.add('paused');
    });

    // ── Progress & time updates ────────────────────────────────
    var _durLoaded = false;
    audio.addEventListener('loadedmetadata', function() {
        durationEl.textContent = fmtTime(audio.duration);
        _durLoaded = true;
    });
    audio.addEventListener('timeupdate', function() {
        if (!audio.duration) return;
        var pct = (audio.currentTime / audio.duration) * 100;
        progressFill.style.width = pct + '%';
        currentTimeEl.textContent = fmtTime(audio.currentTime);
    });
    audio.addEventListener('ended', function() {
        playIcon.className = 'fas fa-play';
        visualArea.classList.add('paused');
    });

    // ── Seek via progress bar click/drag (desktop) ─────────────
    var seeking = false;
    function seekFromEvent(clientX) {
        if (!_durLoaded || !audio.duration) return;
        var rect = progressBar.getBoundingClientRect();
        var pct = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
        audio.currentTime = pct * audio.duration;
    }

    // Touch support for mobile
    progressBar.addEventListener('touchstart', function(e) { seeking = true; seekFromEvent(e.touches[0].clientX); });
    document.addEventListener('touchmove', function(e) { if (seeking) seekFromEvent(e.touches[0].clientX); }, { passive: true });
    document.addEventListener('touchend', function() { seeking = false; });

    // Mouse support for desktop
    progressBar.addEventListener('mousedown', function(e) { seeking = true; seekFromEvent(e.clientX); });
    document.addEventListener('mousemove', function(e) { if (seeking) seekFromEvent(e.clientX); });
    document.addEventListener('mouseup', function() { seeking = false; });

    // ── Volume control ────────────────────────────────────────
    volumeSlider.addEventListener('input', function() {
        audio.volume = parseFloat(volumeSlider.value);
        audio.muted = false;
        updateVolIcon();
    });
    muteBtn.addEventListener('click', function() {
        audio.muted = !audio.muted;
        updateVolIcon();
    });
    function updateVolIcon() {
        if (audio.muted || audio.volume === 0) volIcon.className = 'fas fa-volume-mute';
        else if (audio.volume < 0.5) volIcon.className = 'fas fa-volume-down';
        else volIcon.className = 'fas fa-volume-up';
    }


})();
