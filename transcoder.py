"""
On-demand HLS transcoder for the Encrypted Vault (Jellyfin-style).

Architecture
────────────
  • Original encrypted file is the ONLY permanent storage.
  • When a video is played, a temporary *session* is created:
      decrypt source → ffprobe → spawn FFmpeg → serve segments from temp.
  • Segments are plain .ts files in a temp dir (RAM-disk recommended).
  • No segments are ever encrypted or stored in the DB.
  • Sessions auto-expire after inactivity and all temp files are wiped.
  • Downloads bypass HLS entirely — the original is streamed/decrypted.
"""

import json
import logging
import math
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid

import config

logger = logging.getLogger('vault.transcoder')

# ── tunables ─────────────────────────────────────────────────────────
SEGMENT_DURATION = 10          # seconds per HLS segment
SESSION_TIMEOUT  = 600         # expire after 10 min of inactivity
_CLEANUP_INTERVAL = 60         # seconds between sweep runs

# Stream codecs that can be remuxed (no re-encode) into HLS
_VIDEO_COPY_CODECS = {'h264', 'hevc', 'h265'}
_AUDIO_COPY_CODECS = {'aac'}
_BITMAP_SUB_CODECS = {'hdmv_pgs_subtitle', 'dvd_subtitle',
                      'dvb_subtitle', 'xsub'}


# ── helpers ──────────────────────────────────────────────────────────
def _ffprobe(path: str) -> dict:
    cmd = [
        config.FFPROBE_PATH, '-v', 'quiet',
        '-print_format', 'json',
        '-show_format', '-show_streams', path,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise RuntimeError(f'ffprobe failed: {r.stderr[:500]}')
    return json.loads(r.stdout)


def _tmpfs_free(path: str) -> int | None:
    """Return free bytes on the filesystem containing *path*, or None."""
    try:
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize
    except Exception:
        return None


def _fmt_gb(b: int) -> str:
    return f'{b / (1024**3):.1f} GB'


# ── HLS session ──────────────────────────────────────────────────────
class HLSSession:
    """On-demand HLS streaming session for a single file.

    Life-cycle
    ──────────
    1.  Created by :func:`get_session` on first player request.
    2.  Background thread decrypts → probes → spawns FFmpeg processes.
    3.  Each segment request returns the .ts straight from the temp dir
        (blocking briefly if FFmpeg hasn't written it yet).
    4.  After *SESSION_TIMEOUT* of inactivity the session is reaped:
        FFmpeg killed, temp dir wiped.
    """

    def __init__(self, file_id: int):
        self.file_id = file_id
        _base = config.TEMP_DIR or None
        if _base:
            os.makedirs(_base, exist_ok=True)
        self.temp_dir = tempfile.mkdtemp(prefix='evlt_', dir=_base)
        self.source_path = os.path.join(self.temp_dir, 'source')

        self.duration: float = 0.0
        self.segment_count: int = 0
        self.video_streams: list[dict] = []
        self.audio_streams: list[dict] = []
        self.subtitle_streams: list[dict] = []   # text-based only

        # Progress tracking for the loading overlay
        self.init_stage: str = 'starting'
        self.decrypt_progress: float = 0.0
        self.file_size: int = 0
        self.bytes_decrypted: int = 0

        self.last_access = time.time()
        self._ready = threading.Event()
        self._error: str | None = None
        self._procs: list[subprocess.Popen] = []
        self._ffmpeg_pending = 0          # count of running FFmpeg procs
        self._ffmpeg_lock = threading.Lock()
        self._source_deleted = False       # set after source cleanup
        self._cleaned_up = False           # set by cleanup() — blocks post-mortem work
        self._audio_spawned: set[int] = set()  # tracks that have FFmpeg running/done
        self._audio_spawn_lock = threading.Lock()
        self._default_audio: int = 0              # track spawned during init
        self._subs_extracted = False               # set after pre-extraction done
        self._sub_cache: dict[int, bytes | None] = {}
        self._sub_lock = threading.Lock()
        self._sub_events: dict[int, threading.Event] = {}

        # Audio cache config (set by start())
        self._cache_mode: str = 'keep'
        self._cached_tracks: dict[int, str] = {}  # tidx → vault_filename
        self._cached_audio_paths: dict[int, str] = {}  # tidx → temp .m4a path
        self._encryptor = None
        self._vault_filename: str = ''
        self._overwrite_callback = None

    # ── bookkeeping ──────────────────────────────────────────────────
    def touch(self):
        self.last_access = time.time()

    def is_ready(self) -> bool:
        return self._ready.is_set() and self._error is None

    def get_error(self) -> str | None:
        return self._error

    def wait_ready(self, timeout: float = 120) -> bool:
        """Block until init completes.  Raises on error."""
        self._ready.wait(timeout)
        if self._error:
            raise RuntimeError(self._error)
        return True

    # ── initialisation (background thread) ───────────────────────────
    def start(self, encryptor, vault_filename: str,
              preferred_audio_lang: str = '',
              cache_mode: str = 'keep',
              cached_tracks: dict[int, str] | None = None,
              overwrite_callback=None):
        self._encryptor = encryptor
        self._vault_filename = vault_filename
        self._cache_mode = cache_mode
        self._cached_tracks = cached_tracks or {}
        self._overwrite_callback = overwrite_callback
        threading.Thread(target=self._init,
                         args=(encryptor, vault_filename, preferred_audio_lang),
                         daemon=True).start()

    def _pick_default_audio(self, preferred_lang: str) -> int:
        """Return the index of the best audio track for the given language."""
        if not preferred_lang:
            return 0
        lang = preferred_lang.lower()
        for i, s in enumerate(self.audio_streams):
            tags = s.get('tags', {})
            track_lang = (tags.get('language') or tags.get('LANGUAGE') or '').lower()
            if track_lang and (track_lang.startswith(lang) or lang.startswith(track_lang)):
                return i
        return 0  # fallback

    def _init(self, encryptor, vault_filename: str,
              preferred_audio_lang: str = ''):
        try:
            vault_path = os.path.join(config.VAULT_DIR, vault_filename)

            # 1. Decrypt with progress
            self.init_stage = 'decrypting'
            logger.info('[HLS %d] Decrypting source…', self.file_id)
            with open(vault_path, 'rb') as f:
                _, original_size = encryptor.read_header(f)
            self.file_size = original_size
            self.bytes_decrypted = 0

            # Pre-check: is there plausibly enough space?
            _base = config.TEMP_DIR or self.temp_dir
            free = _tmpfs_free(_base)
            if free is not None:
                needed = original_size * 2  # source + segments
                logger.info('[HLS %d] tmpfs free: %s, file: %s, need ~%s',
                            self.file_id, _fmt_gb(free),
                            _fmt_gb(original_size), _fmt_gb(needed))
                if free < original_size:
                    raise RuntimeError(
                        f'Not enough space in tmpfs: {_fmt_gb(free)} free '
                        f'but file is {_fmt_gb(original_size)}. '
                        f'Increase TMPFS_SIZE (need ~{_fmt_gb(needed)}).')

            with open(self.source_path, 'wb') as out:
                for chunk in encryptor.decrypt_full(vault_path):
                    try:
                        out.write(chunk)
                    except OSError as e:
                        free = _tmpfs_free(_base)
                        raise RuntimeError(
                            f'Write failed during decrypt '
                            f'({_fmt_gb(self.bytes_decrypted)} written, '
                            f'{_fmt_gb(free) if free is not None else "?"} '
                            f'free): {e}') from e
                    self.bytes_decrypted += len(chunk)
                    if self.file_size > 0:
                        self.decrypt_progress = self.bytes_decrypted / self.file_size

            # 2. Probe
            self.init_stage = 'probing'
            logger.info('[HLS %d] Probing…', self.file_id)
            info = _ffprobe(self.source_path)
            streams = info.get('streams', [])
            self.duration = float(
                info.get('format', {}).get('duration', 0))
            self.segment_count = max(
                1, math.ceil(self.duration / SEGMENT_DURATION))

            self.video_streams = [
                s for s in streams if s.get('codec_type') == 'video']
            self.audio_streams = [
                s for s in streams if s.get('codec_type') == 'audio']
            self.subtitle_streams = [
                s for s in streams
                if s.get('codec_type') == 'subtitle'
                and s.get('codec_name', '') not in _BITMAP_SUB_CODECS
            ]

            if not self.video_streams:
                raise RuntimeError('No video stream found')

            logger.info(
                '[HLS %d] %dV %dA %dS – %.1fs',
                self.file_id,
                len(self.video_streams),
                len(self.audio_streams),
                len(self.subtitle_streams),
                self.duration,
            )

            # 2b. Load cached audio tracks (always use if available)
            if self._cached_tracks:
                for tidx, vault_fname in self._cached_tracks.items():
                    if tidx >= len(self.audio_streams):
                        continue
                    cache_path = os.path.join(
                        self.temp_dir, f'cached_a{tidx}.m4a')
                    vp = os.path.join(config.VAULT_DIR, vault_fname)
                    try:
                        encryptor.decrypt_to_file(vp, cache_path)
                        self._cached_audio_paths[tidx] = cache_path
                        logger.info(
                            '[HLS %d] Loaded cached audio %d (%.1f MB)',
                            self.file_id, tidx,
                            os.path.getsize(cache_path) / (1024*1024))
                    except Exception as e:
                        logger.warning(
                            '[HLS %d] Cache load failed for audio %d: %s',
                            self.file_id, tidx, e)

            # 3. Spawn HLS — video + preferred audio track only.
            #    Remaining audio tracks are spawned AFTER subs are extracted
            #    (handled in _on_ffmpeg_done so source is still available).
            self.init_stage = 'transcoding'
            self._spawn_hls('video', 0)
            if self.audio_streams:
                self._default_audio = self._pick_default_audio(preferred_audio_lang)
                self._spawn_audio(self._default_audio)
                logger.info('[HLS %d] Default audio track: %d (lang pref: %r)',
                            self.file_id, self._default_audio, preferred_audio_lang)

            self.init_stage = 'ready'
            self._ready.set()
            logger.info('[HLS %d] Session ready', self.file_id)

        except Exception as exc:
            logger.error('[HLS %d] Init error: %s',
                         self.file_id, exc, exc_info=True)
            self._error = str(exc)
            self._ready.set()          # unblock waiters

    # ── FFmpeg helpers ───────────────────────────────────────────────
    def _hls_dir(self, stype: str, tidx: int) -> str:
        d = os.path.join(self.temp_dir, f'{stype}_{tidx}')
        os.makedirs(d, exist_ok=True)
        return d

    def _spawn_audio(self, tidx: int):
        """Spawn FFmpeg for an audio track if not already started."""
        with self._audio_spawn_lock:
            if tidx in self._audio_spawned:
                return
            self._audio_spawned.add(tidx)
        if tidx in self._cached_audio_paths:
            self._spawn_cached_audio(tidx)
        else:
            self._spawn_hls('audio', tidx)

    def _ensure_audio(self, tidx: int):
        """Ensure an audio track's FFmpeg has been started (on-demand)."""
        if tidx in self._audio_spawned:
            return  # fast path, no lock
        if self._cleaned_up or self._source_deleted:
            return  # too late
        self._spawn_audio(tidx)

    def _spawn_remaining_audio(self, skip: int = 0):
        """Background thread: spawn all audio tracks except *skip* sequentially."""
        for i in range(len(self.audio_streams)):
            if i == skip:
                continue
            if self._cleaned_up:
                return
            self._spawn_audio(i)

    def _spawn_cached_audio(self, tidx: int):
        """Spawn FFmpeg for a cached (already-AAC) audio track — copy only."""
        d = self._hls_dir('audio', tidx)
        cache_path = self._cached_audio_paths[tidx]

        stderr_path = os.path.join(d, 'ffmpeg.log')
        stderr_file = open(stderr_path, 'w')

        cmd = [
            config.FFMPEG_PATH, '-y', '-hide_banner', '-loglevel', 'warning',
            '-i', cache_path,
            '-c:a', 'copy',
            '-f', 'hls',
            '-hls_time', str(SEGMENT_DURATION),
            '-hls_playlist_type', 'vod',
            '-hls_segment_filename', os.path.join(d, '%05d.ts'),
            os.path.join(d, 'playlist.m3u8'),
        ]
        logger.info('[HLS %d] Spawning cached audio_%d (copy): %s',
                    self.file_id, tidx, ' '.join(cmd))
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=stderr_file)
        self._procs.append(proc)
        with self._ffmpeg_lock:
            self._ffmpeg_pending += 1
        threading.Thread(
            target=self._watch_ffmpeg,
            args=(proc, f'audio_{tidx}', stderr_path, stderr_file, d),
            daemon=True).start()

    def _spawn_hls(self, stype: str, tidx: int):
        d = self._hls_dir(stype, tidx)
        if stype == 'video':
            vc = self.video_streams[0].get('codec_name', '')
            codec_args = (
                ['-c:v', 'copy'] if vc in _VIDEO_COPY_CODECS
                else ['-c:v', 'libx264', '-preset', 'fast', '-crf', '22']
            )
            stream_args = ['-map', '0:v:0', '-an', '-sn']
        else:
            ac = self.audio_streams[tidx].get('codec_name', '')
            codec_args = (
                ['-c:a', 'copy'] if ac in _AUDIO_COPY_CODECS
                else ['-c:a', 'aac', '-b:a', '192k']
            )
            stream_args = [f'-map', f'0:a:{tidx}', '-vn', '-sn']

        # Write stderr to a file — prevents pipe deadlock AND lets us
        # see the actual error when FFmpeg fails in Docker.
        stderr_path = os.path.join(d, 'ffmpeg.log')
        stderr_file = open(stderr_path, 'w')

        cmd = [
            config.FFMPEG_PATH, '-y', '-hide_banner', '-loglevel', 'warning',
            # Explicit probing limits — prevents FFmpeg from hanging on
            # MKV files with font attachment streams (the Docker bug).
            '-analyzeduration', '10000000',   # 10 seconds
            '-probesize', '50000000',         # 50 MB
            '-i', self.source_path,
            *stream_args, *codec_args,
            '-f', 'hls',
            '-hls_time', str(SEGMENT_DURATION),
            '-hls_playlist_type', 'vod',
            '-hls_segment_filename', os.path.join(d, '%05d.ts'),
            os.path.join(d, 'playlist.m3u8'),
        ]
        logger.info('[HLS %d] Spawning FFmpeg %s_%d: %s',
                    self.file_id, stype, tidx, ' '.join(cmd))
        # Verify source exists before spawning
        if os.path.exists(self.source_path):
            sz = os.path.getsize(self.source_path)
            logger.info('[HLS %d] Source file: %s (%d bytes)',
                        self.file_id, self.source_path, sz)
        else:
            logger.error('[HLS %d] SOURCE FILE MISSING: %s',
                         self.file_id, self.source_path)
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=stderr_file)
        self._procs.append(proc)
        with self._ffmpeg_lock:
            self._ffmpeg_pending += 1
        logger.info('[HLS %d] FFmpeg %s_%d started, pid=%d',
                    self.file_id, stype, tidx, proc.pid)
        threading.Thread(
            target=self._watch_ffmpeg,
            args=(proc, f'{stype}_{tidx}', stderr_path, stderr_file, d),
            daemon=True).start()

    def _watch_ffmpeg(self, proc, label, stderr_path, stderr_file, outdir):
        """Monitor FFmpeg: log progress every 30s, log errors on exit."""
        # Harmless mpegts warnings that clutter the log
        _NOISE = {'frame size not set'}
        interval = 30
        while True:
            try:
                rc = proc.wait(timeout=interval)
                # Process exited
                stderr_file.close()
                try:
                    err_text = open(stderr_path).read()
                except Exception:
                    err_text = ''
                files = os.listdir(outdir) if os.path.isdir(outdir) else []
                ts_count = sum(1 for f in files if f.endswith('.ts'))
                # Print FFmpeg log to terminal
                if err_text:
                    print(f"\n===== FFmpeg log for {label} =====\n{err_text}\n==============================\n")
                # Killed by cleanup (-9 / SIGKILL) is expected — don't ERROR
                if rc == -9 or self._cleaned_up:
                    logger.info('[HLS %d] FFmpeg %s stopped (%d segments)',
                                self.file_id, label, ts_count)
                elif rc != 0:
                    # Filter noise from stderr before logging
                    filtered = '\n'.join(
                        l for l in err_text.splitlines()
                        if not any(n in l for n in _NOISE)
                    ).strip()
                    logger.error(
                        '[HLS %d] FFmpeg %s exited code %d (%d segments)%s',
                        self.file_id, label, rc, ts_count,
                        f'. stderr: {filtered[-400:]}' if filtered else '')
                else:
                    logger.info('[HLS %d] FFmpeg %s finished OK (%d segments)',
                                self.file_id, label, ts_count)
                    # Save audio cache if applicable (save mode, non-AAC, not already cached)
                    if (label.startswith('audio_')
                            and self._cache_mode == 'save'
                            and not self._cleaned_up):
                        tidx = int(label.split('_')[1])
                        if tidx not in self._cached_audio_paths:
                            self._save_audio_cache(tidx, outdir)
                if not self._cleaned_up:
                    self._on_ffmpeg_done()
                return
            except subprocess.TimeoutExpired:
                if self._cleaned_up:
                    return
                files = os.listdir(outdir) if os.path.isdir(outdir) else []
                ts_count = sum(1 for f in files if f.endswith('.ts'))
                has_pl = 'playlist.m3u8' in files
                logger.info(
                    '[HLS %d] FFmpeg %s pid=%d still running: '
                    '%d segments, playlist=%s',
                    self.file_id, label, proc.pid, ts_count, has_pl)

    # ── source file cleanup (free RAM) ────────────────────────────────
    def _on_ffmpeg_done(self):
        """Called when an FFmpeg process exits.

        Phase 1 (video + default audio done): extract all subs, then
        spawn remaining audio tracks in the background.
        Phase 2 (remaining audio done): delete the source file.
        """
        with self._ffmpeg_lock:
            self._ffmpeg_pending -= 1
            remaining = self._ffmpeg_pending
        if remaining > 0:
            return
        if self._cleaned_up:
            return

        if not self._subs_extracted:
            # Phase 1: subs first, then kick off remaining audio
            self._subs_extracted = True
            logger.info('[HLS %d] Initial FFmpeg done, extracting subs',
                        self.file_id)
            for i in range(len(self.subtitle_streams)):
                if i not in self._sub_cache:
                    try:
                        data = self._extract_sub_sync(i)
                        with self._sub_lock:
                            self._sub_cache[i] = data
                            evt = self._sub_events.pop(i, None)
                        if evt is not None:
                            evt.set()
                    except Exception as e:
                        logger.warning('[HLS %d] Sub %d extract failed: %s',
                                       self.file_id, i, e)
                        with self._sub_lock:
                            self._sub_cache[i] = None

            # Now spawn remaining audio tracks
            extra = [i for i in range(len(self.audio_streams))
                     if i != self._default_audio
                     and i not in self._audio_spawned]
            if extra:
                logger.info('[HLS %d] Spawning remaining audio tracks: %s',
                            self.file_id, extra)
                threading.Thread(
                    target=self._spawn_remaining_audio,
                    args=(self._default_audio,),
                    daemon=True).start()
            else:
                # No extra audio — go straight to overwrite / source cleanup
                if self._cache_mode == 'overwrite' and not self._source_deleted:
                    self._do_overwrite()
                self._delete_source()
        else:
            # Phase 2: remaining audio finished
            if self._cache_mode == 'overwrite' and not self._source_deleted:
                self._do_overwrite()
            self._delete_source()

    def _delete_source(self):
        """Remove the decrypted source file to free tmpfs."""
        try:
            if os.path.exists(self.source_path):
                sz = os.path.getsize(self.source_path)
                os.remove(self.source_path)
                self._source_deleted = True
                logger.info('[HLS %d] Source deleted, freed %.1f GB',
                            self.file_id, sz / (1024**3))
        except Exception as e:
            logger.warning('[HLS %d] Source cleanup failed: %s',
                           self.file_id, e)

    # ── audio cache (save mode) ──────────────────────────────────────
    def _save_audio_cache(self, tidx: int, outdir: str):
        """Save a transcoded audio track to the encrypted vault cache."""
        ac = self.audio_streams[tidx].get('codec_name', '')
        if ac in _AUDIO_COPY_CODECS:
            return  # already AAC — nothing to cache

        playlist = os.path.join(outdir, 'playlist.m3u8')
        if not os.path.exists(playlist):
            logger.warning('[HLS %d] Cannot cache audio %d: no playlist',
                           self.file_id, tidx)
            return

        # Concatenate HLS segments → single M4A
        m4a_path = os.path.join(self.temp_dir, f'cache_a{tidx}.m4a')
        cmd = [
            config.FFMPEG_PATH, '-y', '-hide_banner', '-loglevel', 'error',
            '-allowed_extensions', 'ALL',
            '-i', playlist,
            '-c:a', 'copy',
            m4a_path,
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if r.returncode or not os.path.exists(m4a_path):
                logger.warning(
                    '[HLS %d] Cache concat failed for audio %d: %s',
                    self.file_id, tidx, r.stderr[:300])
                return

            # Encrypt and save to vault
            vault_fname = f'{uuid.uuid4()}.enc'
            vault_path = os.path.join(config.VAULT_DIR, vault_fname)
            file_size = os.path.getsize(m4a_path)
            with open(m4a_path, 'rb') as inp:
                self._encryptor.encrypt_stream(inp, vault_path, file_size)

            # Record in DB
            from models import add_audio_cache
            add_audio_cache(self.file_id, tidx, ac, vault_fname)

            logger.info(
                '[HLS %d] Cached audio track %d (%s→AAC, %.1f MB)',
                self.file_id, tidx, ac, file_size / (1024 * 1024))
        except Exception as e:
            logger.error('[HLS %d] Failed to cache audio %d: %s',
                         self.file_id, tidx, e)
        finally:
            try:
                os.remove(m4a_path)
            except Exception:
                pass

    # ── overwrite mode (re-encode for browser compat) ────────────────
    def _do_overwrite(self):
        """Re-encode source → H.264 8-bit video + AAC stereo audio.

        Produces a file playable in virtually every browser.
        """
        if self._source_deleted or not os.path.exists(self.source_path):
            logger.warning('[HLS %d] Cannot overwrite: source gone',
                           self.file_id)
            return

        # Check if re-encode is needed
        vc = self.video_streams[0].get('codec_name', '') if self.video_streams else ''
        pix_fmt = self.video_streams[0].get('pix_fmt', '') if self.video_streams else ''
        non_aac = [i for i, s in enumerate(self.audio_streams)
                   if s.get('codec_name', '') not in _AUDIO_COPY_CODECS]
        needs_video = vc != 'h264' or pix_fmt != 'yuv420p'
        if not needs_video and not non_aac:
            logger.info('[HLS %d] Already H.264/yuv420p + all AAC, skipping overwrite',
                        self.file_id)
            return

        logger.info('[HLS %d] Overwrite: re-encoding (video=%s pix_fmt=%s, %d non-AAC audio)',
                    self.file_id, vc, pix_fmt, len(non_aac))

        # Write output to vault dir (disk) instead of tmpfs to save RAM
        output_path = os.path.join(
            config.VAULT_DIR, f'_ow_{uuid.uuid4()}.tmp')
        cmd = [
            config.FFMPEG_PATH, '-y', '-hide_banner', '-loglevel', 'warning',
            '-analyzeduration', '10000000', '-probesize', '50000000',
            '-i', self.source_path,
            '-map', '0',
            '-c:v', 'libx264', '-crf', '18', '-preset', 'slow',
            '-pix_fmt', 'yuv420p',
            '-c:a', 'aac', '-b:a', '192k', '-ac', '2',
            '-c:s', 'copy',
            '-c:d', 'copy',
            '-f', 'matroska', output_path,
        ]

        logger.info('[HLS %d] Overwrite cmd: %s',
                    self.file_id, ' '.join(cmd))
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=7200)
            if r.returncode:
                logger.error(
                    '[HLS %d] Overwrite re-encode failed (rc=%d): %s',
                    self.file_id, r.returncode, r.stderr[:500])
                return

            new_size = os.path.getsize(output_path)
            vault_path = os.path.join(
                config.VAULT_DIR, self._vault_filename)
            vault_tmp = vault_path + '.tmp'

            with open(output_path, 'rb') as inp:
                self._encryptor.encrypt_stream(inp, vault_tmp, new_size)
            os.replace(vault_tmp, vault_path)

            logger.info('[HLS %d] Overwrite done (%.1f MB)',
                        self.file_id, new_size / (1024 * 1024))

            if self._overwrite_callback:
                try:
                    self._overwrite_callback(new_size)
                except Exception as e:
                    logger.error('[HLS %d] Overwrite callback failed: %s',
                                 self.file_id, e)
        except Exception as e:
            logger.error('[HLS %d] Overwrite failed: %s', self.file_id, e)
            try:
                os.remove(vault_path + '.tmp')
            except Exception:
                pass
        finally:
            try:
                os.remove(output_path)
            except Exception:
                pass

    # ── lazy subtitle extraction ─────────────────────────────────────
    def _extract_sub_sync(self, tidx: int) -> bytes | None:
        """Extract a single subtitle track, returning VTT bytes or None."""
        vtt_path = os.path.join(self.temp_dir, f'sub_{tidx}.vtt')
        cmd = [
            config.FFMPEG_PATH, '-y', '-hide_banner',
            '-loglevel', 'error',
            '-analyzeduration', '10000000',
            '-probesize', '50000000',
            '-i', self.source_path,
            '-map', f'0:s:{tidx}',
            '-c:s', 'webvtt',
            vtt_path,
        ]
        logger.info('[HLS %d] Extracting subtitle %d on demand',
                    self.file_id, tidx)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if os.path.exists(vtt_path) and os.path.getsize(vtt_path) > 0:
            data = open(vtt_path, 'rb').read()
            os.remove(vtt_path)
            return data
        if r.returncode:
            logger.warning('[HLS %d] Subtitle %d failed: %s',
                           self.file_id, tidx, r.stderr[:200])
        return None

    # ── segment / track access ───────────────────────────────────────
    def get_segment(self, stype: str, tidx: int,
                    seg_idx: int, timeout: float = 30) -> bytes | None:
        """Return segment bytes, blocking until FFmpeg writes it."""
        self.touch()
        if stype == 'audio':
            self._ensure_audio(tidx)
        seg_path = os.path.join(
            self._hls_dir(stype, tidx), f'{seg_idx:05d}.ts')
        deadline = time.time() + timeout
        while not os.path.exists(seg_path):
            if time.time() > deadline:
                return None
            # If playlist is complete but file still absent → invalid index
            pl = os.path.join(self._hls_dir(stype, tidx), 'playlist.m3u8')
            if os.path.exists(pl):
                with open(pl) as f:
                    if '#EXT-X-ENDLIST' in f.read():
                        return None
            time.sleep(0.15)
        time.sleep(0.02)  # let final write flush
        return open(seg_path, 'rb').read()

    def get_segment_durations(self, stype: str, tidx: int) -> list[float]:
        """Return segment durations — actual from playlist if complete, else estimates.

        With -hls_playlist_type vod, FFmpeg writes playlist.m3u8 only
        when fully done (not incrementally).  Re-encoding many audio tracks
        can take minutes.  We return estimated durations immediately so the
        playlist endpoint never blocks, and let get_segment() wait per-segment.
        """
        self.touch()
        if stype == 'audio':
            self._ensure_audio(tidx)
        pl = os.path.join(self._hls_dir(stype, tidx), 'playlist.m3u8')
        # Quick check: if FFmpeg already finished we have the real playlist
        if os.path.exists(pl):
            with open(pl) as f:
                content = f.read()
            if '#EXT-X-ENDLIST' in content:
                durs = []
                for line in content.splitlines():
                    if line.strip().startswith('#EXTINF:'):
                        durs.append(
                            float(line.strip().split(':')[1].split(',')[0]))
                if durs:
                    return durs
        # FFmpeg still running or playlist not written yet — return estimates
        # immediately so the playlist endpoint is served without delay.
        # get_segment() will block per-segment as they're produced.
        full = int(self.duration // SEGMENT_DURATION)
        rem = self.duration - full * SEGMENT_DURATION
        durs = [float(SEGMENT_DURATION)] * full
        if rem > 0:
            durs.append(round(rem, 6))
        return durs or [self.duration]

    def get_subtitle(self, tidx: int) -> bytes | None:
        """Return VTT data, extracting lazily on first request.

        If another thread is already extracting this track, block until
        it finishes rather than returning None (which would cause a 404
        that hls.js won't retry).
        """
        self.touch()
        # Fast path: already cached
        if tidx in self._sub_cache:
            return self._sub_cache[tidx]
        with self._sub_lock:
            # Re-check under lock
            if tidx in self._sub_cache:
                return self._sub_cache[tidx]
            # Another thread is extracting — wait for it
            if tidx in self._sub_events:
                evt = self._sub_events[tidx]
            else:
                # We're the first — create event and do the work
                evt = threading.Event()
                self._sub_events[tidx] = evt
                evt = None  # signal that *we* should extract
        if evt is not None:
            # Wait for the extracting thread to finish (up to 2 min)
            evt.wait(timeout=120)
            return self._sub_cache.get(tidx)
        # We own extraction
        try:
            data = self._extract_sub_sync(tidx)
        except Exception:
            data = None
        with self._sub_lock:
            self._sub_cache[tidx] = data
            done_evt = self._sub_events.pop(tidx, None)
        if done_evt is not None:
            done_evt.set()  # wake all waiters
        return data

    def audio_info(self) -> list[dict]:
        result = []
        for i, s in enumerate(self.audio_streams):
            tags = s.get('tags', {})
            result.append({
                'track_index': i,
                'language': (tags.get('language', '')
                             or tags.get('LANGUAGE', '') or ''),
                'label': (tags.get('title', '')
                          or tags.get('TITLE', '') or ''),
                'codec': s.get('codec_name', ''),
                'is_default': i == 0,
                'is_cached': i in self._cached_audio_paths,
            })
        return result

    def subtitle_info(self) -> list[dict]:
        result = []
        for i, s in enumerate(self.subtitle_streams):
            tags = s.get('tags', {})
            result.append({
                'track_index': i,
                'language': (tags.get('language', '')
                             or tags.get('LANGUAGE', '') or ''),
                'label': (tags.get('title', '')
                          or tags.get('TITLE', '') or ''),
                'codec': s.get('codec_name', ''),
            })
        return result

    # ── tear-down ────────────────────────────────────────────────────
    def cleanup(self):
        self._cleaned_up = True
        for p in self._procs:
            try:
                p.kill()
                p.wait(timeout=5)
            except Exception:
                pass
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        logger.info('[HLS %d] Session cleaned up', self.file_id)


# ── session manager ─────────────────────────────────────────────────
_sessions: dict[int, HLSSession] = {}
_slock = threading.Lock()
_cleanup_started = False


def get_session(file_id: int,
                encryptor=None,
                vault_filename: str | None = None,
                preferred_audio_lang: str = '',
                cache_mode: str = 'keep',
                cached_tracks: dict[int, str] | None = None,
                overwrite_callback=None) -> HLSSession | None:
    """Return an existing session, or create one if *encryptor* is given.

    Creating a new session destroys ALL other sessions first so that only
    one video is loaded in tmpfs at a time.
    """
    global _cleanup_started
    with _slock:
        if not _cleanup_started:
            threading.Thread(target=_sweep, daemon=True).start()
            _cleanup_started = True

        sess = _sessions.get(file_id)
        if sess is not None:
            sess.touch()
            return sess
        if encryptor is None or vault_filename is None:
            return None

        # Destroy all other sessions to free tmpfs
        old: list[HLSSession] = []
        for fid in list(_sessions):
            old.append(_sessions.pop(fid))
        sess = HLSSession(file_id)
        _sessions[file_id] = sess

    # Clean up outside the lock
    for s in old:
        logger.info('[HLS] Destroying session %d to free space for %d',
                    s.file_id, file_id)
        s.cleanup()

    sess.start(encryptor, vault_filename, preferred_audio_lang,
               cache_mode, cached_tracks, overwrite_callback)
    return sess


def destroy_session(file_id: int):
    """Explicitly kill a session (e.g. when the file is deleted)."""
    with _slock:
        sess = _sessions.pop(file_id, None)
    if sess:
        sess.cleanup()


def _sweep():
    """Background reaper for idle sessions."""
    while True:
        time.sleep(_CLEANUP_INTERVAL)
        now = time.time()
        expired: list[HLSSession] = []
        with _slock:
            for fid in list(_sessions):
                if now - _sessions[fid].last_access > SESSION_TIMEOUT:
                    expired.append(_sessions.pop(fid))
        for sess in expired:
            sess.cleanup()


# ── global re-encode queue ───────────────────────────────────────────
# A single worker thread processes re-encode jobs one at a time.
# Deduplication: a file_id can only appear once in the queue + active.
import queue as _queue_mod

_reencode_q: _queue_mod.Queue = _queue_mod.Queue()
_reencode_jobs: dict[str, dict] = {}   # job_id → info
_reencode_file_ids: set[int] = set()   # file_ids currently queued or running
_rj_lock = threading.Lock()
_JOB_EXPIRY = 300  # auto-remove finished jobs after 5 min
_queue_worker_started = False


def submit_reencode(encryptor, vault_filename: str, file_id: int,
                    size_callback=None, file_name: str = '') -> dict:
    """Submit a file to the global re-encode queue.

    Returns {'accepted': True/False, 'reason': ..., 'job_id': ...}
    """
    global _queue_worker_started
    with _rj_lock:
        if file_id in _reencode_file_ids:
            return {'accepted': False,
                    'reason': f'{file_name or file_id} is already queued or processing'}
        job_id = str(uuid.uuid4())[:8]
        _reencode_file_ids.add(file_id)
        _reencode_jobs[job_id] = {
            'status': 'queued',
            'file_id': file_id,
            'file_name': file_name or f'file #{file_id}',
            'started': None,
            'finished': None,
            'error': None,
        }
    _reencode_q.put({
        'job_id': job_id,
        'encryptor': encryptor,
        'vault_filename': vault_filename,
        'file_id': file_id,
        'file_name': file_name or f'file #{file_id}',
        'size_callback': size_callback,
    })
    # Start the worker thread on first submit (lazy init)
    if not _queue_worker_started:
        _queue_worker_started = True
        t = threading.Thread(target=_reencode_worker, daemon=True)
        t.start()
    return {'accepted': True, 'job_id': job_id}


def _reencode_worker():
    """Single worker thread — processes one re-encode job at a time."""
    while True:
        item = _reencode_q.get()
        try:
            _process_reencode_job(item)
        except Exception as e:
            logger.error('[RE-Q] Unexpected worker error: %s', e, exc_info=True)
        finally:
            _reencode_q.task_done()


def _finish_job(job_id: str, status: str = 'done', error: str | None = None):
    with _rj_lock:
        j = _reencode_jobs.get(job_id)
        if j:
            j['status'] = status
            j['error'] = error
            j['finished'] = time.time()
            _reencode_file_ids.discard(j['file_id'])


def get_reencode_status() -> list[dict]:
    """Return all jobs, pruning expired ones."""
    now = time.time()
    result = []
    with _rj_lock:
        expired = [jid for jid, j in _reencode_jobs.items()
                   if j['finished'] and now - j['finished'] > _JOB_EXPIRY]
        for jid in expired:
            del _reencode_jobs[jid]
        for jid, j in _reencode_jobs.items():
            result.append({'job_id': jid, **j})
    return result


def pop_finished_jobs() -> list[dict]:
    """Return and remove all finished (done/error/skipped) jobs."""
    finished = []
    with _rj_lock:
        done_ids = [jid for jid, j in _reencode_jobs.items()
                    if j['status'] in ('done', 'error', 'skipped')]
        for jid in done_ids:
            finished.append({'job_id': jid, **_reencode_jobs.pop(jid)})
    return finished


def get_queue_size() -> int:
    """Return number of jobs waiting in the queue (not including active)."""
    return _reencode_q.qsize()


def clear_finished_jobs() -> int:
    """Remove all finished (done/error/skipped) jobs. Returns count cleared."""
    with _rj_lock:
        done_ids = [jid for jid, j in _reencode_jobs.items()
                    if j['status'] in ('done', 'error', 'skipped')]
        for jid in done_ids:
            del _reencode_jobs[jid]
    return len(done_ids)


# ── re-encode job processor (called by worker thread) ────────────────
def _process_reencode_job(item: dict):
    """Run one re-encode job from the queue."""
    job_id = item['job_id']
    file_id = item['file_id']
    encryptor = item['encryptor']
    vault_filename = item['vault_filename']
    size_callback = item['size_callback']

    with _rj_lock:
        j = _reencode_jobs.get(job_id)
        if j:
            j['status'] = 'running'
            j['started'] = time.time()

    _base = config.TEMP_DIR or None
    if _base:
        os.makedirs(_base, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix='evlt_ow_', dir=_base)
    source_path = os.path.join(tmp, 'source')
    try:
        vault_path = os.path.join(config.VAULT_DIR, vault_filename)

        # 1. Decrypt
        logger.info('[RE %d] Decrypting…', file_id)
        encryptor.decrypt_to_file(vault_path, source_path)
        logger.info('[RE %d] Decrypted (%.1f MB)',
                    file_id, os.path.getsize(source_path) / (1024**2))

        # 2. Probe — safeguard: skip if already correct format
        info = _ffprobe(source_path)
        streams = info.get('streams', [])
        video_streams = [s for s in streams if s.get('codec_type') == 'video']
        audio_streams = [s for s in streams if s.get('codec_type') == 'audio']

        vc = video_streams[0].get('codec_name', '') if video_streams else ''
        pix_fmt = video_streams[0].get('pix_fmt', '') if video_streams else ''
        non_aac = [i for i, s in enumerate(audio_streams)
                   if s.get('codec_name', '') not in _AUDIO_COPY_CODECS]
        needs_video = vc != 'h264' or pix_fmt != 'yuv420p'

        if not needs_video and not non_aac:
            logger.info('[RE %d] Already H.264/yuv420p + all AAC — skipping',
                        file_id)
            _finish_job(job_id, status='skipped')
            return

        # 3. Re-encode
        output_path = os.path.join(
            config.VAULT_DIR, f'_ow_{uuid.uuid4()}.tmp')
        cmd = [
            config.FFMPEG_PATH, '-y', '-hide_banner', '-loglevel', 'warning',
            '-analyzeduration', '10000000', '-probesize', '50000000',
            '-i', source_path,
            '-map', '0',
            '-c:v', 'libx264', '-crf', '18', '-preset', 'slow',
            '-pix_fmt', 'yuv420p',
            '-c:a', 'aac', '-b:a', '192k', '-ac', '2',
            '-c:s', 'copy',
            '-c:d', 'copy',
            '-f', 'matroska', output_path,
        ]

        logger.info('[RE %d] Re-encoding (video=%s pix_fmt=%s, %d non-AAC audio)…',
                    file_id, vc, pix_fmt, len(non_aac))
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
        if r.returncode:
            err_msg = r.stderr[:300]
            logger.error('[RE %d] Re-encode failed (rc=%d): %s',
                         file_id, r.returncode, err_msg)
            _finish_job(job_id, error=f'FFmpeg failed (rc={r.returncode})')
            return

        # 4. Encrypt and replace
        new_size = os.path.getsize(output_path)
        vault_tmp = vault_path + '.tmp'
        with open(output_path, 'rb') as inp:
            encryptor.encrypt_stream(inp, vault_tmp, new_size)
        os.replace(vault_tmp, vault_path)
        logger.info('[RE %d] Re-encode done (%.1f MB)', file_id,
                    new_size / (1024**2))

        if size_callback:
            try:
                size_callback(new_size)
            except Exception as e:
                logger.error('[RE %d] Size callback failed: %s', file_id, e)

        # 5. Clear any audio cache for this file (now obsolete)
        from models import clear_audio_cache
        old = clear_audio_cache(file_id)
        for vf in old:
            try:
                p = os.path.join(config.VAULT_DIR, vf)
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        if old:
            logger.info('[RE %d] Cleared %d obsolete cache entries',
                        file_id, len(old))

        _finish_job(job_id)

    except Exception as e:
        logger.error('[RE %d] Re-encode failed: %s', file_id, e,
                     exc_info=True)
        _finish_job(job_id, error=str(e))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        try:
            for f in os.listdir(config.VAULT_DIR):
                if f.startswith('_ow_') and f.endswith('.tmp'):
                    os.remove(os.path.join(config.VAULT_DIR, f))
        except Exception:
            pass


# ── legacy wrapper (used by HLS session _do_overwrite) ───────────────
def reencode_file(encryptor, vault_filename: str, file_id: int,
                  size_callback=None, file_name: str = ''):
    """Submit to the global queue. For backward compat."""
    result = submit_reencode(encryptor, vault_filename, file_id,
                             size_callback=size_callback,
                             file_name=file_name)
    if not result['accepted']:
        logger.info('[RE %d] Skipped (already queued): %s',
                    file_id, result['reason'])


# Backward-compat alias
overwrite_audio = reencode_file