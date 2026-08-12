document.addEventListener('DOMContentLoaded', function() {
    if (typeof window.renderLwsLoginStatus === 'function') {
        window.renderLwsLoginStatus('auth-status');
    }

    var canDelete = false;
    var cookies = document.cookie.split(';');
    for (var i = 0; i < cookies.length; i++) {
        var c = cookies[i].trim();
        if (c.indexOf('auth_session=') === 0) {
            var token = c.substring(13);
            var parts = token.split('.');
            if (parts.length === 3) {
                try {
                    var payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
                    if (payload && payload.grant) {
                        var grants = payload.grant.split(',');
                        if (grants.indexOf('*') !== -1 || grants.indexOf('hls:2') !== -1) {
                            canDelete = true;
                        }
                    }
                } catch (e) {
                    /* ignore */
                }
            }
        }
    }
    
    var delBtn = document.getElementById('delete-btn');
    if (canDelete && delBtn) {
        delBtn.classList.remove('hidden');
        delBtn.addEventListener('click', function(event) {
            event.preventDefault();
            if (!confirm("Are you sure you want to delete this file?")) return;
            var urlParams = new URLSearchParams(window.location.search);
            var videoSrc = urlParams.get('v');
            if (videoSrc) {
                var filename = videoSrc.replace('hls/stream/', '');
                fetch('hls/delete/' + filename, {
                    method: 'POST'
                }).then(function(res) {
                    if (res.ok) {
                        window.location.href = 'hls/';
                    } else {
                        alert('Failed to delete file');
                    }
                });
            }
        });
    }

    var video = document.getElementById('video');
    
    var urlParams = new URLSearchParams(window.location.search);
    var videoSrc = urlParams.get('v');
    var rawSrc = urlParams.get('raw');

    // Preferred subtitle languages (most-preferred first). Used to pick a
    // sensible default in the CC dropdown; subtitles stay OFF until the
    // user clicks CC.
    var prefLangs = (navigator.languages && navigator.languages.length)
            ? navigator.languages
            : [navigator.language || 'en'];

    // Display sanitized filename above the playback window
    var filenameContainer = document.getElementById('video-filename');
    if (filenameContainer && (videoSrc || rawSrc)) {
        var filepath = videoSrc || rawSrc;
        var parts = filepath.split('/');
        var filename = '';
        if (parts[parts.length - 1] === 'index.m3u8' && parts.length > 1) {
            filename = parts[parts.length - 2];
        } else {
            filename = parts[parts.length - 1];
        }
        filenameContainer.textContent = filename;
    }

    // Toggle debug logs panel visibility
    var toggleBtn = document.getElementById('toggle-logs-btn');
    var debugPanel = document.getElementById('debug-panel');
    if (toggleBtn && debugPanel) {
        toggleBtn.addEventListener('click', function() {
            debugPanel.classList.toggle('hidden');
        });
    }

    if (rawSrc) {
        // Play directly via HTTP Range requests natively supported by lws
        video.src = rawSrc;
        video.addEventListener('loadedmetadata', function() {
            video.play();
        });
        return;
    }

    if (!videoSrc) {
        alert("No video source provided.");
        return;
    }

    var logsContainer = document.getElementById('debug-logs');
    function logMsg(msg) {
        if (logsContainer) {
            var time = new Date().toLocaleTimeString();
            logsContainer.innerHTML = '[' + time + '] ' + msg + '<br>' + logsContainer.innerHTML;
        }
    }

    // Video Element Events
    video.addEventListener('play', function() { logMsg('video: play'); });
    video.addEventListener('playing', function() { logMsg('video: playing'); });
    video.addEventListener('pause', function() { logMsg('video: pause'); });
    video.addEventListener('waiting', function() { logMsg('video: waiting (buffering)'); });
    video.addEventListener('stalled', function() { logMsg('video: stalled'); });
    video.addEventListener('seeking', function() { logMsg('video: seeking to ' + video.currentTime.toFixed(3) + 's'); });
    video.addEventListener('seeked', function() { logMsg('video: seeked to ' + video.currentTime.toFixed(3) + 's'); });
    video.addEventListener('error', function() {
        var err = video.error;
        logMsg('video error: code ' + (err ? err.code : 'unknown') + ', msg: ' + (err ? err.message : 'unknown'));
    });

    function getHash(str) {
        if (crypto && crypto.subtle) {
            return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then(function(buf) {
                return Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
            });
        }
        return new Promise(function(resolve) {
            var hash = 0;
            for (var i = 0; i < str.length; i++) hash = ((hash << 5) - hash) + str.codePointAt(i) | 0;
            resolve(hash.toString(36));
        });
    }

    var tsSrc = urlParams.get('t') || '0';
    getHash(videoSrc + '_' + tsSrc).then(function(hk) {
        var hashKey = 'lws_hls_' + hk;
        var startPos = 0;
        
        try {
            var saved = localStorage.getItem(hashKey);
            if (saved) {
                var parsed = JSON.parse(saved);
                if (Date.now() - parsed.ts < 604800000) { // 1 week
                    startPos = parsed.pos;
                    logMsg('resuming from ' + startPos.toFixed(1) + 's');
                } else {
                    localStorage.removeItem(hashKey);
                    parsed = null;
                }
            }
        } catch(e) {
            /* ignore */
            parsed = null;
        }

        /* Persistent player state shared across the resume-position writer
         * (timeupdate) and the subtitle selection UI. ccOn/subId are restored
         * from localStorage and re-applied once hls.js reports the available
         * subtitle tracks. subId is the track NAME (e.g. "Subtitles [e9,
         * subrip]"), which is stable for a given file regardless of hls.js's
         * array ordering. */
        var resumeState = {
            ccOn: !!(parsed && parsed.ccOn),
            subId: (parsed && parsed.subId) || '',
            lastPos: -1, lastCcOn: null, lastSubId: null
        };

        video.addEventListener('timeupdate', function() {
            if (!video.duration || Number.isNaN(video.duration)) return;
            var pct = video.currentTime / video.duration;
            if (pct >= 0.95) {
                localStorage.removeItem(hashKey);
            } else if (video.currentTime > 0) {
                /* Throttle writes: only persist every ~5s, and only when the
                 * position (rounded) or sub state actually changed. */
                var posR = Math.floor(video.currentTime);
                if (posR === resumeState.lastPos &&
                    resumeState.ccOn === resumeState.lastCcOn &&
                    resumeState.subId === resumeState.lastSubId)
                    return;
                resumeState.lastPos = posR;
                resumeState.lastCcOn = resumeState.ccOn;
                resumeState.lastSubId = resumeState.subId;
                localStorage.setItem(hashKey, JSON.stringify({
                    pos: video.currentTime,
                    dur: video.duration,
                    ts: Date.now(),
                    ccOn: resumeState.ccOn,
                    subId: resumeState.subId
                }));
            }
        });

        // ---- subtitle (CC) UI ----
        // Subtitles stay OFF until the user clicks CC. The dropdown
        // remembers a preferred language (chosen against navigator.language
        // when the track list arrives) and is used as the target when CC
        // is toggled on.
        var ccBtn = document.getElementById('cc-btn');
        var subSel = document.getElementById('sub-lang');
        var subState = { ccOn: false, reported: false };

        function langPrefix(lang) {
            return (lang || '').toLowerCase().split('-')[0];
        }

        // Natural-order string compare: compares digit runs numerically and
        // everything else lexically, so "e2" < "e10" (not "e10" < "e2" as
        // plain string compare would give). Used to sort the dropdown so the
        // track list reads e2, e3, ..., e10, e11.
        function natCmp(a, b) {
            var i = 0, j = 0;
            while (i < a.length && j < b.length) {
                var ca = a.codePointAt(i), cb = b.codePointAt(j);
                var da = (ca >= 48 && ca <= 57), db = (cb >= 48 && cb <= 57);
                if (da && db) {
                    // gather the whole digit run on each side
                    var si = i, sj = j;
                    while (i < a.length && a.codePointAt(i) >= 48 && a.codePointAt(i) <= 57) i++;
                    while (j < b.length && b.codePointAt(j) >= 48 && b.codePointAt(j) <= 57) j++;
                    var na = Number.parseInt(a.slice(si, i), 10);
                    var nb = Number.parseInt(b.slice(sj, j), 10);
                    if (na !== nb) return na < nb ? -1 : 1;
                } else {
                    if (ca !== cb) return ca < cb ? -1 : 1;
                    i++; j++;
                }
            }
            return (a.length - i) - (b.length - j);
        }

        // Pick the best-matching subtitle track ARRAY INDEX from a list of
        // {id, name, lang, ...} using the browser's preferred languages.
        // Returns -1 if none match. hls.subtitleTrack takes an index into
        // hls.subtitleTracks (which equals the track's id when ids are 0..N-1,
        // but using the index directly is unambiguous).
        function pickDefaultSub(tracks) {
            for (var pi = 0; pi < prefLangs.length; pi++) {
                var pl = langPrefix(prefLangs[pi]);
                if (!pl) continue;
                for (var ti = 0; ti < tracks.length; ti++) {
                    if (langPrefix(tracks[ti].lang) === pl)
                        return ti;
                }
            }
            return tracks.length ? 0 : -1;
        }

        if (ccBtn && subSel) {
            ccBtn.addEventListener('click', function() {
                var target = subSel.value;
                if (subState.ccOn) {
                    subState.ccOn = false;
                    resumeState.ccOn = false;
                    resumeState.subId = '';
                    subOnOff(false);
                    ccBtn.classList.remove('active');
                    logMsg('subs: off');
                } else if (target && target !== '-1') {
                    subState.ccOn = true;
                    resumeState.ccOn = true;
                    resumeState.subId = currentSubName();
                    subOnOff(target);
                    ccBtn.classList.add('active');
                    logMsg('subs: on (' + subSel.options[subSel.selectedIndex].text + ')');
                }
            });
            subSel.addEventListener('change', function() {
                /* remember the new selection even if CC is off, so a later
                 * CC-on restores this choice; update persisted subId when on. */
                if (subState.ccOn) {
                    var t = subSel.value;
                    if (t && t !== '-1') {
                        subOnOff(t);
                        resumeState.subId = currentSubName();
                    }
                } else {
                    resumeState.subId = currentSubName();
                }
            });
            /* display name of whatever the dropdown currently points at */
            function currentSubName() {
                var o = subSel.options[subSel.selectedIndex];
                return o ? o.textContent : '';
            }
        }

        // subOnOff() is bound per-branch below (hls.js sets hls.subtitleTrack;
        // native HLS toggles textTracks[i].mode).
        var subOnOff = function() {};

        if (Hls.isSupported()) {
            logMsg('hls.js supported');
            var hls = new Hls({
                debug: false,
                maxBufferLength: 60,
                maxMaxBufferLength: 120,
                maxBufferHole: 0.5,
                startPosition: startPos,
                nudgeMaxRetry: 5,
                // Hand subtitle tracks to the <video>'s native TextTracks so
                // the browser renders cues with its default styling. (This is
                // hls.js's default in 1.5.8; set explicitly for clarity.)
                renderTextTracksNatively: true,
            });
            hls.loadSource(videoSrc);
            hls.attachMedia(video);
            
            hls.on(Hls.Events.MANIFEST_PARSED, function() {
                logMsg('hls: manifest parsed, playing');
                video.play();
            });

            hls.on(Hls.Events.ERROR, function(event, data) {
                var msg = 'hls error: type=' + data.type + ', details=' + data.details + ', fatal=' + data.fatal;
                logMsg(msg);
                if (data.fatal) {
                    switch(data.type) {
                        case Hls.ErrorTypes.NETWORK_ERROR:
                            logMsg('hls: fatal network error, trying to recover');
                            hls.startLoad();
                            break;
                        case Hls.ErrorTypes.MEDIA_ERROR:
                            logMsg('hls: fatal media error, trying to recover');
                            hls.recoverMediaError();
                            break;
                        default:
                            logMsg('hls: unrecoverable fatal error');
                            hls.destroy();
                            break;
                    }
                }
            });

            hls.on(Hls.Events.BUFFER_APPENDED, function() {
                if (video.buffered.length > 0) {
                    var ranges = [];
                    for (var i = 0; i < video.buffered.length; i++) {
                        ranges.push('[' + video.buffered.start(i).toFixed(1) + 's - ' + video.buffered.end(i).toFixed(1) + 's]');
                    }
                    logMsg('buffer: ' + ranges.join(', '));
                }
            });
            hls.on(Hls.Events.FRAG_LOADING, function(event, data) {
                if (data.frag) {
                    logMsg('loading seg ' + data.frag.sn + ' (' + data.frag.start.toFixed(1) + 's - ' + (data.frag.start + data.frag.duration).toFixed(1) + 's)');
                }
            });

            // ---- subtitle diagnostics + UI ----
            // We log liberally so the player logs panel shows exactly what
            // hls.js thinks the subtitle situation is, without guessing.

            // Raw manifest: fires for both master and media playlists. For a
            // master playlist, data.subtitleTracks / data.audioTracks hold the
            // parsed #EXT-X-MEDIA entries; for a media playlist (no subs),
            // subtitleTracks is empty.
            hls.on(Hls.Events.MANIFEST_LOADED, function(event, data) {
                var nLevels = (data && data.levels) ? data.levels.length : 0;
                var nSubs = (data && data.subtitleTracks) ? data.subtitleTracks.length : 0;
                var nAudio = (data && data.audioTracks) ? data.audioTracks.length : 0;
                logMsg('subs: MANIFEST_LOADED levels=' + nLevels +
                       ' subtitleTracks=' + nSubs + ' audioTracks=' + nAudio +
                       ' (' + (nLevels ? 'master' : 'media') + ' playlist)');
            });

            hls.on(Hls.Events.SUBTITLE_TRACKS_UPDATED, function(event, data) {
                var subs = (data && data.subtitleTracks) ? data.subtitleTracks : [];
                subState.reported = true;
                logMsg('subs: SUBTITLE_TRACKS_UPDATED -> ' + subs.length + ' track(s)');
                subs.forEach(function(t, i) {
                    logMsg('  sub track idx=' + i +
                           ' id="' + (t.id !== undefined ? t.id : '') + '"' +
                           ' name="' + (t.name || '') + '"' +
                           ' lang="' + (t.lang || '') + '"' +
                           ' type="' + (t.type || '') + '"' +
                           ' groupId="' + (t.groupId || '') + '"' +
                           ' url=' + (t.url || '(none)'));
                });
                if (!subs.length) {
                    logMsg('subs: no subtitle tracks in this playlist ' +
                           '(server found no usable text subs; bitmap subs ' +
                           'like PGS/VOBSUB/DVB are skipped server-side)');
                    return;
                }
                if (!ccBtn || !subSel) return;

                // Build the dropdown in NATURAL order of the track name (which
                // embeds the id like "Subtitles [e9, subrip]"), so the user
                // sees e2, e3, ..., e10, e11 rather than the lexicographic
                // e10, e11, e2, e3 that hls.js's array order yields. The
                // <option value> is still the ORIGINAL array index into subs[],
                // because that's what hls.subtitleTrack consumes — we keep a
                // sorted list of (origIndex) so the value mapping is correct
                // regardless of display order.
                var order = subs.map(function(t, i) { return i; });
                order.sort(function(a, b) {
                    return natCmp(subs[a].name || '', subs[b].name || '');
                });

                subSel.innerHTML = '';
                var off = document.createElement('option');
                off.value = '-1';
                off.textContent = 'Off';
                subSel.appendChild(off);
                order.forEach(function(origIdx) {
                    var t = subs[origIdx];
                    var o = document.createElement('option');
                    o.value = String(origIdx);
                    o.textContent = t.name || t.lang || ('track ' + origIdx);
                    subSel.appendChild(o);
                });

                // Pick the initial dropdown selection. If we restored a saved
                // subId from localStorage and it still exists, prefer that;
                // otherwise fall back to the navigator.language default.
                var def = -1;
                if (resumeState.subId) {
                    for (var oi = 0; oi < subSel.options.length; oi++) {
                        if (subSel.options[oi].textContent === resumeState.subId) {
                            def = Number.parseInt(subSel.options[oi].value, 10);
                            break;
                        }
                    }
                    if (def === -1)
                        logMsg('subs: saved selection "' + resumeState.subId +
                               '" no longer exists, using default');
                }
                if (def === -1) {
                    def = pickDefaultSub(subs);
                    if (def !== -1)
                        logMsg('subs: preferred language "' + prefLangs.join(',') +
                               '" -> default idx=' + def + ' "' +
                               (subs[def] || {}).name +
                               '" (off until CC clicked)');
                } else {
                    logMsg('subs: restoring saved selection "' +
                           resumeState.subId + '" (idx=' + def + ')');
                }
                subSel.value = (def !== -1) ? String(def) : '-1';

                ccBtn.classList.remove('hidden');
                subSel.classList.remove('hidden');

                // If subs were on last time, re-enable them now (after the
                // dropdown is populated and the selection set).
                if (resumeState.ccOn && def !== -1 && !subState.ccOn) {
                    subState.ccOn = true;
                    subOnOff(def);
                    ccBtn.classList.add('active');
                    logMsg('subs: restored ON (' +
                           subSel.options[subSel.selectedIndex].text + ')');
                }
            });

            hls.on(Hls.Events.SUBTITLE_TRACK_LOADED, function(event, data) {
                logMsg('subs: track ' + (data && data.id !== undefined ? data.id : '?') +
                       ' playlist loaded');
            });

            hls.on(Hls.Events.SUBTITLE_TRACK_SWITCH, function(event, data) {
                logMsg('subs: switched to id=' + (data && data.id !== undefined ? data.id : '?'));
            });

            // Cues actually arrived from a sub segment and were parsed. This
            // is the definitive "subs data reached hls.js" signal — distinct
            // from "the playlist was fetched" (SUBTITLE_TRACK_LOADED). We also
            // dump each decoded cue's text here so the operator can see, on
            // the player page, exactly what subs the server produced.
            hls.on(Hls.Events.CUES_PARSED, function(event, data) {
                var cues = (data && data.cues) ? data.cues : [];
                var ncues = cues.length;
                var tname = (data && data.track)
                        ? (data.track.lang || data.track.name || '?') : '?';
                var first = ncues ? ('first=' + cues[0].startTime.toFixed(2) +
                           '->' + cues[0].endTime.toFixed(2)) : '';
                logMsg('subs: CUES_PARSED ' + ncues + ' cue(s) track="' +
                       tname + '" ' + first);

                // Dump the decoded cue text. Cap per-event to keep the log
                // readable for long segments; note if truncated.
                var MAXDUMP = 12;
                var shown = Math.min(ncues, MAXDUMP);
                for (var i = 0; i < shown; i++) {
                    var c = cues[i];
                    var body = (c.text || '').replace(/\n/g, ' / ');
                    if (body.length > 120)
                        body = body.slice(0, 117) + '...';
                    logMsg('  cue[' + i + '] ' +
                           c.startTime.toFixed(2) + '->' +
                           c.endTime.toFixed(2) + ' "' + body + '"');
                }
                if (ncues > MAXDUMP)
                    logMsg('  ...(' + (ncues - MAXDUMP) + ' more cue(s) not shown)');

                // Position cues: snapToLines=false makes .line a percentage
                // (0=top, 100=bottom). cueLineForView() is geometry-driven
                // (lifts ~1 line when the video is near-fullscreen) so cues
                // clear tablet bottom-bezel camera cutouts and aren't clipped.
                var line = cueLineForView();
                for (var k = 0; k < ncues; k++) {
                    try {
                        cues[k].snapToLines = false;
                        cues[k].line = line;
                    } catch (e) { /* VTTCue props may be read-only in some impls */ }
                }
                // make sure the font size custom property is current too
                applyCueMetrics();
            });

            // A subtitle fragment was processed. Useful to confirm the VTT
            // segments are actually being downloaded and decoded.
            hls.on(Hls.Events.SUBTITLE_FRAG_PROCESSED, function(event, data) {
                var f = data && data.frag;
                logMsg('subs: frag processed sn=' + (f ? f.sn : '?') +
                       (f ? ' (' + f.start.toFixed(1) + 's-' + (f.start + f.duration).toFixed(1) + 's)' : ''));
            });

            // If by the time the main manifest is parsed we never got a
            // SUBTITLE_TRACKS_UPDATED, say so explicitly (otherwise the user
            // just sees the CC button never appear and has to guess why).
            hls.on(Hls.Events.MANIFEST_PARSED, function() {
                setTimeout(function() {
                    if (!subState.reported)
                        logMsg('subs: no SUBTITLE_TRACKS_UPDATED event from ' +
                               'hls.js (no subtitle tracks advertised in the ' +
                               'playlist)');
                }, 500);
            });

            // hls.js: hls.subtitleTrack takes the ARRAY INDEX into
            // hls.subtitleTracks (-1 = off). It asynchronously fetches that
            // track's playlist and cues; SUBTITLE_TRACK_LOADED /
            // SUBTITLE_TRACK_SWITCH confirm it happened.
            subOnOff = function(target) {
                if (target === false) {
                    hls.subtitleTrack = -1;
                    logMsg('subs: hls.subtitleTrack = -1 (off)');
                } else {
                    var idx = Number.parseInt(target, 10);
                    var nAvail = (hls.subtitleTracks ? hls.subtitleTracks.length : -1);
                    hls.subtitleTrack = idx;
                    // readback + array size: if hls.js rejected the set
                    // (e.g. idx >= tracksInGroup.length after dedup) the
                    // readback will be -1 and we'll see the mismatch.
                    var rb = hls.subtitleTrack;
                    logMsg('subs: hls.subtitleTrack = ' + idx +
                           ' (readback=' + rb +
                           ', subtitleTracks.length=' + nAvail + ')');
                    if (rb !== idx)
                        logMsg('subs: WARNING - hls.js did not accept track ' +
                               idx + ' (readback ' + rb + '): it may have ' +
                               'deduped the playlist; check SUBTITLE_TRACKS_' +
                               'UPDATED count above vs number of tracks');
                    // After giving hls.js a moment to create the native
                    // TextTrack + load the first fragment, dump its state so
                    // we can see whether cues actually made it to the element
                    // that the browser renders from.
                    [250, 1500, 4000].forEach(function(ms) {
                        setTimeout(dumpNativeTextTracks, ms);
                    });
                }
            };

            // ---- cue sizing + positioning, driven by video geometry ----
            //
            // We deliberately do NOT rely on the :fullscreen pseudo-class or
            // the fullscreenchange event: both are flaky on mobile (Android
            // especially), which produced random results — large font in the
            // small window, small font in fullscreen, etc. Instead we watch
            // the video's actual rendered size (ResizeObserver + window
            // resize/orientationchange) and compute everything from that.
            //
            // Font size: written into a dedicated <style> element as a concrete
            // px rule for video::cue. We use a live stylesheet (rather than a
            // CSS custom property) because some browsers don't resolve var()
            // inside ::cue's UA shadow tree. Sized to ~4.5% of the video
            // height (readable in the small frame, proportional in fullscreen).
            var cueStyle = document.createElement('style');
            document.head.appendChild(cueStyle);
            function setCueFontSize(px) {
                cueStyle.textContent =
                    'video::cue{font-size:' + px + 'px;line-height:1.25;' +
                    'background:rgba(0,0,0,0.72);color:#fff;white-space:pre-wrap;}';
            }
            setCueFontSize(18); /* sensible default until first metrics pass */
            function applyCueMetrics() {
                var rect = video.getBoundingClientRect();
                var vhgt = rect.height || 0;
                if (vhgt <= 0) return;
                var fs = Math.max(12, Math.round(vhgt * 0.045));
                setCueFontSize(fs);
                reapplyCueLines();
            }
            function cueLineForView() {
                // Lift cues further from the bottom when the video is large,
                // to clear tablet front-camera cutouts that sit in the bottom
                // bezel. "Large" = fills most of the screen height.
                var rect = video.getBoundingClientRect();
                var vhgt = rect.height || 0;
                var sh = window.innerHeight || screen.height || 0;
                if (sh > 0 && vhgt / sh > 0.80) return 80; /* ~fullscreen */
                return 86;
            }
            function reapplyCueLines() {
                var tts = video.textTracks;
                if (!tts) return;
                var line = cueLineForView();
                for (var i = 0; i < tts.length; i++) {
                    var cs = tts[i].cues;
                    if (!cs) continue;
                    for (var j = 0; j < cs.length; j++) {
                        try {
                            cs[j].snapToLines = false;
                            cs[j].line = line;
                        } catch (e) { /* ignore */ }
                    }
                }
            }
            if (window.ResizeObserver) {
                var ro = new ResizeObserver(function () { applyCueMetrics(); });
                ro.observe(video);
            }
            window.addEventListener('resize', applyCueMetrics);
            window.addEventListener('orientationchange', applyCueMetrics);
            video.addEventListener('loadedmetadata', applyCueMetrics);
            // re-run shortly after load too, once layout has settled
            setTimeout(applyCueMetrics, 500);
            setTimeout(applyCueMetrics, 2000);

            // Pure diagnostic: log each native video.textTracks entry (the
            // rendering surface when renderTextTracksNatively is true) — its
            // mode, cue count, first/last cue times, and first cue text. We do
            // NOT mutate track modes here: with renderTextTracksNatively true,
            // hls.js owns the native track modes, and forcing them ourselves
            // (a previous version did) breaks selection when multiple tracks
            // share the same language (it would activate all of them).
            function dumpNativeTextTracks() {
                var tts = video.textTracks;
                if (!tts || !tts.length) {
                    logMsg('subs: video.textTracks empty');
                    return;
                }
                for (var i = 0; i < tts.length; i++) {
                    var tt = tts[i];
                    var c = tt.cues;
                    var n = c ? c.length : 0;
                    var fr = (n && c[0]) ? (fmtTC(c[0].startTime) + '->' + fmtTC(c[0].endTime)) : '';
                    var lr = (n && c[n - 1]) ? (fmtTC(c[n - 1].startTime) + '->' + fmtTC(c[n - 1].endTime)) : '';
                    logMsg('subs: textTrack[' + i + '] kind="' + tt.kind +
                           '" lang="' + (tt.language || '') + '" label="' + (tt.label || '') +
                           '" mode="' + tt.mode +
                           '" cues=' + n + (n ? (' [' + fr + ' ... ' + lr + ']') : ''));
                    if (n && c[0] && c[0].text) {
                        var body = c[0].text.replace(/\n/g, ' / ');
                        if (body.length > 120)
                            body = body.slice(0, 117) + '...';
                        logMsg('  textTrack[' + i + '] cue[0] text="' + body + '"');
                    }
                }
            }
            function fmtTC(t) { return (typeof t === 'number') ? t.toFixed(2) + 's' : '?'; }
        }
        // For Safari, which natively supports HLS
        else if (video.canPlayType('application/vnd.apple.mpegurl')) {
            logMsg('native HLS supported');
            video.src = videoSrc;
            video.addEventListener('loadedmetadata', function() {
                logMsg('native HLS metadata loaded, playing');
                if (startPos > 0) {
                    video.currentTime = startPos;
                }
                video.play();

                // native HLS exposes subtitle variants as <video>.textTracks
                populateNativeSubs();
            });

            function populateNativeSubs() {
                var tts = video.textTracks;
                var i, subTracks = [];
                for (i = 0; i < tts.length; i++) {
                    if (tts[i].kind === 'subtitles' || tts[i].kind === 'captions') {
                        subTracks.push({
                            id: i,
                            name: tts[i].label || tts[i].language || ('track ' + i),
                            lang: tts[i].language || ''
                        });
                        // start everything disabled; CC toggle enables
                        tts[i].mode = 'disabled';
                    }
                }
                logMsg('subs: ' + subTracks.length + ' native track(s)');
                if (!subTracks.length || !ccBtn || !subSel) return;

                subSel.innerHTML = '';
                var off = document.createElement('option');
                off.value = '-1';
                off.textContent = 'Off';
                subSel.appendChild(off);
                subTracks.forEach(function(t) {
                    var o = document.createElement('option');
                    o.value = t.id;
                    o.textContent = t.name;
                    subSel.appendChild(o);
                });

                var def = pickDefaultSub(subTracks);
                subSel.value = (def !== -1) ? def : '-1';
                ccBtn.classList.remove('hidden');
                subSel.classList.remove('hidden');
            }

            // native HLS: target = numeric textTrack index, false = off
            subOnOff = function(target) {
                var tts = video.textTracks;
                var i;
                if (target === false) {
                    for (i = 0; i < tts.length; i++)
                        if (tts[i].kind === 'subtitles' || tts[i].kind === 'captions')
                            tts[i].mode = 'disabled';
                } else {
                    for (i = 0; i < tts.length; i++) {
                        if (tts[i].kind !== 'subtitles' && tts[i].kind !== 'captions')
                            continue;
                        tts[i].mode = (i === Number.parseInt(target, 10)) ? 'showing' : 'disabled';
                    }
                }
            };

            // Polling buffer status for native HLS
            setInterval(function() {
                if (video.buffered.length > 0) {
                    var ranges = [];
                    for (var i = 0; i < video.buffered.length; i++) {
                        ranges.push('[' + video.buffered.start(i).toFixed(1) + 's - ' + video.buffered.end(i).toFixed(1) + 's]');
                    }
                    logMsg('native buffer: ' + ranges.join(', '));
                }
            }, 2000);
        }
        else {
            logMsg('error: browser does not support HLS');
            alert("Your browser does not support playing this video.");
        }
    });
});
