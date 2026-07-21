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
                } catch (e) {}
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

    if (Hls.isSupported()) {
        logMsg('hls.js supported');
        var hls = new Hls({
            debug: false,
            maxBufferLength: 60,
            maxMaxBufferLength: 120,
            maxBufferHole: 0.5,
            startPosition: 0,
            nudgeMaxRetry: 5,
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
    }
    // For Safari, which natively supports HLS
    else if (video.canPlayType('application/vnd.apple.mpegurl')) {
        logMsg('native HLS supported');
        video.src = videoSrc;
        video.addEventListener('loadedmetadata', function() {
            logMsg('native HLS metadata loaded, playing');
            video.play();
        });

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
