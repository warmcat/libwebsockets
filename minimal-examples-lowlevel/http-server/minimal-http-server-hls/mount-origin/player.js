document.addEventListener('DOMContentLoaded', function() {
    if (typeof window.renderLwsLoginStatus === 'function') {
        window.renderLwsLoginStatus('auth-status');
    }

    var video = document.getElementById('video');
    
    var urlParams = new URLSearchParams(window.location.search);
    var videoSrc = urlParams.get('v');
    var rawSrc = urlParams.get('raw');

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

    if (Hls.isSupported()) {
        var hls = new Hls({
            debug: false,
        });
        hls.loadSource(videoSrc);
        hls.attachMedia(video);
        hls.on(Hls.Events.MANIFEST_PARSED, function() {
            video.play();
        });
    }
    // For Safari, which natively supports HLS
    else if (video.canPlayType('application/vnd.apple.mpegurl')) {
        video.src = videoSrc;
        video.addEventListener('loadedmetadata', function() {
            video.play();
        });
    }
    else {
        alert("Your browser does not support playing this video.");
    }
});
