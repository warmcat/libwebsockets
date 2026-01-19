document.addEventListener('DOMContentLoaded', function() {
    var btn = document.getElementById('captcha-btn');
    var barCont = document.getElementById('bargraph-container');
    var barFill = document.getElementById('bargraph-fill');
    var sPre = document.getElementById('status-pre');
    var sReady = document.getElementById('status-ready');
    var sPressed = document.getElementById('status-pressed');
    var msg = document.getElementById('countdown-msg');
    var form = document.getElementById('captcha-form');
    var headerImg = document.getElementById('header-img');

    if (!btn) return;

    var pre_delay = (typeof lws_interceptor_pre_delay_ms !== 'undefined') ? lws_interceptor_pre_delay_ms : 2000;
    var post_delay = (typeof lws_interceptor_post_delay_ms !== 'undefined') ? lws_interceptor_post_delay_ms : 5000;

    // Load and stats
    var statLoad = document.getElementById('stat-load');
    var statServed = document.getElementById('stat-served');
    var statPassed = document.getElementById('stat-passed');

    if (statLoad && typeof lws_system_load !== 'undefined') statLoad.innerText = lws_system_load;
    if (statServed && typeof lws_interceptor_served !== 'undefined') statServed.innerText = lws_interceptor_served;
    if (statPassed && typeof lws_interceptor_passed !== 'undefined') statPassed.innerText = lws_interceptor_passed;

    if (headerImg) {
        var images = ['scrapers-1.jpg', 'scrapers-2.jpg', 'scrapers-3.jpg'];
        var randomImg = images[Math.floor(Math.random() * images.length)];
        headerImg.src = randomImg;
    }

    btn.style.display = 'none';
    if (barCont) barCont.style.display = 'block';

    function setStatus(id) {
        if (sPre) sPre.style.display = (id === 'pre') ? 'block' : 'none';
        if (sReady) sReady.style.display = (id === 'ready') ? 'block' : 'none';
        if (sPressed) sPressed.style.display = (id === 'pressed') ? 'block' : 'none';
    }

    function animateBar(duration, callback) {
        var start = Date.now();
        function frame() {
            var elapsed = Date.now() - start;
            var progress = Math.min(100, (elapsed / duration) * 100);
            if (barFill) barFill.style.width = progress + '%';
            
            if (elapsed < duration) {
                var left = Math.ceil((duration - elapsed) / 1000);
                if (msg) {
                    if (barFill.classList.contains('verifying'))
                        msg.innerText = 'Verifying... ' + left + 's remaining';
                    else
                        msg.innerText = 'Prove you are human... ' + left + 's remaining';
                }
                requestAnimationFrame(frame);
            } else {
                if (barFill) barFill.style.width = '100%';
                if (callback) callback();
            }
        }
        requestAnimationFrame(frame);
    }

    // Stage 1: Pre-delay
    setStatus('pre');
    animateBar(pre_delay, function() {
        setStatus('ready');
        if (msg) msg.innerText = 'Ready to continue.';
        btn.style.display = 'block';
    });

    if (form) {
        form.addEventListener('submit', function(e) {
            // Prevent multiple submissions
            if (btn.disabled) return;
            
            btn.disabled = true;
            btn.style.display = 'none';
            setStatus('pressed');
            
            if (barFill) {
                barFill.classList.add('verifying');
                barFill.style.width = '0%';
            }
            
            // Stage 2: Post-submission delay
            animateBar(post_delay, function() {
                if (msg) msg.innerText = 'Redirecting...';
            });
            
            // We let the form submit normally, the server will hold the connection
            // for post_delay_ms anyway. The JS animation is just for UI.
            return true;
        });
    }
});
