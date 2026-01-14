function startCaptcha() {
    var btn = document.getElementById('captcha-btn');
    var countdownDiv = document.getElementById('countdown');
    btn.style.display = 'none';

    var seconds = 5;
    countdownDiv.innerText = "Please wait " + seconds + " seconds...";

    var interval = setInterval(function() {
        seconds--;
        if (seconds > 0) {
            countdownDiv.innerText = "Please wait " + seconds + " seconds...";
        } else {
            clearInterval(interval);
            countdownDiv.innerText = "Verifying...";
        }
    }, 1000);

    return true;
}
