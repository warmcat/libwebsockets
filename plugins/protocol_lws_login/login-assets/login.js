document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get('error');
    if (error) {
        const errorMsg = document.getElementById('error-msg');
        errorMsg.textContent = decodeURIComponent(error);
        errorMsg.style.display = 'block';
    }
});
