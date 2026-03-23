// auth.js - CSP Compliant Frontend Logic

document.addEventListener('DOMContentLoaded', () => {
    // Elements
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const totpGroup = document.getElementById('totp-group');

    const regToggleBox = document.getElementById('registration-toggle-box');
    const logToggleBox = document.getElementById('login-toggle-box');
    const switchRegBtn = document.getElementById('switch-to-reg');
    const switchLoginBtn = document.getElementById('switch-to-login');

    const notifBox = document.getElementById('notification');
    const notifMsg = document.getElementById('notif-message');
    const subtitle = document.getElementById('subtitle');

    let isRegistrationMode = false;
    let totpRequired = false;

    // Check backend status automatically
    async function checkServerStatus() {
        try {
            const response = await fetch('/auth/api/status');
            if (response.ok) {
                const data = await response.json();
                if (data.users_empty) {
                    isRegistrationMode = true;
                    loginForm.classList.add('hidden');
                    registerForm.classList.remove('hidden');
                    regToggleBox.classList.add('hidden');
                    logToggleBox.classList.add('hidden'); // Drop the login escape hatch

                    subtitle.innerText = "Initial Network Registration (Admin Bootstrap)";
                }
            }
        } catch (e) {
            console.error("Status polling failed", e);
        }
    }

    checkServerStatus();

    // View Switching
    switchRegBtn.addEventListener('click', () => {
        isRegistrationMode = true;
        loginForm.classList.add('hidden');
        registerForm.classList.remove('hidden');
        regToggleBox.classList.add('hidden');
        logToggleBox.classList.remove('hidden');
        subtitle.innerText = "Initial Network Registration";
        hideNotif();
    });

    switchLoginBtn.addEventListener('click', () => {
        isRegistrationMode = false;
        registerForm.classList.add('hidden');
        loginForm.classList.remove('hidden');
        logToggleBox.classList.add('hidden');
        regToggleBox.classList.remove('hidden');
        subtitle.innerText = "Authenticate your session to continue";
        hideNotif();
    });

    // Form Submissions
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = document.getElementById('login-btn');
        btn.classList.add('loading');
        hideNotif();

        const formData = new FormData(loginForm);
        const payload = Object.fromEntries(formData.entries());

        try {
            // Send to auth plugin endpoint handled by LWS
            const response = await fetch('/auth/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams(formData).toString()
            });

            if (response.status === 401) {
                const reqTotp = response.headers.get('X-Requires-TOTP');
                if (reqTotp) {
                    totpRequired = true;
                    totpGroup.classList.remove('hidden');
                    showNotif('error', 'Authenticator code required.');
                } else {
                    let errMsg = 'Invalid security credentials.';
                    try {
                        const data = await response.json();
                        if (data && data.error) errMsg = data.error;
                    } catch (e) {}
                    showNotif('error', errMsg);
                }
            } else if (response.ok) {
                const data = await response.json();
                showNotif('success', 'Clearance accepted. Welcome.');
                // Usually LWS sets cookie, but we can also store token in memory if preferred
                setTimeout(() => window.location.href = '/', 1000);
            } else {
                showNotif('error', 'Server anomaly detected.');
            }
        } catch (err) {
            showNotif('error', 'Network communication failed.' + err.message);
        } finally {
            btn.classList.remove('loading');
        }
    });

    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = document.getElementById('reg-btn');
        btn.classList.add('loading');
        hideNotif();

        const formData = new FormData(registerForm);
        const payload = Object.fromEntries(formData.entries());

        try {
            const response = await fetch('/auth/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams(formData).toString()
            });

            if (response.ok) {
                showNotif('success', 'Verification dispatched. Please check your email.');
                setTimeout(() => switchLoginBtn.click(), 3000);
            } else if (response.status === 403) {
                showNotif('error', 'Registration UI is administratively locked.');
            } else {
                let errMsg = 'User formation failed or exists.';
                try {
                    const data = await response.json();
                    if (data && data.error) errMsg = data.error;
                } catch (e) {}
                showNotif('error', errMsg);
            }
        } catch (err) {
            showNotif('error', 'Network communication failed.');
        } finally {
            btn.classList.remove('loading');
        }
    });

    function showNotif(type, msg) {
        notifBox.className = `notification ${type}`;
        notifMsg.innerText = msg;
    }

    document.getElementById('finish-totp-btn').addEventListener('click', () => {
        document.getElementById('totp-setup-box').classList.add('hidden');
        switchLoginBtn.click();
    });

    function hideNotif() {
        notifBox.className = 'notification hidden';
    }
});
