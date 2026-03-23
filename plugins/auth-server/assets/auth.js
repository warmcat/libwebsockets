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

    const urlParams = new URLSearchParams(window.location.search);
    const clientId = urlParams.get('client_id');
    const redirectUri = urlParams.get('redirect_uri');
    const state = urlParams.get('state');
    const codeChallenge = urlParams.get('code_challenge');
    const codeChallengeMethod = urlParams.get('code_challenge_method');
    const serviceName = urlParams.get('service_name');

    // Check backend status automatically
    async function checkServerStatus() {
        try {
            const response = await fetch('/api/status');
            if (response.ok) {
                const data = await response.json();
                if (data.csrf_token) window.csrf_token = data.csrf_token;

                if (data.logged_in) {
                    if (clientId && redirectUri) {
                        window.location.href = `/api/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state||'')}&response_type=code` + (codeChallenge ? `&code_challenge=${encodeURIComponent(codeChallenge)}` : '') + (codeChallengeMethod ? `&code_challenge_method=${encodeURIComponent(codeChallengeMethod)}` : '');
                        return;
                    } else if (redirectUri) {
                        window.location.href = redirectUri;
                        return;
                    } else {
                        loginForm.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 2rem;"><p>Active session detected. You are securely authenticated.</p></div>`;
                        subtitle.innerText = "Authentication Successful";
                        return;
                    }
                }

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
        subtitle.innerText = serviceName ? "Authenticate to access " + serviceName : "Authenticate your session to continue";
        hideNotif();
    });

    if (serviceName && !isRegistrationMode) {
        subtitle.innerText = "Authenticate to access " + serviceName;
    }

    // Form Submissions
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = document.getElementById('login-btn');
        btn.classList.add('loading');
        hideNotif();

        const formData = new FormData(loginForm);
        formData.append("csrf_token", window.csrf_token || "");

        if (clientId) formData.append("client_id", clientId);
        if (redirectUri) formData.append("redirect_uri", redirectUri);
        if (state) formData.append("state", state);
        if (codeChallenge) formData.append("code_challenge", codeChallenge);
        if (codeChallengeMethod) formData.append("code_challenge_method", codeChallengeMethod);

        try {
            // Send to auth plugin endpoint handled by LWS
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
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
                if (data.redirect) {
                    setTimeout(() => window.location.href = data.redirect, 1000);
                } else {
                    setTimeout(() => window.location.href = '/', 1000);
                }
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
        formData.append("csrf_token", window.csrf_token || "");
        const payload = Object.fromEntries(formData.entries());

        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
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
