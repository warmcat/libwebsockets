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


    async function loadManifest() {
        try {
            const response = await fetch('/api/manifest', { cache: 'no-store', credentials: 'include' });
            if (response.ok) {
                const data = await response.json();

                if (data.ui_title && data.ui_title !== "") {
                    const h1 = document.querySelector('.panel-header h1');
                    if (h1) h1.innerText = data.ui_title;
                }

                if (data.ui_subtitle && data.ui_subtitle !== "") {
                    if (subtitle) subtitle.innerText = data.ui_subtitle;
                }

                if (data.ui_new_network && data.ui_new_network !== "") {
                    // Update text node before the button without destroying the button
                    if (regToggleBox && regToggleBox.firstElementChild) {
                        const p = regToggleBox.firstElementChild;
                        if (p.childNodes.length > 0 && p.childNodes[0].nodeType === Node.TEXT_NODE) {
                            p.childNodes[0].nodeValue = data.ui_new_network + " ";
                        }
                    }
                }

                if (data.ui_css && data.ui_css !== "") {
                    const link = document.createElement("link");
                    link.rel = "stylesheet";
                    link.href = data.ui_css;
                    document.head.appendChild(link);
                }
            }
        } catch (e) {
            console.error("Manifest load failed", e);
        }
    }

    function renderAuthStatus(data, isDenied) {
        let grantsHtml = Object.keys(data.grants || {}).length
            ? '<table class="auth-grants-table">' +
              '<tr><th>Service</th><th class="level-col">Level</th></tr>' +
              Object.keys(data.grants).map(k => `<tr><td>${k}</td><td class="level-col">L${data.grants[k]}</td></tr>`).join('') +
              '</table>'
            : '<div class="auth-grants-empty">No Active Grants</div>';

        let logsHtml = (!isDenied && data.logs && data.logs.length)
            ? '<p class="auth-session-title auth-log-title">Valid JWK Peers</p>' +
              '<table class="auth-log-table">' +
              '<tr><th>Date / Time</th><th class="ip-col">IP Address</th></tr>' +
              data.logs.map(lg => `<tr><td class="time-col">${new Date(lg.time * 1000).toLocaleString()}</td><td class="ip-col">${lg.ip}</td></tr>`).join('') +
              '</table>'
            : '';

        let headerHtml = `<div class="auth-status-row success-row">
            <span class="auth-status-icon">✅</span>
            <span class="auth-status-text">Logged in as ${data.email || 'Unknown User'}</span>
        </div>`;

        if (isDenied) {
            headerHtml += `<div class="auth-status-row error-row auth-status-spacer">
                <span class="auth-status-icon">❌</span>
                <span class="auth-status-text">Doesn't grant '${serviceName || 'required service'}'</span>
            </div>`;
        } else {
            headerHtml += `<div class="auth-status-spacer"></div>`;
        }

        loginForm.innerHTML = `<div class="auth-session-box">
            ${headerHtml}
            ${grantsHtml}
            ${logsHtml}
            <button type="button" id="btn-destroy-session" class="btn primary-btn">${isDenied ? 'Logout / Switch User' : 'Logout'}</button>
        </div>`;

        document.getElementById('btn-destroy-session').addEventListener('click', async function() {
            const btn = this;
            btn.innerText = "Logging out...";
            btn.disabled = true;
            await fetch('/api/status?destroy=1', { cache: 'no-store', credentials: 'include' });
            window.location.reload();
        });
    }

    // Check backend status automatically
    async function checkServerStatus() {
        try {
            const statusUrl = serviceName ? `/api/status?service_name=${encodeURIComponent(serviceName)}` : '/api/status';
            const response = await fetch(statusUrl, { cache: 'no-store', credentials: 'include' });
            if (response.ok) {
                const data = await response.json();
                if (data.csrf_token) window.csrf_token = data.csrf_token;
                
                const strikeOverlay = document.getElementById('strike-overlay');
                const strikeCount = document.getElementById('strike-count');
                if (strikeOverlay && strikeCount) {
                    if (data.strikes > 0) {
                        strikeCount.innerText = data.strikes + "/5";
                        strikeOverlay.classList.remove('hidden');
                        setTimeout(() => strikeOverlay.classList.add('show-strike'), 20);
                    } else {
                        strikeOverlay.classList.remove('show-strike');
                        setTimeout(() => strikeOverlay.classList.add('hidden'), 1000);
                    }
                }

                if (data.logged_in) {
                    regToggleBox.classList.add('hidden');

                    if (data.lacks_grant) {
                        renderAuthStatus(data, true);
                        subtitle.innerText = "Insufficient Privileges";
                        /* The user requested getting rid of this error box entirely and standardizing.
                           Since showNotif generates this other error box, let's remove it if the user doesn't want redundancy,
                           or keep it if it's the notification. "I'd like to get rid of the first error box... and change it to this kind of simplified and standardized flow" */
                        // showNotif('error', 'You lack the required grant to access this service.');
                        return;
                    }

                    if (clientId && redirectUri) {
                        /*alert("auth.js auth redirect -> " + `/api/authorize`); */ window.location.href = `/api/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state||'')}&response_type=code` + (codeChallenge ? `&code_challenge=${encodeURIComponent(codeChallenge)}` : '') + (codeChallengeMethod ? `&code_challenge_method=${encodeURIComponent(codeChallengeMethod)}` : '');
                        return;
                    } else if (redirectUri) {
                        try {
                            const res = await fetch('/api/sso_exchange', {
                                method: 'POST',
                                credentials: 'include',
                                body: `redirect_uri=${encodeURIComponent(redirectUri)}&csrf_token=${encodeURIComponent(window.csrf_token || "")}`,
                                headers: {'Content-Type': 'application/x-www-form-urlencoded'}
                            });
                            if (res.ok) {
                                const tdata = await res.json();
                                if (tdata.token) {
                                    let u;
                                    try { u = new URL(redirectUri); } catch(e) {}
                                    if (u) {
                                        const form = document.createElement('form');
                                        form.method = 'POST';
                                        let path = u.pathname;
                                        if (path.endsWith('/')) path = path.slice(0, -1);
                                        form.action = u.origin + path + '/.lws-login-sso';
                                        const tInput = document.createElement('input');
                                        tInput.type = 'hidden';
                                        tInput.name = 'token';
                                        tInput.value = tdata.token;
                                        form.appendChild(tInput);
                                        const rInput = document.createElement('input');
                                        rInput.type = 'hidden';
                                        rInput.name = 'target';
                                        rInput.value = redirectUri;
                                        form.appendChild(rInput);
                                        document.body.appendChild(form);
                                        form.submit();
                                        return;
                                    }
                                }
                            } else {
                                const errData = await res.json();
                                loginForm.innerHTML = `<div class="auth-session-box">
                                    <div class="auth-status-row error-row auth-status-spacer">
                                        <span class="auth-status-icon">❌</span>
                                        <span class="auth-status-text">Security Violation</span>
                                    </div>
                                    <p class="auth-session-email">${errData.error || 'Untrusted Redirect URI'}</p>
                                    <p style="font-size: 0.8rem; color: #94a3b8; text-align: center; margin-top: 10px;">The specified redirection target is not whitelisted by the network administrator.</p>
                                </div>`;
                                subtitle.innerText = "Access Blocked";
                                showNotif('error', errData.error || 'Untrusted Redirect URI');
                                return;
                            }
                        } catch (e) {
                            console.error("SSO Exchange failed", e);
                            showNotif('error', 'SSO Network Failure');
                            return;
                        }
                        return;
                    } else {
                        renderAuthStatus(data, false);
                        subtitle.innerText = "Active Session";
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

    loadManifest();
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
        if (serviceName) formData.append("service_name", serviceName);

        try {
            // Send to auth plugin endpoint handled by LWS
            const response = await fetch('/api/login', {
                method: 'POST',
                credentials: 'include',
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
                    setTimeout(() => {
                        const firstBox = document.querySelector('.totp-box');
                        if (firstBox) firstBox.focus();
                    }, 50);
                } else {
                    let errMsg = 'Invalid security credentials.';
                    try {
                        const data = await response.json();
                        if (data && data.error) errMsg = data.error;
                    } catch (e) {}
                    showNotif('error', errMsg);
                    checkServerStatus();
                }
            } else if (response.status === 403) {
                let errMsg = 'Insufficient Privileges.';
                try {
                    const data = await response.json();
                    if (data && data.error) errMsg = data.error;
                } catch (e) {}
                showNotif('error', errMsg);
            } else if (response.ok) {
                const data = await response.json();
                const stkOverlay = document.getElementById('strike-overlay');
                if (stkOverlay) {
                    stkOverlay.classList.remove('show-strike');
                }
                if (data.redirect) {
                    window.location.href = data.redirect;
                } else if (redirectUri) {
                    let u;
                    try { u = new URL(redirectUri); } catch(e) {}
                    if (u) {
                        const form = document.createElement('form');
                        form.method = 'POST';
                        let path = u.pathname;
                        if (path.endsWith('/')) path = path.slice(0, -1);
                        form.action = u.origin + path + '/.lws-login-sso';
                        const tInput = document.createElement('input');
                        tInput.type = 'hidden';
                        tInput.name = 'token';
                        tInput.value = data.token;
                        form.appendChild(tInput);
                        const rInput = document.createElement('input');
                        rInput.type = 'hidden';
                        rInput.name = 'target';
                        rInput.value = redirectUri;
                        form.appendChild(rInput);
                        document.body.appendChild(form);
                        form.submit();
                    } else {
                        window.location.href = redirectUri;
                    }
                } else {
                    window.location.href = '/';
                }
            } else {
                let errMsg = 'Server anomaly detected.';
                try {
                    const data = await response.json();
                    if (data && data.error) errMsg = data.error;
                } catch (e) {}
                showNotif('error', errMsg);
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
                credentials: 'include',
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

    // TOTP Box Logic
    const totpBoxes = document.querySelectorAll('.totp-box');
    const totpHidden = document.getElementById('login-totp');

    if (totpBoxes.length > 0) {
        totpBoxes.forEach((box, index) => {
            box.addEventListener('input', (e) => {
                // Ensure only digits
                e.target.value = e.target.value.replace(/[^0-9]/g, '');

                if (e.target.value.length === 1) {
                    if (index < totpBoxes.length - 1) {
                        totpBoxes[index + 1].focus();
                    } else {
                        updateTotpHidden();
                        // Delay slightly so the input value registers visually before submit
                        setTimeout(() => loginForm.requestSubmit(), 50);
                    }
                }
                updateTotpHidden();
            });

            box.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace' && !e.target.value && index > 0) {
                    totpBoxes[index - 1].focus();
                } else if (e.key === 'Enter') {
                    e.preventDefault();
                    loginForm.requestSubmit();
                }
            });

            box.addEventListener('paste', (e) => {
                e.preventDefault();
                const pasted = (e.clipboardData || window.clipboardData).getData('text').trim().replace(/[^0-9]/g, '').slice(0, 6);
                if (pasted) {
                    for (let i = 0; i < pasted.length; i++) {
                        if (totpBoxes[i]) totpBoxes[i].value = pasted[i];
                    }
                    updateTotpHidden();
                    if (pasted.length === 6) {
                        totpBoxes[5].focus();
                        setTimeout(() => loginForm.requestSubmit(), 50);
                    } else {
                        totpBoxes[pasted.length].focus();
                    }
                }
            });
        });

        function updateTotpHidden() {
            let code = '';
            totpBoxes.forEach(b => code += b.value);
            if (totpHidden) totpHidden.value = code;
        }
    }

    // Initial Focus Management
    setTimeout(() => {
        const emailInput = document.getElementById('login-username');
        const passInput = document.getElementById('login-password');

        if (emailInput && !emailInput.value) {
            emailInput.focus();
        } else if (passInput && !passInput.value) {
            passInput.focus();
        } else if (totpBoxes.length > 0) {
            const tGroup = document.getElementById('totp-group');
            if (tGroup && !tGroup.classList.contains('hidden')) {
                totpBoxes[0].focus();
            }
        }
    }, 150);

    const deviceCodeParam = urlParams.get('device_code');
    const deviceAuthBox = document.getElementById('device-auth-box');
    const deviceAuthBtn = document.getElementById('device-auth-btn');
    const deviceCodeInput = document.getElementById('device-code');

    if (deviceCodeParam) {
        // Hide standard forms
        if (loginForm) loginForm.classList.add('hidden');
        if (registerForm) registerForm.classList.add('hidden');
        if (regToggleBox) regToggleBox.classList.add('hidden');
        if (logToggleBox) logToggleBox.classList.add('hidden');

        // Show device auth
        if (deviceAuthBox) {
            deviceAuthBox.classList.remove('hidden');
            deviceAuthBox.classList.add('active');
        }
        if (deviceCodeInput) {
            deviceCodeInput.value = deviceCodeParam;
        }
        if (subtitle) {
            subtitle.innerText = "Authorize a new device";
        }
    }

    if (deviceAuthBtn) {
        deviceAuthBtn.addEventListener('click', async () => {
            const code = deviceCodeInput.value.trim();
            if (code.length < 8) {
                showNotif('error', 'Invalid code length');
                return;
            }

            const loader = deviceAuthBtn.querySelector('.loader');
            const span = deviceAuthBtn.querySelector('span');

            deviceAuthBtn.disabled = true;
            if (loader) loader.classList.remove('hidden');
            if (span) span.innerText = 'Authorizing...';

            try {
                const formData = new URLSearchParams();
                formData.append('user_code', code);
                if (window.csrf_token) formData.append('csrf_token', window.csrf_token);

                const response = await fetch('/api/device_approve', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    credentials: 'include',
                    body: formData.toString()
                });

                if (response.ok) {
                    showNotif('success', 'Device authorized successfully!');
                    deviceAuthBox.innerHTML = `
                        <div class="auth-status-row success-row" style="margin-bottom: 0;">
                            <span class="auth-status-icon">✅</span>
                            <span class="auth-status-text">Device Authorized</span>
                        </div>
                        <p style="text-align: center; color: var(--text-muted); font-size: 0.9rem; margin-top: 15px;">
                            You may now close this tab. The device will connect automatically.
                        </p>
                    `;
                } else {
                    deviceAuthBtn.disabled = false;
                    if (loader) loader.classList.add('hidden');
                    if (span) span.innerText = 'Authorize Device';

                    let errMsg = 'Authorization failed';
                    try {
                        const data = await response.json();
                        if (data && data.error) errMsg = data.error;
                    } catch (e) {}
                    showNotif('error', errMsg);
                }
            } catch (e) {
                deviceAuthBtn.disabled = false;
                if (loader) loader.classList.add('hidden');
                if (span) span.innerText = 'Authorize Device';
                showNotif('error', 'Network error');
            }
        });
    }
});
