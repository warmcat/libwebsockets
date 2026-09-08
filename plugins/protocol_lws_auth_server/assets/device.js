/*
 * The auth_csrf cookie is the server half of the double-submit pair and
 * is deliberately HttpOnly, so script cannot read it out of
 * document.cookie.  The /api/device page therefore carries the current
 * token in a data-csrf attribute on the button, exactly as /api/status
 * hands it to auth.js in its JSON.
 */
function getCsrfToken() {
  const btn = document.getElementById('authBtn');
  return btn ? (btn.getAttribute('data-csrf') || '') : '';
}
async function authorize() {
  const code = document.getElementById('userCode').value.trim();
  const msg = document.getElementById('statusMsg');
  if (code.length < 8) { msg.textContent = 'Invalid code length'; msg.className = 'status error'; return; }
  msg.textContent = 'Authorizing...'; msg.className = 'status';
  try {
    const res = await fetch('/api/device_approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'user_code=' + encodeURIComponent(code) + '&csrf_token=' + encodeURIComponent(getCsrfToken())
    });
    if (res.ok) {
      msg.textContent = 'Device authorized successfully! You may close this window.';
      msg.className = 'status success';
      document.getElementById('authBtn').disabled = true;
    } else {
      const data = await res.json();
      msg.textContent = data.error || 'Authorization failed.';
      msg.className = 'status error';
    }
  } catch (e) { msg.textContent = 'Network error.'; msg.className = 'status error'; }
}

document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('authBtn');
  if (btn) btn.addEventListener('click', authorize);
});
