function getCookie(name) {
  let match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? match[2] : '';
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
      body: 'user_code=' + encodeURIComponent(code) + '&csrf_token=' + encodeURIComponent(getCookie('auth_csrf'))
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
