let ws;
let currentDomain = '';

function connect() {
    const l = window.location;
    let wsUrl = (l.protocol === "https:" ? "wss://" : "ws://") + l.host;

    ws = new WebSocket(wsUrl, "lws-dht-dnssec-monitor");

    const statusBadge = document.getElementById('ws-status');

    ws.onopen = function() {
        statusBadge.textContent = 'Connected';
        statusBadge.className = 'status-badge connected';
        sendReq({ req: 'get_domains' });
    };

    ws.onmessage = function(msg) {
        try {
            const data = JSON.parse(msg.data);
            handleResponse(data);
        } catch(e) {
            console.error('Failed to parse WS msg:', e);
        }
    };

    ws.onclose = function() {
        statusBadge.textContent = 'Disconnected';
        statusBadge.className = 'status-badge disconnected';
        setTimeout(connect, 3000);
    };
}

function sendReq(obj) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(obj));
    } else {
        showToast('Not connected to server', true);
    }
}

function showToast(msg, isError = false) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.className = 'toast show ' + (isError ? 'error' : 'success');
    setTimeout(() => {
        toast.className = 'toast';
    }, 3000);
}

function handleResponse(data) {
    if (data.status === 'error') {
        showToast(data.msg || 'An error occurred', true);
        return;
    }

    switch(data.req) {
        case 'get_domains':
            renderDomains(data.domains || []);
            break;
        case 'create_domain':
            closeModal('modal-new-domain');
            showToast('Domain created successfully');
            sendReq({ req: 'get_domains' });
            break;
        case 'delete_domain':
            showToast('Domain deleted');
            closeDetail();
            sendReq({ req: 'get_domains' });
            break;
        case 'get_zone':
            document.getElementById('zone-editor').value = data.zone || '';
            openModal('modal-zone');
            break;
        case 'update_zone':
            closeModal('modal-zone');
            showToast('Zonefile updated successfully');
            break;
        case 'get_tls':
            renderTls(data.tls || []);
            break;
        case 'create_tls':
            closeModal('modal-new-tls');
            showToast('TLS Subdomain configuration created');
            sendReq({ req: 'get_tls', domain: currentDomain });
            break;
        case 'delete_tls':
            showToast('TLS configuration deleted');
            sendReq({ req: 'get_tls', domain: currentDomain });
            break;
    }
}

function renderDomains(domains) {
    const tbody = document.querySelector('#table-domains tbody');
    tbody.innerHTML = '';

    if (!domains.length) {
        tbody.innerHTML = '<tr><td colspan="2" class="loading">No domains found. Add one to begin.</td></tr>';
        return;
    }

    domains.forEach(d => {
        const tr = document.createElement('tr');
        if (d === currentDomain) tr.classList.add('active');

        const tdName = document.createElement('td');
        const a = document.createElement('a');
        a.href = '#';
        a.textContent = d;
        a.onclick = (e) => {
            e.preventDefault();
            selectDomain(d);
        };
        tdName.appendChild(a);

        const tdAct = document.createElement('td');
        const btnDel = document.createElement('button');
        btnDel.className = 'btn btn-sm danger';
        btnDel.textContent = 'Delete';
        btnDel.onclick = () => {
            if (confirm(`Delete domain ${d} and all associated files?`)) {
                sendReq({ req: 'delete_domain', domain: d });
            }
        };
        tdAct.appendChild(btnDel);

        tr.appendChild(tdName);
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
    });
}

function selectDomain(domain) {
    currentDomain = domain;
    document.querySelector('#detail-title span').textContent = domain;
    document.getElementById('detail-panel').classList.remove('hidden-panel');

    const rows = document.querySelectorAll('#table-domains tbody tr');
    rows.forEach(r => {
        r.classList.remove('active');
        if (r.cells[0].textContent === domain) r.classList.add('active');
    });

    sendReq({ req: 'get_tls', domain: domain });
}

function closeDetail() {
    currentDomain = '';
    document.getElementById('detail-panel').classList.add('hidden-panel');
}

function renderTls(tlsList) {
    const tbody = document.querySelector('#table-tls tbody');
    tbody.innerHTML = '';

    if (!tlsList.length) {
        tbody.innerHTML = '<tr><td colspan="2" class="loading">No TLS configs found.</td></tr>';
        return;
    }

    tlsList.forEach(t => {
        const subdomain = t.replace('.json', '');
        const tr = document.createElement('tr');

        const tdName = document.createElement('td');
        tdName.textContent = subdomain;

        const tdAct = document.createElement('td');
        const btnDel = document.createElement('button');
        btnDel.className = 'btn btn-sm danger';
        btnDel.textContent = 'Delete';
        btnDel.onclick = () => {
            if (confirm(`Delete TLS configuration for ${subdomain}?`)) {
                sendReq({ req: 'delete_tls', domain: currentDomain, subdomain: subdomain });
            }
        };
        tdAct.appendChild(btnDel);

        tr.appendChild(tdName);
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
    });
}

/* Modal UX */
function openModal(id) {
    document.getElementById(id).classList.add('show');
}
function closeModal(id) {
    document.getElementById(id).classList.remove('show');
}

/* Event Listeners */
document.addEventListener('DOMContentLoaded', () => {
    connect();

    document.getElementById('btn-add-domain').onclick = () => {
        document.getElementById('input-new-domain').value = '';
        openModal('modal-new-domain');
    };

    document.getElementById('input-new-domain').oninput = (e) => {
        document.getElementById('btn-nd-save').disabled = !e.target.value.trim();
    };

    document.getElementById('btn-nd-cancel').onclick = () => closeModal('modal-new-domain');
    document.getElementById('btn-nd-save').onclick = () => {
        const domain = document.getElementById('input-new-domain').value.trim();
        if (domain) {
            sendReq({ req: 'create_domain', domain: domain });
        }
    };

    document.getElementById('btn-edit-zone').onclick = () => {
        if (!currentDomain) return;
        document.getElementById('zone-domain-name').textContent = currentDomain;
        sendReq({ req: 'get_zone', domain: currentDomain });
    };

    document.getElementById('btn-zone-cancel').onclick = () => closeModal('modal-zone');
    document.getElementById('btn-zone-save').onclick = () => {
        const buf = document.getElementById('zone-editor').value;
        sendReq({ req: 'update_zone', domain: currentDomain, zone: buf });
    };

    document.getElementById('btn-add-tls').onclick = () => {
        if (!currentDomain) return;
        document.getElementById('tls-domain-name').textContent = currentDomain;
        document.getElementById('input-tls-subdomain').value = '';
        document.getElementById('input-tls-email').value = '';
        document.getElementById('input-tls-org').value = '';
        document.getElementById('input-tls-dir').value = 'https://acme-v02.api.letsencrypt.org/directory';
        checkTlsForm();
        openModal('modal-new-tls');
    };

    const checkTlsForm = () => {
        const sd = document.getElementById('input-tls-subdomain').value.trim();
        const em = document.getElementById('input-tls-email').value.trim();
        const org = document.getElementById('input-tls-org').value.trim();
        const dir = document.getElementById('input-tls-dir').value.trim();
        document.getElementById('btn-nt-save').disabled = !(sd && em && org && dir);
    };

    document.querySelectorAll('#modal-new-tls input').forEach(el => el.oninput = checkTlsForm);

    document.getElementById('btn-nt-cancel').onclick = () => closeModal('modal-new-tls');
    document.getElementById('btn-nt-save').onclick = () => {
        sendReq({
            req: 'create_tls',
            domain: currentDomain,
            subdomain: document.getElementById('input-tls-subdomain').value.trim(),
            email: document.getElementById('input-tls-email').value.trim(),
            organization: document.getElementById('input-tls-org').value.trim(),
            directory_url: document.getElementById('input-tls-dir').value.trim()
        });
    };
});
