const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
let ws;
let currentEditUid = null;

function connect() {
    ws = new WebSocket(`${protocol}//${window.location.host}${window.location.pathname}`, 'lws-auth-server');

    ws.onopen = () => { ws.send(JSON.stringify({ op: 'list' })); };
    ws.onmessage = (msg) => {
        const data = JSON.parse(msg.data);
        if (data.op === 'list_reply') renderTable(data.users);
    };
    ws.onclose = () => { setTimeout(connect, 2000); };
}

function renderTable(users) {
    const tbody = document.querySelector('#usersTable tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    users.forEach(u => {
        let grantsHtml = Object.keys(u.grants).map(k => {
            const cls = k === '*' ? 'badge star' : 'badge';
            return `<span class="${cls}">${k}:${u.grants[k]}</span>`;
        }).join('');

        const isGod = u.grants && u.grants['*'] !== undefined;
        const actionsHtml = isGod ?
            `<span style="color:var(--text-muted);font-style:italic;">Protected Administrator</span>` :
            `<button class="editBtn" data-uid="${u.uid}" data-grants='${JSON.stringify(u.grants)}'>Edit</button>
             <button class="danger deleteBtn" data-uid="${u.uid}" data-user="${u.user}">Delete</button>`;

        tbody.innerHTML += `
            <tr>
                <td>${u.uid}</td>
                <td><b>${u.user}</b></td>
                <td>${grantsHtml}</td>
                <td>${actionsHtml}</td>
            </tr>
        `;
    });

    document.querySelectorAll('.editBtn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const uid = e.target.getAttribute('data-uid');
            const grantsObj = JSON.parse(e.target.getAttribute('data-grants'));
            openEdit(uid, grantsObj);
        });
    });

    document.querySelectorAll('.deleteBtn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const uid = e.target.getAttribute('data-uid');
            const user = e.target.getAttribute('data-user');
            deleteUser(uid, user);
        });
    });
}

function deleteUser(uid, username) {
    if (confirm(`Are you sure you want to delete ${username}?`)) {
        ws.send(JSON.stringify({ op: 'delete', uid }));
    }
}

function openEdit(uid, grantsObj) {
    currentEditUid = uid;
    const str = Object.keys(grantsObj).map(k => `${k}:${grantsObj[k]}`).join(',');
    document.getElementById('grantsInput').value = str;
    document.getElementById('modal').style.display = 'flex';
}

function saveEdit() {
    const grants = document.getElementById('grantsInput').value.trim();
    ws.send(JSON.stringify({ op: 'edit', uid: currentEditUid, grants }));
    closeModal();
}

function closeModal() {
    document.getElementById('modal').style.display = 'none';
    currentEditUid = null;
}

window.onload = () => {
    connect();
    document.getElementById('saveBtn').addEventListener('click', saveEdit);
    document.getElementById('cancelBtn').addEventListener('click', closeModal);
};
