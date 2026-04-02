const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
let ws;
let currentEditUid = null;

function connect() {
    ws = new WebSocket(`${protocol}//${window.location.host}${window.location.pathname}`, 'lws-auth-server');

    ws.onopen = () => { 
        ws.send(JSON.stringify({ op: 'list' })); 
        ws.send(JSON.stringify({ op: 'clients_list' })); 
    };
    ws.onmessage = (msg) => {
        const data = JSON.parse(msg.data);
        if (data.op === 'list_reply') renderTable(data.users);
        else if (data.op === 'clients_list_reply') renderClientsTable(data.clients);
    };
    ws.onclose = () => { setTimeout(connect, 2000); };
}

let isClientCreate = false;

function renderClientsTable(clients) {
    const tbody = document.querySelector('#clientsTable tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    clients.forEach(c => {
        tbody.innerHTML += `
            <tr>
                <td><b>${c.client_id}</b></td>
                <td>${c.name}</td>
                <td style="word-break: break-all; font-size: 0.9em;"><code>${c.redirect_uris}</code></td>
                <td>
                    <button class="editClientBtn" data-cid="${c.client_id}" data-name="${c.name}" data-redirects="${c.redirect_uris}">Edit</button>
                    <button class="danger deleteClientBtn" data-cid="${c.client_id}">Delete</button>
                </td>
            </tr>
        `;
    });

    document.querySelectorAll('.editClientBtn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.getElementById('cmId').value = e.target.getAttribute('data-cid');
            document.getElementById('cmId').disabled = true;
            document.getElementById('cmName').value = e.target.getAttribute('data-name');
            document.getElementById('cmRedirects').value = e.target.getAttribute('data-redirects');
            
            isClientCreate = false;
            document.getElementById('cmTitle').innerText = 'Edit Grant';
            document.getElementById('clientModal').classList.add('flex');
        });
    });

    document.querySelectorAll('.deleteClientBtn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const cid = e.target.getAttribute('data-cid');
            if (confirm(`Are you sure you want to delete grant_id '${cid}'?`)) {
                ws.send(JSON.stringify({ op: 'client_delete', client_id: cid }));
            }
        });
    });
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
    document.getElementById('modal').style.display = 'flex'; // Pre-existing, kept for safety unless fixing entirely
}

function saveEdit() {
    const grants = document.getElementById('grantsInput').value.trim();
    ws.send(JSON.stringify({ op: 'edit', uid: currentEditUid, grants }));
    closeModal();
}

function closeModal() {
    document.getElementById('modal').style.display = 'none'; // Pre-existing
    currentEditUid = null;
}

window.onload = () => {
    connect();

    document.getElementById('tabUsers').addEventListener('click', (e) => {
        e.target.className = 'tab-active';
        document.getElementById('tabClients').className = 'tab-inactive';
        document.getElementById('usersView').classList.remove('hidden');
        document.getElementById('clientsView').classList.add('hidden');
    });

    document.getElementById('tabClients').addEventListener('click', (e) => {
        e.target.className = 'tab-active';
        document.getElementById('tabUsers').className = 'tab-inactive';
        document.getElementById('clientsView').classList.remove('hidden');
        document.getElementById('usersView').classList.add('hidden');
    });

    document.getElementById('addClientBtn').addEventListener('click', () => {
        document.getElementById('cmId').value = '';
        document.getElementById('cmId').disabled = false;
        document.getElementById('cmName').value = '';
        document.getElementById('cmRedirects').value = '';
        
        isClientCreate = true;
        document.getElementById('cmTitle').innerText = 'Add New Grant';
        document.getElementById('clientModal').classList.add('flex');
    });

    document.getElementById('cmSaveBtn').addEventListener('click', () => {
        const cid = document.getElementById('cmId').value.trim();
        const nm = document.getElementById('cmName').value.trim();
        const ru = document.getElementById('cmRedirects').value.trim();
        
        if (!cid) return alert('Grant ID is required');
        
        ws.send(JSON.stringify({ 
            op: isClientCreate ? 'client_create' : 'client_edit', 
            client_id: cid, 
            name: nm, 
            redirect_uris: ru 
        }));
        
        document.getElementById('clientModal').classList.remove('flex');
    });

    document.getElementById('cmCancelBtn').addEventListener('click', () => {
        document.getElementById('clientModal').classList.remove('flex');
    });

    document.getElementById('saveBtn').addEventListener('click', saveEdit);
    document.getElementById('cancelBtn').addEventListener('click', closeModal);
};
