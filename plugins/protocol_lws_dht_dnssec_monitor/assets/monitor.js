let ws;
let currentDomain = '';
let currentZone = null;
let certCheckQueue = [];
let certCheckTimers = {};
let concurrentChecks = 0;
const MAX_CONCURRENT = 5;

function processCertQueue() {
    while (concurrentChecks < MAX_CONCURRENT && certCheckQueue.length > 0) {
        let task = certCheckQueue.shift();
        concurrentChecks++;
        let span = document.getElementById(`cert-status-${task.fqdn}`);
        if (span) span.innerText = 'Checking...';
        sendReq({ req: 'check_cert', domain: currentDomain, subdomain: task.fqdn, port: task.port });

        certCheckTimers[task.fqdn] = setTimeout(() => {
            let s = document.getElementById(`cert-status-${task.fqdn}`);
            if (s && s.innerText === 'Checking...') {
                s.innerText = 'Timeout';
                s.style.color = '#f87171';
            }
            if (certCheckTimers[task.fqdn]) delete certCheckTimers[task.fqdn];
            concurrentChecks = Math.max(0, concurrentChecks - 1);
            processCertQueue();
        }, 5000);
    }
}

function generateId() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

class ZoneFile {
    constructor(zoneText) {
        this.records = [];
        this.parse(zoneText || '');
    }

    parse(text) {
        const lines = text.split('\n');
        let currentRecord = null;
        let inMultiLine = false;

        for (let i = 0; i < lines.length; i++) {
            let line = lines[i];

            // If we are currently parsing a multi-line block (like SOA)
            if (inMultiLine) {
                currentRecord.raw += '\n' + line;
                if (line.includes(')')) {
                    inMultiLine = false;
                    this.parseMultiRecord(currentRecord);
                    this.records.push(currentRecord);
                    currentRecord = null;
                }
                continue;
            }

            // Empty lines or purely comments
            if (/^\s*$/.test(line) || /^\s*;/.test(line)) {
                this.records.push({ id: generateId(), type: 'comment', raw: line, lineIndex: i });
                continue;
            }

            // Macros like $TTL or $ORIGIN
            if (line.startsWith('$')) {
                this.records.push({ id: generateId(), type: 'macro', raw: line, lineIndex: i });
                continue;
            }

            // Check for multi-line start (usually SOA)
            if (line.includes('(')) {
                inMultiLine = true;
                currentRecord = { id: generateId(), type: 'SOA', raw: line, lineIndex: i };
                if (line.includes(')')) {
                    inMultiLine = false;
                    this.parseMultiRecord(currentRecord);
                    this.records.push(currentRecord);
                    currentRecord = null;
                }
                continue;
            }

            // Standard one-line Resource Record
            let rec = this.parseSingleRecord(line);
            rec.lineIndex = i;
            this.records.push(rec);
        }

        if (currentRecord) {
             this.parseMultiRecord(currentRecord);
             if (currentRecord.lineIndex === undefined) currentRecord.lineIndex = lines.length;
             this.records.push(currentRecord);
        }
    }

    parseMultiRecord(record) {
        let clean = record.raw.replace(/;.*$/gm, '').replace(/[\(\)]/g, ' ').trim();
        let tokens = clean.split(/\s+/);

        let soaIdx = tokens.indexOf('SOA');
        if (soaIdx !== -1) {
            record.parsed = {
                name: tokens[0],
                ttl: soaIdx > 2 && !isNaN(tokens[1]) ? tokens[1] : '',
                clazz: 'IN',
                mname: tokens[soaIdx + 1] || '',
                rname: tokens[soaIdx + 2] || '',
                serial: tokens[soaIdx + 3] || '',
                refresh: tokens[soaIdx + 4] || '',
                retry: tokens[soaIdx + 5] || '',
                expire: tokens[soaIdx + 6] || '',
                minimum: tokens[soaIdx + 7] || ''
            };
        }
    }

    parseSingleRecord(line) {
        let text = line;
        let cIdx = line.indexOf(';');
        let comment = '';
        if (cIdx !== -1) {
            text = line.substring(0, cIdx);
            comment = line.substring(cIdx);
        }

        let tokens = text.trim().split(/\s+/);
        let name;

        if (/^\s/.test(line)) {
            name = '@';
        } else {
            name = tokens.shift();
        }

        let ttl = '';
        if (/^\d+/.test(tokens[0])) {
            ttl = tokens.shift();
        }

        let clazz = 'IN';
        if (tokens[0] === 'IN' || tokens[0] === 'CH' || tokens[0] === 'HS') {
            clazz = tokens.shift();
        }

        let rtype = tokens.shift() || 'UNKNOWN';
        let value = tokens.join(' ');

        return {
            id: generateId(),
            type: rtype,
            raw: line,
            parsed: { name, ttl, clazz, type: rtype, value },
            comment
        };
    }

    updateRecord(id, parsedData) {
        let rec = this.records.find(r => r.id === id);
        if (!rec) return;

        if (parsedData.type === 'SOA') {
            rec.raw = `${parsedData.name || '@'} ${parsedData.ttl ? parsedData.ttl + ' ' : ''}IN SOA ${parsedData.mname} ${parsedData.rname} (\n` +
                      `\t\t\t\t${parsedData.serial}\n\t\t\t\t${parsedData.refresh}\n\t\t\t\t${parsedData.retry}\n\t\t\t\t${parsedData.expire}\n\t\t\t\t${parsedData.minimum} )`;
            rec.parsed = parsedData;
            rec.type = 'SOA';
        } else {
            let line = `${parsedData.name === '@' ? '@' : parsedData.name}\t${parsedData.ttl}\tIN\t${parsedData.type}\t${parsedData.value}`;
            if (rec.comment) line += `\t${rec.comment}`;
            rec.raw = line;
            rec.parsed = parsedData;
            rec.type = parsedData.type;
        }
    }

    addRecord(parsedData) {
        let line = '';
        if (parsedData.type === 'SOA') {
            line = `${parsedData.name || '@'} ${parsedData.ttl ? parsedData.ttl + ' ' : ''}IN SOA ${parsedData.mname} ${parsedData.rname} (\n` +
                   `\t\t\t\t${parsedData.serial}\n\t\t\t\t${parsedData.refresh}\n\t\t\t\t${parsedData.retry}\n\t\t\t\t${parsedData.expire}\n\t\t\t\t${parsedData.minimum} )`;
        } else {
            line = `${parsedData.name === '@' ? '@' : parsedData.name}\t${parsedData.ttl}\tIN\t${parsedData.type}\t${parsedData.value}`;
        }

        this.records.push({
            id: generateId(),
            type: parsedData.type,
            raw: line,
            parsed: parsedData,
            comment: ''
        });
    }

    deleteRecord(id) {
        this.records = this.records.filter(r => r.id !== id);
    }

    serialize() {
        return this.records.map(r => r.raw).join('\n');
    }
}

function connect() {
    const l = window.location;
    let wsUrl = (l.protocol === "https:" ? "wss://" : "ws://") + l.host;

    ws = new WebSocket(wsUrl, "lws-dht-dnssec-monitor");

    const statusBadge = document.getElementById('ws-status');

    ws.onopen = function() {
        statusBadge.textContent = 'Connected';
        statusBadge.className = 'status-badge connected';
        // The backend UDS proxy ring buffer drops overlapping packets if fired synchronously!
        // We must sequence the API bootstrap calls.
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
        case 'get_ipv6_suffix':
            window.ipv6_suffix = data.suffix || '';
            const inSuf = document.getElementById('input-ipv6-suffix');
            if (inSuf) inSuf.value = window.ipv6_suffix;
            if (window.last_extip_data) handleResponse({ status:'ok', req:'extip_update', data:window.last_extip_data });
            break;
        case 'set_ipv6_suffix':
            showToast('IPv6 suffix preference saved successfully');
            break;
        case 'extip_update':
            if (data.data && data.data['ext-ips']) {
                window.last_extip_data = data.data;
                const bdg = document.getElementById('extip-status');

                // data.data['ext-ips'] is an Array of strings, handle it properly!
                const ips = Array.isArray(data.data['ext-ips']) ? data.data['ext-ips'] : (data.data['ext-ips'] + '').split(',');
                let content = '';
                ips.forEach(ip => {
                    let type = ip.includes(':') ? 'Ext IPv6' : 'Ext IPv4';
                    if (type === 'Ext IPv6' && window.ipv6_suffix) {
                        let parts = ip.split(':');
                        if (parts.length > 2) {
                            parts.pop();
                            ip = parts.join(':') + ':' + window.ipv6_suffix;
                        }
                    }
                    content += `<div>${type}: ${ip}</div>`;
                });
                bdg.style.display = 'inline-block';
                bdg.innerHTML = content;
            }
            break;
        case 'get_domains':
            renderDomains(data.domains || []);
            // Bootstrap phase 2: now safe to fetch suffix config
            sendReq({ req: 'get_ipv6_suffix' });
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
            currentZone = new ZoneFile(data.zone || '');
            renderZoneTable();
            updateRawEditor();
            document.getElementById('record-editor')?.classList.add('hidden-panel');
            // Sequence getting TLS after getting Zone to avoid UDS packet drops
            sendReq({ req: 'get_tls', domain: currentDomain });
            break;
        case 'update_zone':
            showToast('Zonefile updated successfully');
            break;
        case 'get_tls':
            window.activeTls = data.tls || [];
            renderZoneTable();
            break;
        case 'create_tls':
        case 'delete_tls':
            showToast(data.req === 'create_tls' ? 'TLS collection enabled' : 'TLS collection disabled');
            // We don't fetch get_tls again because we update window.activeTls synchronously.
            break;
        case 'cert_status':
            let span = document.getElementById(`cert-status-${data.subdomain}`);
            if (certCheckTimers[data.subdomain]) {
                clearTimeout(certCheckTimers[data.subdomain]);
                delete certCheckTimers[data.subdomain];
                concurrentChecks = Math.max(0, concurrentChecks - 1);
            }
            if (span) {
                if (data.status === 'ok') {
                    span.innerText = data.msg;
                    span.style.color = '#34d399';
                } else {
                    span.innerText = data.msg;
                    span.style.color = '#f87171';
                }
            }
            processCertQueue();
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
    document.getElementById('detail-panel')?.classList.remove('hidden-panel');
    document.getElementById('domain-panel')?.classList.add('hidden-panel');
    document.getElementById('record-editor')?.classList.add('hidden-panel');

    const rows = document.querySelectorAll('#table-domains tbody tr');
    rows.forEach(r => {
        r.classList.remove('active');
        if (r.cells[0].textContent === domain) r.classList.add('active');
    });

    window.activeTls = [];
    sendReq({ req: 'get_zone', domain: domain });
}

function closeDetail() {
    currentDomain = '';
    document.getElementById('detail-panel').classList.add('hidden-panel');
    document.getElementById('domain-panel').classList.remove('hidden-panel');
}

function updateRawEditor() {
    document.getElementById('raw-zone-editor').value = currentZone ? currentZone.serialize() : '';
}

function renderZoneTable() {
    const tbody = document.querySelector('#table-zone tbody');
    tbody.innerHTML = '';

    if (!currentZone) return;

    certCheckQueue = [];
    Object.values(certCheckTimers).forEach(t => clearTimeout(t));
    certCheckTimers = {};
    concurrentChecks = 0;
    window.renderedTlsFqdns = new Set();
    const records = currentZone.records.filter(r => r.type !== 'comment' && r.type !== 'macro');

    if (records.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading">No records found.</td></tr>';
        return;
    }

    records.forEach(r => {
        const tr = document.createElement('tr');
        tr.classList.add('clickable-row');
        tr.dataset.id = r.id;
        tr.onclick = (e) => {
            if (e.target.tagName !== 'BUTTON') {
                openEditor(r.id);
            }
        };

        let nameStr = r.parsed?.name || '@';
        let typeStr = r.type;
        let ttlStr = r.parsed?.ttl || '-';
        let valStr = r.parsed?.value;

        if (r.type === 'SOA') {
            valStr = `Serial: ${r.parsed?.serial} (MNAME: ${r.parsed?.mname})`;
        }

        let fqdn = nameStr === '@' ? currentDomain : nameStr + '.' + currentDomain;
        let isTlsCapable = (r.type === 'A' || r.type === 'AAAA' || r.type === 'CNAME');
        let tlsTd = '<td class="ext-tls-cell">-</td>';

        if (isTlsCapable && !window.renderedTlsFqdns.has(fqdn)) {
            window.renderedTlsFqdns.add(fqdn);
            let activeConfig = window.activeTls ? window.activeTls.find(t => t.fqdn === fqdn) : null;
            let portVal = activeConfig ? activeConfig.port : '';
            tlsTd = `<td class="ext-tls-cell">
                         <div style="display:flex; align-items:center; justify-content:flex-start; gap: 0.5rem">
                             <input type="number" class="tls-port ext-port" data-fqdn="${fqdn}" value="${portVal}" maxlength="5" placeholder="Port" style="width:70px; background: rgba(0,0,0,0.2); color:#fff; border:1px solid #444; border-radius:4px; padding:2px;">
                             <span id="cert-status-${fqdn}" class="cert-status" style="font-size:0.8em; color:#aaa;"></span>
                         </div>
                     </td>`;
        }

        tr.innerHTML = `
            <td class="ext-mono">${nameStr}</td>
            <td>${ttlStr}</td>
            <td><span class="status-badge ext-badge">${typeStr}</span></td>
            <td class="ext-value">${valStr || '-'}</td>
            ${tlsTd}
        `;

        const portInput = tr.querySelector('.tls-port');
        if (portInput) {
            portInput.onclick = (e) => e.stopPropagation();
            portInput.onchange = (e) => {
                let p = e.target.value.trim();
                let pnum = parseInt(p, 10);
                if (!p || isNaN(pnum) || pnum <= 0 || pnum > 65535) {
                    sendReq({ req: 'delete_tls', domain: currentDomain, subdomain: fqdn });
                    if (window.activeTls) window.activeTls = window.activeTls.filter(x => x.fqdn !== fqdn);
                    document.getElementById(`cert-status-${fqdn}`).innerText = '';
                } else {
                    sendReq({ req: 'create_tls', domain: currentDomain, subdomain: fqdn, port: pnum });
                    if (!window.activeTls) window.activeTls = [];
                    let exist = window.activeTls.find(x => x.fqdn === fqdn);
                    if (exist) exist.port = pnum;
                    else window.activeTls.push({fqdn: fqdn, port: pnum});
                    
                    certCheckQueue.push({fqdn: fqdn, port: pnum});
                    processCertQueue();
                }
            };

            if (portInput.value) {
                let pnum = parseInt(portInput.value, 10);
                certCheckQueue.push({fqdn: fqdn, port: pnum});
            }
        }

        const tdAct = document.createElement('td');
        if (r.type !== 'SOA') {
            const btnDel = document.createElement('button');
            btnDel.className = 'btn btn-sm danger';
            btnDel.textContent = 'Delete';
            btnDel.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                if (confirm('Delete this record?')) {
                    currentZone.deleteRecord(r.id);
                    renderZoneTable();
                    updateRawEditor();
                    document.getElementById('record-editor')?.classList.add('hidden-panel');
                }
            };
            tdAct.appendChild(btnDel);
        }

        tr.appendChild(tdAct);
        tbody.appendChild(tr);
    });

    if (certCheckQueue.length > 0) processCertQueue();
}

let editingRecordId = null;

function renderFormFields(type, data) {
    const form = document.getElementById('editor-form');

    let common = `
        <div class="ext-grid-1">
            <div>
                <label>Name (e.g. @ or www)</label>
                <input type="text" id="edit-name" value="${data.name || ''}" placeholder="@">
            </div>
            <div>
                <label>TTL</label>
                <input type="text" id="edit-ttl" value="${data.ttl || ''}" placeholder="3600">
            </div>
        </div>
    `;

    if (type === 'SOA') {
        form.innerHTML = `
            ${common}
            <div class="ext-grid-2">
                <div><label>MNAME (Primary NS)</label><input type="text" id="edit-mname" value="${data.mname || ''}"></div>
                <div><label>RNAME (Admin Email)</label><input type="text" id="edit-rname" value="${data.rname || ''}"></div>
            </div>
            <div class="ext-grid-4">
                <div><label>Serial</label><input type="number" id="edit-serial" value="${data.serial || ''}"></div>
                <div><label>Refresh</label><input type="number" id="edit-refresh" value="${data.refresh || ''}"></div>
                <div><label>Retry</label><input type="number" id="edit-retry" value="${data.retry || ''}"></div>
                <div><label>Expire</label><input type="number" id="edit-expire" value="${data.expire || ''}"></div>
            </div>
            <div class="ext-mt">
                <label>Minimum TTL</label><input type="number" id="edit-minimum" value="${data.minimum || ''}">
            </div>
            <input type="hidden" id="edit-type" value="SOA">
        `;
    } else {
        let valueLabel = 'Value (Target IP or Data)';
        if (type === 'CNAME') valueLabel = 'Target Domain (CNAME)';
        if (type === 'TXT') valueLabel = 'Text Content';

        form.innerHTML = `
            ${common}
            <div class="ext-grid-select">
                <div>
                    <label>Record Type</label>
                    <select id="edit-type" class="ext-select">
                        <option value="A" ${type === 'A' ? 'selected' : ''}>A</option>
                        <option value="AAAA" ${type === 'AAAA' ? 'selected' : ''}>AAAA</option>
                        <option value="CNAME" ${type === 'CNAME' ? 'selected' : ''}>CNAME</option>
                        <option value="TXT" ${type === 'TXT' ? 'selected' : ''}>TXT</option>
                        <option value="MX" ${type === 'MX' ? 'selected' : ''}>MX</option>
                        <option value="NS" ${type === 'NS' ? 'selected' : ''}>NS</option>
                    </select>
                </div>
                <div>
                    <label>${valueLabel}</label>
                    <input type="text" id="edit-value" value="${data.value || ''}" placeholder="...">
                </div>
            </div>
        `;

        document.getElementById('edit-type').onchange = (e) => {
            const v = document.getElementById('edit-value');
            if (e.target.value === 'A') v.placeholder = '192.168.1.1';
            if (e.target.value === 'CNAME') v.placeholder = 'example.com.';
        };
    }
}

function openEditor(id) {
    editingRecordId = id;
    const editor = document.getElementById('record-editor');
    editor.classList.remove('hidden-panel');

    if (id) {
        const rec = currentZone.records.find(r => r.id === id);
        document.getElementById('editor-title').textContent = 'Edit Record';
        renderFormFields(rec.type, rec.parsed || {});
    } else {
        document.getElementById('editor-title').textContent = 'Add New Record';
        renderFormFields('A', { name: '@' });
    }
}

    document.addEventListener('DOMContentLoaded', () => {
    if (typeof window.renderLwsLoginStatus === 'function') {
        window.renderLwsLoginStatus('user-info');
    }
    connect();

    const rawEditor = document.getElementById('raw-zone-editor');
    rawEditor.addEventListener('input', (e) => {
        if (!currentDomain) return;
        currentZone = new ZoneFile(e.target.value);
        renderZoneTable();
        document.getElementById('record-editor')?.classList.add('hidden-panel');
        syncScroll(e.target);
    });

    const syncScroll = (target) => {
        if (!currentZone) return;
        let pos = target.selectionStart;
        if (pos === undefined) return;
        let lineNumber = target.value.substring(0, pos).split('\n').length - 1;
        
        let closestRec = null;
        for (let r of currentZone.records) {
            if (r.lineIndex !== undefined && r.lineIndex <= lineNumber) {
                if (!closestRec || r.lineIndex > closestRec.lineIndex) {
                    closestRec = r;
                }
            }
        }
        
        if (closestRec) {
            let row = document.querySelector(`#table-zone tr[data-id="${closestRec.id}"]`);
            if (row) {
                document.querySelectorAll('#table-zone tr').forEach(r => r.classList.remove('active'));
                row.classList.add('active');
                row.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }
    };

    ['keyup', 'click', 'focus'].forEach(evt => {
        rawEditor.addEventListener(evt, (e) => syncScroll(e.target));
    });

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

    document.getElementById('btn-back-domains').onclick = () => {
        closeDetail();
    };

    document.getElementById('btn-save-zonefile').onclick = () => {
        if (!currentDomain || !currentZone) return;

        let existingFqdns = new Set();
        currentZone.records.forEach(r => {
            if (r.type === 'comment' || r.type === 'macro' || r.type === 'SOA') return;
            let nameStr = r.parsed?.name || '@';
            let fqdn = nameStr === '@' ? currentDomain : nameStr + '.' + currentDomain;
            existingFqdns.add(fqdn);
        });

        if (window.activeTls) {
            window.activeTls.forEach(obj => {
                let fqdn = obj.fqdn;
                if (!existingFqdns.has(fqdn)) {
                    sendReq({ req: 'delete_tls', domain: currentDomain, subdomain: fqdn });
                }
            });
        }

        const serialized = currentZone.serialize();
        sendReq({ req: 'update_zone', domain: currentDomain, zone: serialized });
    };

    document.getElementById('btn-add-record').onclick = () => {
        openEditor(null);
    };

    document.getElementById('btn-cancel-edit').onclick = () => {
        document.getElementById('record-editor')?.classList.add('hidden-panel');
    };

    document.getElementById('btn-apply-record').onclick = () => {
        const type = document.getElementById('edit-type').value;
        const name = document.getElementById('edit-name').value.trim() || '@';
        const ttl = document.getElementById('edit-ttl').value.trim();

        let data = { type, name, ttl };

        if (type === 'SOA') {
            data.mname = document.getElementById('edit-mname').value.trim();
            data.rname = document.getElementById('edit-rname').value.trim();
            data.serial = document.getElementById('edit-serial').value.trim();
            data.refresh = document.getElementById('edit-refresh').value.trim();
            data.retry = document.getElementById('edit-retry').value.trim();
            data.expire = document.getElementById('edit-expire').value.trim();
            data.minimum = document.getElementById('edit-minimum').value.trim();
        } else {
            data.value = document.getElementById('edit-value').value.trim();
        }

        if (editingRecordId) {
            currentZone.updateRecord(editingRecordId, data);
        } else {
            currentZone.addRecord(data);
        }

        renderZoneTable();
        updateRawEditor();
        document.getElementById('record-editor')?.classList.add('hidden-panel');
    };

    const btnSaveSuffix = document.getElementById('btn-save-suffix');
    if (btnSaveSuffix) {
        btnSaveSuffix.onclick = () => {
            const val = document.getElementById('input-ipv6-suffix').value.trim();
            window.ipv6_suffix = val;
            sendReq({ req: 'set_ipv6_suffix', suffix: val });
            if (window.last_extip_data) handleResponse({ status:'ok', req:'extip_update', data:window.last_extip_data });
        };
    }
});

function openModal(id) {
    document.getElementById(id).classList.add('show');
}
function closeModal(id) {
    document.getElementById(id).classList.remove('show');
}
