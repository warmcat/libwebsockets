let ws;
let currentDomain = '';
let currentDomainObj = null;
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
                s.classList.remove('text-green', 'text-gray'); s.classList.add('text-red');
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
        console.log('[INSTRUMENT] WS onopen: Connection established.');
        statusBadge.classList.add('hide'); statusBadge.classList.remove('show-inline', 'show-flex');
        document.getElementById('reconnect-overlay').classList.add('hide'); document.getElementById('reconnect-overlay').classList.remove('show-inline', 'show-flex');
        document.body.classList.remove('is-disconnected');
        // The backend UDS proxy ring buffer drops overlapping packets if fired synchronously!
        // We must sequence the API bootstrap calls.
        console.log('[INSTRUMENT] WS onopen: Bootstrapping with get_domains...');
        sendReq({ req: 'get_domains' });
    };

    ws.onmessage = function(msg) {
        console.log('[INSTRUMENT] WS onmessage: Raw payload: ', msg.data);
        try {
            const data = JSON.parse(msg.data);
            console.log('[INSTRUMENT] WS onmessage: Parsed data: ', data);
            handleResponse(data);
        } catch(e) {
            console.error('[INSTRUMENT] Failed to parse WS msg:', e);
            console.log('[INSTRUMENT] Raw message fragment/broken:', msg.data);
        }
    };

    ws.onclose = function() {
        console.warn('[INSTRUMENT] WS onclose: Connection closed or bounced. Retrying in 3000ms...');
        statusBadge.classList.remove('hide'); statusBadge.classList.add('show-inline');
        statusBadge.textContent = 'Disconnected';
        statusBadge.className = 'status-badge disconnected show-inline';
        document.getElementById('reconnect-overlay').classList.remove('hide'); document.getElementById('reconnect-overlay').classList.add('show-flex');
        document.body.classList.add('is-disconnected');
        setTimeout(connect, 3000);
    };
}

window.activeTls = [];
window.certStatusCache = {};

function sendReq(obj) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        console.log('[INSTRUMENT] sendReq: Dispatching payload -> ', obj);
        ws.send(JSON.stringify(obj));
    } else {
        console.log('[INSTRUMENT] sendReq: Failed because WS is not OPEN (ready state: ' + (ws ? ws.readyState : 'null') + ') -> ', obj);
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
                bdg.classList.remove('hide'); bdg.classList.add('show-inline');
                bdg.innerHTML = content;
            }
            break;
        case 'get_domains':
            window.domainsCache = data.domains || [];
            renderDomains(window.domainsCache);
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
            window.certStatusCache[data.subdomain + ':' + data.port] = data;
            let span = document.getElementById(`cert-status-${data.subdomain}`);
            if (certCheckTimers[data.subdomain]) {
                clearTimeout(certCheckTimers[data.subdomain]);
                delete certCheckTimers[data.subdomain];
                concurrentChecks = Math.max(0, concurrentChecks - 1);
            }
            if (span) {
                if (data.status === 'ok') {
                    span.innerText = data.msg;
                    span.classList.remove('text-red', 'text-gray'); span.classList.add('text-green');
                } else {
                    span.innerText = data.msg;
                    span.classList.remove('text-green', 'text-gray'); span.classList.add('text-red');
                }
            }
            processCertQueue();
            break;
    }
}

function renderDomains(domains) {
    const tbody = document.querySelector('#table-domains tbody');
    tbody.innerHTML = '';
    
    console.log('Rendering domains:', domains);

    if (!domains.length) {
        tbody.innerHTML = '<tr><td colspan="3" class="loading">No domains found. Add one to begin.</td></tr>';
        return;
    }

    domains.forEach(d => {
        const name = d.name || d;
        const expiry = d.whois ? d.whois.expiry_date : 0;
        
        const tr = document.createElement('tr');
        if (name === currentDomain) tr.classList.add('active');

        const tdName = document.createElement('td');
        const a = document.createElement('a');
        a.href = '#';
        a.textContent = name;
        a.onclick = (e) => {
            e.preventDefault();
            selectDomain(name);
        };
        tdName.appendChild(a);

        const tdExpiry = document.createElement('td');
        tdExpiry.className = 'expiry-column';
        tdExpiry.innerHTML = formatExpiry(expiry);

        const tdAct = document.createElement('td');
        const btnDel = document.createElement('button');
        btnDel.className = 'btn btn-sm danger';
        btnDel.textContent = 'Delete';
        btnDel.onclick = () => {
            if (confirm(`Delete domain ${name} and all associated files?`)) {
                sendReq({ req: 'delete_domain', domain: name });
            }
        };
        tdAct.appendChild(btnDel);

        tr.appendChild(tdName);
        tr.appendChild(tdExpiry);
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
    });
}

function formatExpiry(unixtime) {
    if (!unixtime) return '---';
    const now = Math.floor(Date.now() / 1000);
    const diff = unixtime - now;
    const totalDays = Math.floor(diff / 86400);
    
    if (totalDays < 0) return '<span class="expiry-critical">Expired</span>';
    
    let str = "";
    let d = totalDays;
    if (d >= 365) {
        str += Math.floor(d / 365) + "y";
        d = d % 365;
    }
    if (d >= 30) {
        let m = Math.floor(d / 30);
        if (m > 0 && str.length < 5) str += m + "mo";
        d = d % 30;
    }
    if (d >= 7 && !str) {
        str += Math.floor(d / 7) + "w";
        d = d % 7;
        if (d > 0) str += d + "d";
    } else if (d > 0 || !str) {
        if (!str || str.indexOf("mo") === -1) str += d + "d";
    }
    
    if (totalDays < 30) return `<span class="expiry-critical">${str}</span>`;
    if (totalDays < 90) return `<span class="expiry-soon">${str}</span>`;
    return str;
}

function selectDomain(domain) {
    currentDomain = domain;
    currentDomainObj = window.domainsCache ? window.domainsCache.find(d => d.name === domain) : null;
    
    document.querySelector('#detail-title span').textContent = domain;
    document.getElementById('detail-panel')?.classList.remove('hidden-panel');
    document.getElementById('domain-panel')?.classList.add('hidden-panel');
    document.getElementById('record-editor')?.classList.add('hidden-panel');

    const rows = document.querySelectorAll('#table-domains tbody tr');
    rows.forEach(r => {
        r.classList.remove('active');
        if (r.cells[0].textContent === domain) r.classList.add('active');
    });

    renderWhoisHeader();
    window.activeTls = [];
    sendReq({ req: 'get_zone', domain: domain });
}

function renderWhoisHeader() {
    const hdr = document.getElementById('whois-header');
    if (!hdr) return;
    
    if (!currentDomainObj || !currentDomainObj.whois) {
        hdr.innerHTML = '<div class="loading">No WHOIS data available</div>';
        return;
    }
    
    const w = currentDomainObj.whois;
    const expiryDate = w.expiry_date ? new Date(w.expiry_date * 1000).toLocaleDateString() : 'Unknown';
    const nsList = (w.nameservers || []).join('<br>') || 'None';
    
    let dsStatus = '';
    if (w.ds_data) {
        const localDs = (currentDomainObj.local_ds || '').trim().toUpperCase();
        const whoisDs = w.ds_data.trim().toUpperCase();
        
        let isMatch = false;
        if (localDs && whoisDs) {
            /* WHOIS DS might contain key ID and other info, we check if local DS is a substring or vice versa */
            isMatch = whoisDs.includes(localDs) || localDs.includes(whoisDs);
        }
        
        dsStatus = `
            <div class="whois-item">
                <span class="whois-label">DNSSEC Match</span>
                <span class="status-match ${isMatch ? 'ok' : 'fail'}">
                    <span class="status-match-icon">${isMatch ? '✔' : '✘'}</span>
                    <span class="whois-value">${isMatch ? 'Matches' : 'Mismatch'}</span>
                    <div class="tooltip">Expected DS:\n${localDs || 'Unknown'}\n\nWHOIS DS:\n${whoisDs}</div>
                </span>
            </div>
        `;
    } else {
        let isSigned = false;
        let dnssecVal = w.dnssec ? w.dnssec.trim().toLowerCase() : '';
        if (dnssecVal === 'signeddelegation' || dnssecVal === 'yes' || dnssecVal === 'signed' || dnssecVal === 'active') {
            isSigned = true;
        }
        
        let statusClass = isSigned ? 'ok' : 'warn';
        let statusIcon = isSigned ? '✔' : '⚠';
        let statusText = w.dnssec || 'Unsigned';
        let tooltipText = isSigned ? 
            'Delegation is actively signed according to WHOIS.\\n(DS hash not provided by registry)' : 
            'No DS records found in WHOIS.\\nDelegate signing if this is incorrect.';

        dsStatus = `
            <div class="whois-item">
                <span class="whois-label">DNSSEC Status</span>
                <span class="status-match ${statusClass}">
                    <span class="status-match-icon">${statusIcon}</span>
                    <span class="whois-value">${statusText}</span>
                    <div class="tooltip">${tooltipText}</div>
                </span>
            </div>
        `;
    }

    hdr.innerHTML = `
        <div class="whois-item">
            <span class="whois-label">Expiry</span>
            <span class="whois-value">${expiryDate}</span>
        </div>
        <div class="whois-item">
            <span class="whois-label">Name Servers</span>
            <span class="whois-value">${nsList}</span>
        </div>
        ${dsStatus}
    `;
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
            let cacheKey = fqdn + ':' + portVal;
            let cached = window.certStatusCache[cacheKey];
            let initStatus = '';
            let initColorClass = 'text-gray';
            if (cached) {
                initStatus = cached.msg;
                initColorClass = (cached.status === 'ok') ? 'text-green' : 'text-red';
            } else if (certCheckTimers[fqdn]) {
                initStatus = 'Checking...';
            }

            tlsTd = `<td class="ext-tls-cell">
                         <div class="tls-port-wrapper">
                             <input type="number" class="tls-port ext-port tls-port-input" data-fqdn="${fqdn}" value="${portVal}" maxlength="5" placeholder="Port">
                             <br>
                             <span id="cert-status-${fqdn}" class="cert-status tls-cert-status ${initColorClass}">${initStatus}</span>
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
                    Object.keys(window.certStatusCache).forEach(k => {
                        if (k.startsWith(fqdn + ':')) delete window.certStatusCache[k];
                    });
                } else {
                    sendReq({ req: 'create_tls', domain: currentDomain, subdomain: fqdn, port: pnum });
                    if (!window.activeTls) window.activeTls = [];
                    let exist = window.activeTls.find(x => x.fqdn === fqdn);
                    if (exist) exist.port = pnum;
                    else window.activeTls.push({fqdn: fqdn, port: pnum});

                    if (certCheckTimers[fqdn]) {
                        clearTimeout(certCheckTimers[fqdn]);
                        delete certCheckTimers[fqdn];
                        concurrentChecks = Math.max(0, concurrentChecks - 1);
                    }
                    delete window.certStatusCache[fqdn + ':' + pnum];
                    certCheckQueue.push({fqdn: fqdn, port: pnum});
                    processCertQueue();
                }
            };

            if (portInput.value) {
                let pnum = parseInt(portInput.value, 10);
                if (!window.certStatusCache[fqdn + ':' + pnum] && !certCheckTimers[fqdn]) {
                    certCheckQueue.push({fqdn: fqdn, port: pnum});
                }
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
