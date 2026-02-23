let ws;
const statusEl = document.getElementById('status');
const sleepVal = document.getElementById('sleep-val');
const worstLatVal = document.getElementById('worst-lat-val');
const eventsVal = document.getElementById('events-val');
const canvas = document.getElementById('latencyChart');
const ctx = canvas.getContext('2d');

let chartSecs = Array(60).fill(null).map(() => ({ sleep: 0, active: 0, events: 0, worst: 0 }));
let maxEvents = 2000;
let worstLatencies = []; // Table of worst latencies seen

let currentSecond = 0;
let secondData = { active: 0, events: 0, worst: 0 };

function resizeCanvas() {
    let p = canvas.parentElement;
    let s = window.getComputedStyle(p);
    canvas.width = p.clientWidth - parseFloat(s.paddingLeft) - parseFloat(s.paddingRight);
    canvas.height = p.clientHeight - parseFloat(s.paddingTop) - parseFloat(s.paddingBottom);
}
window.addEventListener('resize', resizeCanvas);
resizeCanvas();

function connect() {
    const l = window.location;
    const wsUrl = `${l.protocol === 'https:' ? 'wss' : 'ws'}://${l.host}${l.pathname}`;
    ws = new WebSocket(wsUrl, 'lws-latency');

    ws.onopen = () => {
        statusEl.textContent = 'Connected';
        statusEl.className = 'status connected';
    };

    ws.onclose = () => {
        statusEl.textContent = 'Disconnected';
        statusEl.className = 'status disconnected';
        setTimeout(connect, 2000);
    };

    ws.onmessage = (e) => {
        try {
            const data = JSON.parse(e.data);
            if (data.buckets && data.buckets.length > 0) {
                data.buckets.forEach(b => {
                    let sec = Math.floor(b.start / 1000000);

                    // Keep a table of worst latencies in memory
                    if (b.wrst > 0) {
                        let exists = worstLatencies.find(w => w.time === b.start);
                        if (!exists) {
                            worstLatencies.push({time: b.start, worst: b.wrst, proto: b.proto, ts: b.ts});
                            worstLatencies.sort((a, b) => b.worst - a.worst);
                            if (worstLatencies.length > 50) worstLatencies.pop();
                        }
                    }

                    if (sec !== currentSecond) {
                        if (currentSecond !== 0) {
                            chartSecs.shift();
                            let sleepTime = Math.max(0, 1000000 - secondData.active);
                            chartSecs.push({...secondData, sleep: sleepTime});

                            maxEvents = 2000;
                            chartSecs.forEach(s => {
                                if (s && s.events > maxEvents) {
                                    maxEvents = s.events;
                                }
                            });

                            // Update UI text for the completed second
                            sleepVal.textContent = `${(sleepTime / 1000).toFixed(1)}ms`;
                            if (secondData.worst > 1000) {
                                worstLatVal.textContent = `${(secondData.worst / 1000).toFixed(1)}ms`;
                            } else {
                                worstLatVal.textContent = `${secondData.worst}us`;
                            }
                            eventsVal.textContent = `${secondData.events}`;
                        }
                        currentSecond = sec;
                        secondData = { active: 0, events: 0, worst: 0 };
                    }

                    secondData.active += b.lat;
                    secondData.events += b.ev;
                    if (b.wrst > secondData.worst) {
                        secondData.worst = b.wrst;
                    }
                });

                drawChart();
                renderTable();
            }
        } catch (err) {
            console.error(err);
        }
    };
}

function drawChart() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const maxUs = 1000000; // 1 second
    const barW = canvas.width / chartSecs.length;

    // Draw stacked bars for sleep and active
    for (let i = 0; i < chartSecs.length; i++) {
        let s = chartSecs[i];
        if (!s) continue;

        let x = i * barW;
        let sleepH = (s.sleep / maxUs) * canvas.height;
        let activeH = (s.active / maxUs) * canvas.height;

        // Active time at bottom (red)
        ctx.fillStyle = '#f44336';
        ctx.fillRect(x, canvas.height - activeH, barW - 1, activeH);

        // Sleep time on top of active (green)
        ctx.fillStyle = '#4CAF50';
        ctx.fillRect(x, canvas.height - activeH - sleepH, barW - 1, sleepH);
    }

    // Draw events line (blue)
    ctx.beginPath();
    let first = true;
    for (let i = 0; i < chartSecs.length; i++) {
        let s = chartSecs[i];
        let x = i * barW + barW / 2;
        let y = canvas.height;
        if (s) {
            y = canvas.height - (s.events / maxEvents) * canvas.height;
        }
        if (first) {
            ctx.moveTo(x, y);
            first = false;
        } else {
            ctx.lineTo(x, y);
        }
    }
    ctx.strokeStyle = '#2196F3';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Draw axis labels
    ctx.fillStyle = '#000000';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(`${maxEvents} ev/s`, canvas.width - 5, 15);

    ctx.textAlign = 'left';
    ctx.fillText(`1.0s`, 5, 15);
}

function renderTable() {
    const tbody = document.getElementById('worst-latencies-body');
    if (!tbody) return;

    tbody.innerHTML = '';
    worstLatencies.forEach(lat => {
        const tr = document.createElement('tr');

        const tdTime = document.createElement('td');
        let tsStr = lat.ts || "-";
        let braceIdx = tsStr.indexOf(']');
        if (braceIdx > 0) {
            tsStr = tsStr.substring(0, braceIdx + 1);
        }
        tdTime.textContent = tsStr;

        const tdWorst = document.createElement('td');
        if (lat.worst > 1000) {
            tdWorst.textContent = (lat.worst / 1000).toFixed(1) + 'ms';
        } else {
            tdWorst.textContent = lat.worst + 'us';
        }

        const tdProtocol = document.createElement('td');
        tdProtocol.textContent = lat.proto || '-';

        tr.appendChild(tdTime);
        tr.appendChild(tdWorst);
        tr.appendChild(tdProtocol);

        tbody.appendChild(tr);
    });
}

connect();
