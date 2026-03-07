let ws;
const statusEl = document.getElementById('status');
const peersVal = document.getElementById('peers-val');
const txVal = document.getElementById('tx-val');
const rxVal = document.getElementById('rx-val');
const dropVal = document.getElementById('drop-val');
const statsBody = document.getElementById('stats-current-body');

const canvas = document.getElementById('dhtChart');
const ctx = canvas.getContext('2d');

let chartData = Array(60).fill(null).map(() => ({ tx: 0, rx: 0, drop: 0 }));
let maxEvents = 10;
let lastStats = null;

function resizeCanvas() {
    let p = canvas.parentElement;
    let s = window.getComputedStyle(p);
    canvas.width = p.clientWidth - parseFloat(s.paddingLeft) - parseFloat(s.paddingRight);
    canvas.height = Math.max(250, p.clientHeight - 60);
}
window.addEventListener('resize', resizeCanvas);
resizeCanvas();

function sumObj(obj) {
    if (!obj) return 0;
    return Object.values(obj).reduce((a, b) => a + b, 0);
}

function connect() {
    const l = window.location;
    const wsUrl = `${l.protocol === 'https:' ? 'wss' : 'ws'}://${l.host}${l.pathname}`;
    ws = new WebSocket(wsUrl, 'lws-dht-stats');

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
            if (data && data.stats_current) {
                const c = data.stats_current;
                
                // Update top metrics
                let totalTx = sumObj(c.tx);
                let totalRx = sumObj(c.rx) - (c.rx.drops || 0); // exclude drops from rx sum
                let drops = c.rx.drops || 0;

                peersVal.textContent = c.peer_count || 0;
                txVal.textContent = totalTx;
                rxVal.textContent = totalRx;
                dropVal.textContent = drops;

                // Render table
                statsBody.innerHTML = '';
                const keys = ['ping', 'pong', 'find_node', 'get_peers', 'announce_peer', 'put', 'get'];
                keys.forEach(k => {
                    const tr = document.createElement('tr');
                    const tdName = document.createElement('td');
                    tdName.textContent = k;
                    const tdTx = document.createElement('td');
                    tdTx.textContent = c.tx[k] || 0;
                    const tdRx = document.createElement('td');
                    tdRx.textContent = c.rx[k] || 0;
                    
                    tr.appendChild(tdName);
                    tr.appendChild(tdTx);
                    tr.appendChild(tdRx);
                    statsBody.appendChild(tr);
                });

                // Calculate deltas for chart
                let dTx = 0, dRx = 0, dDrop = 0;
                if (lastStats) {
                    let lastTotalTx = sumObj(lastStats.tx);
                    let lastTotalRx = sumObj(lastStats.rx) - (lastStats.rx.drops || 0);
                    let lastDrops = lastStats.rx.drops || 0;

                    if (totalTx >= lastTotalTx) dTx = totalTx - lastTotalTx;
                    else dTx = totalTx; // bucket rotated

                    if (totalRx >= lastTotalRx) dRx = totalRx - lastTotalRx;
                    else dRx = totalRx;

                    if (drops >= lastDrops) dDrop = drops - lastDrops;
                    else dDrop = drops;
                }
                
                lastStats = c;

                // Push to chart
                chartData.shift();
                chartData.push({ tx: dTx, rx: dRx, drop: dDrop });

                maxEvents = 10;
                chartData.forEach(s => {
                    if (s) {
                        let total = s.tx + s.rx + s.drop;
                        if (total > maxEvents) maxEvents = total;
                    }
                });

                drawChart();
            }
        } catch (err) {
            console.error(err);
        }
    };
}

function drawChart() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const barW = canvas.width / chartData.length;

    for (let i = 0; i < chartData.length; i++) {
        let s = chartData[i];
        if (!s) continue;

        let x = i * barW;
        
        let txH = (s.tx / maxEvents) * canvas.height;
        let rxH = (s.rx / maxEvents) * canvas.height;
        let dropH = (s.drop / maxEvents) * canvas.height;

        // TX (Blue)
        ctx.fillStyle = '#2196F3';
        ctx.fillRect(x, canvas.height - txH, barW - 1, txH);

        // RX (Green)
        ctx.fillStyle = '#4CAF50';
        ctx.fillRect(x, canvas.height - txH - rxH, barW - 1, rxH);

        // Drops (Red)
        ctx.fillStyle = '#f44336';
        ctx.fillRect(x, canvas.height - txH - rxH - dropH, barW - 1, dropH);
    }

    // Draw axis labels
    ctx.fillStyle = '#aaaaaa';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(`${maxEvents} pkts/s`, canvas.width - 5, 15);
}

connect();
