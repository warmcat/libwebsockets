const DOM = {
    startBtn: document.getElementById('start-btn'),
    connStatus: document.getElementById('conn-status'),
    progressText: document.getElementById('progress-text'),
    progressBar: document.getElementById('overall-progress'),
    logContainer: document.getElementById('log')
};

const BLOB_SIZE = 4 * 1024 * 1024;
const HASH_SIZE = 32;
const TOTAL_SIZE = BLOB_SIZE + HASH_SIZE;
const TEST_ITERATIONS = 10;

let wt = null;

function log(msg, type = 'info') {
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    
    const time = document.createElement('span');
    time.className = 'log-time';
    const now = new Date();
    time.textContent = `[${now.toLocaleTimeString()}.${now.getMilliseconds().toString().padStart(3, '0')}]`;
    
    const text = document.createElement('span');
    text.textContent = msg;
    
    entry.appendChild(time);
    entry.appendChild(text);
    DOM.logContainer.appendChild(entry);
    DOM.logContainer.scrollTop = DOM.logContainer.scrollHeight;
}

function updateStatus(status, className) {
    DOM.connStatus.textContent = status;
    DOM.connStatus.className = `status-badge ${className}`;
}

function updateProgress(iter) {
    DOM.progressText.textContent = `${iter} / ${TEST_ITERATIONS} Iterations`;
    DOM.progressBar.style.width = `${(iter / TEST_ITERATIONS) * 100}%`;
}

function hexString(buffer) {
    const hashArray = Array.from(new Uint8Array(buffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateTestPayload() {
    log('Generating 4MB random payload...');
    const buffer = new Uint8Array(BLOB_SIZE);
    const maxRandomChunk = 65536;
    for (let offset = 0; offset < BLOB_SIZE; offset += maxRandomChunk) {
        const chunk = buffer.subarray(offset, offset + maxRandomChunk);
        crypto.getRandomValues(chunk);
    }
    
    log('Calculating SHA-256 hash...');
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = new Uint8Array(hashBuffer);
    
    log(`Generated Payload Hash: ${hexString(hashArray)}`);
    
    // Combine payload and hash
    const combined = new Uint8Array(TOTAL_SIZE);
    combined.set(buffer, 0);
    combined.set(hashArray, BLOB_SIZE);
    return combined;
}

async function sendStreamData(writer, data) {
    // Write in chunks to avoid blocking
    const chunkSize = 65536;
    for (let offset = 0; offset < data.length; offset += chunkSize) {
        const end = Math.min(offset + chunkSize, data.length);
        await writer.write(data.subarray(offset, end));
    }
}

let leftover = null;

async function receiveAndVerify(reader, expectedBytes) {
    const receivedData = new Uint8Array(expectedBytes);
    let bytesRead = 0;
    
    if (leftover && leftover.length > 0) {
        const copyLen = Math.min(leftover.length, expectedBytes - bytesRead);
        receivedData.set(leftover.subarray(0, copyLen), bytesRead);
        bytesRead += copyLen;
        if (copyLen < leftover.length) {
            leftover = leftover.subarray(copyLen);
        } else {
            leftover = null;
        }
    }
    
    while (bytesRead < expectedBytes) {
        const { value, done } = await reader.read();
        if (done) break;
        
        const copyLen = Math.min(value.length, expectedBytes - bytesRead);
        receivedData.set(value.subarray(0, copyLen), bytesRead);
        bytesRead += copyLen;
        
        if (copyLen < value.length) {
            leftover = value.subarray(copyLen);
        }
    }
    
    if (bytesRead < expectedBytes) {
        throw new Error(`Incomplete read. Expected ${expectedBytes}, got ${bytesRead}`);
    }
    
    const blob = receivedData.subarray(0, BLOB_SIZE);
    const expectedHash = receivedData.subarray(BLOB_SIZE, TOTAL_SIZE);
    
    const computedHashBuffer = await crypto.subtle.digest('SHA-256', blob);
    const computedHash = new Uint8Array(computedHashBuffer);
    
    const computedHex = hexString(computedHash);
    const expectedHex = hexString(expectedHash);
    
    if (computedHex === expectedHex) {
        log(`Server hash verified successfully: ${computedHex}`, 'success');
        return true;
    } else {
        throw new Error(`Hash mismatch! Expected: ${expectedHex}, Got: ${computedHex}`);
    }
}

async function startTest() {
    leftover = null;
    try {
        DOM.startBtn.disabled = true;
        updateStatus('Connecting...', 'connecting');
        updateProgress(0);
        DOM.logContainer.innerHTML = '';
        
        let url = "https://localhost:7681/";
        if (window.location.protocol.startsWith('http')) {
            const base = new URL('../', window.location.href).href;
            url = base.replace(/^http:/, 'https:');
        }
        
        log(`Connecting to WebTransport at ${url}`);
        wt = new WebTransport(url, {
            protocols: ['webtransport-test']
        });
        
        await wt.ready;
        updateStatus('Connected', 'connected');
        log('WebTransport Session Established', 'success');
        
        log('Opening Bidirectional Stream...');
        const stream = await wt.createBidirectionalStream();
        log('Stream established. Starting transmission loop.');
        
        const writer = stream.writable.getWriter();
        const reader = stream.readable.getReader();
        
        for (let i = 0; i < TEST_ITERATIONS; i++) {
            log(`--- Iteration ${i + 1} / ${TEST_ITERATIONS} ---`, 'info');
            
            // 1. Generate new payload + hash
            const payload = await generateTestPayload();
            
            // 2. Send payload & Wait for response simultaneously
            log('Starting concurrent send and receive...');
            
            const sendPromise = sendStreamData(writer, payload)
                .then(() => log(`Sent 4MB blob ${i + 1}`, 'info'));
                
            const receivePromise = receiveAndVerify(reader, TOTAL_SIZE)
                .then(() => log(`Received and verified blob ${i + 1}`, 'success'));
                
            await Promise.all([sendPromise, receivePromise]);
            
            updateProgress(i + 1);
        }
        
        log('Test Completed Successfully!', 'success');
        await writer.close();
        wt.close();
        updateStatus('Disconnected', 'disconnected');
        
    } catch (err) {
        log(`Error: ${err.message}`, 'error');
        updateStatus('Error', 'disconnected');
        if (wt) {
            wt.close();
            wt = null;
        }
    } finally {
        DOM.startBtn.disabled = false;
    }
}

DOM.startBtn.addEventListener('click', startTest);
