const DOM = {
    urlInput: document.getElementById('server-url'),
    hashInput: document.getElementById('cert-hash'),
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

function parseHash(hashStr) {
    const cleaned = hashStr.replace(/[:\s]/g, '');
    const bytes = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < cleaned.length; i += 2) {
        bytes[i / 2] = parseInt(cleaned.substring(i, i + 2), 16);
    }
    return bytes;
}

async function generateTestPayload() {
    log('Generating 4MB random payload...');
    const buffer = new Uint8Array(BLOB_SIZE);
    crypto.getRandomValues(buffer); // Generates 4MB of PRNG
    
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

async function receiveAndVerify(reader, expectedBytes) {
    const receivedData = new Uint8Array(expectedBytes);
    let bytesRead = 0;
    
    while (bytesRead < expectedBytes) {
        const { value, done } = await reader.read();
        if (done) break;
        
        receivedData.set(value, bytesRead);
        bytesRead += value.length;
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
    try {
        DOM.startBtn.disabled = true;
        updateStatus('Connecting...', 'connecting');
        updateProgress(0);
        DOM.logContainer.innerHTML = '';
        
        const url = DOM.urlInput.value;
        const certHashStr = DOM.hashInput.value.trim();
        
        const options = {};
        if (certHashStr) {
            try {
                const bytes = parseHash(certHashStr);
                options.serverCertificateHashes = [{
                    algorithm: "sha-256",
                    value: bytes.buffer
                }];
                log('Using provided certificate hash for validation.');
            } catch (e) {
                log('Invalid certificate hash format.', 'error');
                throw e;
            }
        }
        
        log(`Connecting to WebTransport at ${url}`);
        wt = new WebTransport(url, options);
        
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
