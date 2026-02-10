const displayVideo = document.getElementById('displayVideo');
const videoLabel = document.getElementById('videoLabel');
const statusMsg = document.getElementById('status');
const startButton = document.getElementById('startButton');
const videoSelect = document.getElementById('videoSource');
const audioSelect = document.getElementById('audioSource');
const audioOutputSelect = document.getElementById('audioOutputSource');
const menuButton = document.getElementById('menuButton');
const menuDropdown = document.getElementById('menuDropdown');
const devicesMenuOption = document.getElementById('devicesMenuOption');
const settingsPanel = document.getElementById('settingsPanel');
const closePanel = document.getElementById('closePanel');
const videoControls = document.getElementById('videoControls');
const audioControls = document.getElementById('audioControls');
const audioOutputControls = document.getElementById('audioOutputControls');
const nameInput = document.getElementById('nameInput');
const participantList = document.getElementById('participantList');
const overlayContainer = document.getElementById('overlayContainer');
const chatButton = document.getElementById('chatButton');
const chatOverlay = document.getElementById('chatOverlay');
const chatHistory = document.getElementById('chatHistory');
const chatInput = document.getElementById('chatInput');
const unreadBadge = document.getElementById('unreadBadge');

let pc;
let ws;
let localStream;
let remoteStream;
let tracksAdded = false;
let inConference = false;
let chatVisible = false;
let unreadCount = 0;
let lastSentJoinedState = null;
let lastSentStats = null;

// Persistence keys
const STORAGE_VIDEO_ID = 'lws_mixer_video_id';
const STORAGE_AUDIO_ID = 'lws_mixer_audio_id';
const STORAGE_OUTPUT_ID = 'lws_mixer_output_id';
const STORAGE_NAME = 'lws_mixer_name';
const STORAGE_CTRL_PREFIX = 'lws_mixer_ctrl_';
let labelTimeout;

/**
 * Common device abstraction (Media Nodes)
 */
class MediaNode {
    constructor(id, label, kind, isRemote = false) {
        this.id = id;
        this.label = label;
        this.kind = kind; // 'videoinput', 'audioinput', or 'audiooutput'
        this.isRemote = isRemote;
        this.controls = []; // Array of {id, name, min, max, step, val}
    }
}

let localNodes = [];
let remoteNodes = [];

function log(msg, isError) {
    console.log((isError ? "ERR: " : "") + msg);
    if (statusMsg) {
        statusMsg.innerText = msg;
        statusMsg.classList.toggle('error', !!isError);
    }
}

function updateConnectionStatus(connected) {
    const el = document.getElementById('connStatus');
    if (el) {
        el.classList.toggle('connected', connected);
        el.title = connected ? "Connected" : "Disconnected";
    }
}

function updateView() {
    videoLabel.classList.remove('hidden');
    if (labelTimeout) clearTimeout(labelTimeout);

    if (inConference && remoteStream) {
        displayVideo.srcObject = remoteStream;
        displayVideo.muted = false;
        videoLabel.innerText = "Conference Stream";
        startButton.innerText = "Connected";

        if (overlayContainer) overlayContainer.style.display = 'block';

        displayVideo.volume = 1.0;
        displayVideo.play().catch(e => console.log("Auto-play failed:", e));

        // Permanent label for metrics
        videoLabel.classList.remove('hidden');
        if (labelTimeout) clearTimeout(labelTimeout);
    } else {
        displayVideo.srcObject = localStream;
        displayVideo.muted = true;
        if (localStream && localStream.getVideoTracks().length > 0) {
             const s = localStream.getVideoTracks()[0].getSettings();
             videoLabel.innerText = `Local Preview (${s.width}x${s.height})`;
        } else {
             videoLabel.innerText = "Local Preview";
        }

        // Hide decorations when in local preview
        if (overlayContainer) overlayContainer.style.display = 'none';

        // Ensure label stays visible during preview (cancel any fade timeout)
        videoLabel.classList.remove('hidden');
        if (labelTimeout) clearTimeout(labelTimeout);
    }
    updateButtonState();

    // Initial size check and event listeners
    adjustOverlaySize();
    window.addEventListener('resize', adjustOverlaySize);
    displayVideo.addEventListener('resize', adjustOverlaySize);
    displayVideo.addEventListener('loadedmetadata', adjustOverlaySize);

    startFPSMonitor();
}

let fpsInterval;
function startFPSMonitor() {
    if (fpsInterval) clearInterval(fpsInterval);

    if (!inConference || !remoteStream) {
        // Clear FPS info from label if we are local
        if (localStream) {
             const s = localStream.getVideoTracks()[0]?.getSettings();
             if (s) videoLabel.innerText = `Local Preview (${s.width}x${s.height})`;
        }
        return;
    }

    // Force label visible during conference
    if (videoLabel.classList.contains('hidden')) {
        videoLabel.classList.remove('hidden');
    }
    if (labelTimeout) clearTimeout(labelTimeout);

    let lastFrames = 0;
    let lastTime = performance.now();

    fpsInterval = setInterval(async () => {
        if (!displayVideo || displayVideo.paused || !pc || pc.signalingState !== 'stable') return;

        try {
            const stats = await pc.getStats();
            let totalFrames = 0;

            stats.forEach(report => {
                if (report.type === 'inbound-rtp' && report.kind === 'video') {
                    totalFrames = report.framesDecoded || 0;
                }
            });

            const now = performance.now();
            const dur = now - lastTime;

            if (dur > 0 && lastFrames > 0) {
                const diff = totalFrames - lastFrames;
                const fps = Math.round((diff * 1000) / dur);

                // Update Label with Resolution
                const w = displayVideo.videoWidth;
                const h = displayVideo.videoHeight;

                let perfClass = 'badge-good';
                if (fps < 15) perfClass = 'badge-poor';
                else if (fps < 24) perfClass = 'badge-fair';

                if (w && h) {
                    videoLabel.innerHTML = `Conference Stream: ${w}x${h} @ <span class="${perfClass}">${fps} FPS</span>`;
                } else {
                    videoLabel.innerHTML = `Conference Stream: <span class="${perfClass}">${fps} FPS</span>`;
                }

                // Ensure visibility
                videoLabel.classList.remove('hidden');
            }

            lastFrames = totalFrames;
            lastTime = now;
        } catch (e) {
            console.error("FPS Stats error:", e);
        }
    }, 1000);
}

function adjustOverlaySize() {
    if (!displayVideo || !overlayContainer) return;

    // Calculate the actual size of the video content within the element
    const videoRatio = displayVideo.videoWidth / displayVideo.videoHeight;
    const elementRatio = displayVideo.clientWidth / displayVideo.clientHeight;

    let width, height, left, top;

    if (!videoRatio) {
        // No video yet, just fill
        width = displayVideo.clientWidth;
        height = displayVideo.clientHeight;
        left = 0;
        top = 0;
    } else if (elementRatio > videoRatio) {
        // Window is wider than video (pillarbox)
        height = displayVideo.clientHeight;
        width = height * videoRatio;
        left = (displayVideo.clientWidth - width) / 2;
        top = 0;
    } else {
        // Window is taller than video (letterbox)
        width = displayVideo.clientWidth;
        height = width / videoRatio;
        top = (displayVideo.clientHeight - height) / 2;
        left = 0;
    }

    overlayContainer.style.width = `${width}px`;
    overlayContainer.style.height = `${height}px`;
    overlayContainer.style.left = `${left}px`;
    overlayContainer.style.top = `${top}px`;
}

function updateButtonState() {
    const name = nameInput.value.trim();

    // Disable name input when in conference
    nameInput.disabled = inConference;

    // Manage Chat Button
    if (chatButton) {
        chatButton.disabled = !inConference;
        if (!inConference) {
             chatButton.classList.remove('active');
        }
    }

    if (inConference) {
        startButton.disabled = false;
        startButton.innerText = "Leave Conference";
        startButton.classList.add('leave');
    } else if (!ws || ws.readyState !== WebSocket.OPEN) {
        startButton.classList.remove('leave');
        startButton.disabled = true;
        startButton.innerText = "Connecting...";
    } else if (!name) {
        startButton.classList.remove('leave');
        startButton.disabled = true;
        startButton.innerText = "Fill Name to Join";
    } else {
        startButton.classList.remove('leave');
        startButton.disabled = false;
        startButton.innerText = "Join Conference";
    }
}

/**
 * Render dynamic controls for a selected device
 */
let audioCtx;
let gainNode;

// Modal Logic
document.addEventListener('DOMContentLoaded', () => {
    const remoteSettingsModal = document.getElementById('remoteSettingsModal');
    // const remoteModalTitle = document.getElementById('remoteModalTitle'); // defined globally or fetched when needed
    // const remoteModalBody = document.getElementById('remoteModalBody');   // defined globally or fetched when needed
    const closeRemoteModal = document.getElementById('closeRemoteModal');

    if (closeRemoteModal) {
        closeRemoteModal.addEventListener('click', () => {
            remoteSettingsModal.classList.add('hidden');
        });
    }

    // Close on outside click
    window.addEventListener('click', (e) => {
        if (e.target === remoteSettingsModal) {
            remoteSettingsModal.classList.add('hidden');
        }
    });
});

// We need these accessible globally for the websocket handlers
let remoteSettingsModal, remoteModalTitle, remoteModalBody;

document.addEventListener('DOMContentLoaded', () => {
    remoteSettingsModal = document.getElementById('remoteSettingsModal');
    remoteModalTitle = document.getElementById('remoteModalTitle');
    remoteModalBody = document.getElementById('remoteModalBody');
});

function renderNodeControls(node, container) {
    if (!container) return;
    container.innerHTML = '';

    if (!node || !node.controls || !node.controls.length) {
        const empty = document.createElement('div');
        empty.className = 'no-controls';
        empty.innerText = 'No hardware controls discovered.';
        container.appendChild(empty);
        return;
    }

    node.controls.forEach(ctrl => {
        const item = document.createElement('div');
        item.className = 'control-item';

        if (ctrl.type === 'boolean') {
            item.className += ' boolean-control';
            const label = document.createElement('label');
            label.className = 'checkbox-container';
            label.innerText = ctrl.name;

            const input = document.createElement('input');
            input.type = 'checkbox';
            input.checked = ctrl.val > 0.5; // >0.5 is true

            input.onchange = (e) => {
                const newVal = e.target.checked ? 1.0 : 0.0;
                applyControl(node, ctrl, newVal);
            };

            const checkmark = document.createElement('span');
            checkmark.className = 'checkmark';

            label.appendChild(input);
            label.appendChild(checkmark);
            item.appendChild(label);
        } else if (ctrl.type === 'select') {
            const header = document.createElement('div');
            header.className = 'control-header';
            const label = document.createElement('label');
            label.innerText = ctrl.name;
            header.appendChild(label);
            item.appendChild(header);

            const select = document.createElement('select');
            select.className = 'control-select';

            ctrl.options.forEach(opt => {
                const option = document.createElement('option');
                option.value = opt;
                option.innerText = opt;
                if (opt === ctrl.val) option.selected = true;
                select.appendChild(option);
            });

            select.onchange = (e) => {
                applyControl(node, ctrl, e.target.value);
            };

            item.appendChild(select);
        } else {
            // Default Slider
            const header = document.createElement('div');
            header.className = 'control-header';
            const label = document.createElement('label');
            label.innerText = ctrl.name;
            const valSpan = document.createElement('span');
            valSpan.className = 'control-value';
            valSpan.innerText = ctrl.val;

            header.appendChild(label);
            header.appendChild(valSpan);
            item.appendChild(header);

            const input = document.createElement('input');
            input.type = 'range';
            input.min = ctrl.min;
            input.max = ctrl.max;
            input.step = ctrl.step || 1;
            input.value = ctrl.val;

            input.oninput = (e) => {
                const newVal = parseFloat(e.target.value);
                valSpan.innerText = newVal;
                applyControl(node, ctrl, newVal);
            };

            item.appendChild(input);
        }
        container.appendChild(item);
    });
}

function renderControls(vNode, aNode, outNode) {
    if (videoControls) videoControls.innerHTML = '';
    if (audioControls) audioControls.innerHTML = '';
    if (audioOutputControls) audioOutputControls.innerHTML = '';

    renderNodeControls(vNode, videoControls);
    renderNodeControls(aNode, audioControls);
    renderNodeControls(outNode, audioOutputControls);
}

function applyControl(node, ctrl, val) {
    ctrl.val = val;
    const storageKey = `${STORAGE_CTRL_PREFIX}${node.id}_${ctrl.id}`;
    localStorage.setItem(storageKey, val);

    if (node.isRemote) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'set_control',
                target: node.targetName,
                kind: node.kind === 'videoinput' ? 'video' : 'audio',
                id: ctrl.id,
                val: val
            }));
            console.log(`[DEBUG] Sent set_control: target=${node.targetName}, id=${ctrl.id}, val=${val}`);
        }
    } else {
        if (node.kind === 'audioinput' && ctrl.id === 'software-gain') {
            if (gainNode) gainNode.gain.setTargetAtTime(val, audioCtx.currentTime, 0.01);
            return;
        }

        if (node.kind === 'audiooutput' && ctrl.id === 'volume') {
             if (displayVideo) displayVideo.volume = val;
             return;
        }

        const tracks = node.kind === 'videoinput' ?
            localStream.getVideoTracks() : localStream.getAudioTracks();
        if (tracks.length > 0) {
            const track = tracks[0];
            const constraints = { advanced: [{ [ctrl.id]: val }] };
            track.applyConstraints(constraints).catch(e => {
                console.warn("Constraint failed:", e);
            });
        }
    }
}

/**
 * Discover hardware capabilities for local tracks
 */
async function discoverLocalCapabilities() {
    if (!localStream) return;

    const vTrack = localStream.getVideoTracks()[0];
    const aTrack = localStream.getAudioTracks()[0];

    const vNode = localNodes.find(n => n.kind === 'videoinput' && n.id === videoSelect.value);
    const aNode = localNodes.find(n => n.kind === 'audioinput' && n.id === audioSelect.value);

    // Video caps
    if (vTrack && vNode) {
        vNode.controls = [];
        const caps = vTrack.getCapabilities ? vTrack.getCapabilities() : {};
        const settings = vTrack.getSettings ? vTrack.getSettings() : {};
        const supported = navigator.mediaDevices.getSupportedConstraints();

        console.log("Local Video Capabilities:", caps);
        console.log("Supported Constraints:", supported);

        // Try ImageCapture API for deeper hardware probe
        let imageCaps = {};
        if (window.ImageCapture) {
            try {
                const capturer = new ImageCapture(vTrack);
                imageCaps = await capturer.getPhotoCapabilities();
                console.log("ImageCapture Capabilities:", imageCaps);
            } catch (e) {
                console.log("ImageCapture not supported for this track:", e.message);
            }
        }

        const videoCandidates = [
            'brightness', 'contrast', 'saturation', 'sharpness',
            'exposureMode', 'exposureTime', 'focusMode', 'focusDistance',
            'whiteBalanceMode', 'colorTemperature', 'zoom', 'tilt', 'pan'
        ];

        videoCandidates.forEach(name => {
            // Check standard caps, supportedConstraints, OR ImageCapture caps
            const cap = caps[name] || imageCaps[name];

            if (cap !== undefined || supported[name]) {
                const saved = localStorage.getItem(`${STORAGE_CTRL_PREFIX}${vNode.id}_${name}`);

                let type = 'slider';
                let min = 0, max = 100, step = 1, val = 0;
                let options = [];

                if (Array.isArray(cap)) {
                    type = 'select';
                    options = cap;
                    val = saved || settings[name] || options[0];
                } else if (typeof cap === 'string') {
                    // Single string value implies a fixed mode or similar, but we can treat as select with 1 option or just display
                    type = 'select';
                    options = [cap];
                    val = saved || settings[name] || cap;
                } else {
                    // It's a range object {min, max, step}
                    const finalRange = (cap && typeof cap === 'object' && cap.min !== undefined) ?
                                        cap : { min: 0, max: 100, step: 1 };
                    min = finalRange.min;
                    max = finalRange.max;
                    step = finalRange.step || 1;
                    val = saved !== null ? parseFloat(saved) : settings[name] || min;
                }

                console.log(`Adding video control ${name} as ${type}`, cap);

                vNode.controls.push({
                    id: name,
                    type: type,
                    name: name.charAt(0).toUpperCase() + name.slice(1).replace(/([A-Z])/g, ' $1'),
                    min: min,
                    max: max,
                    step: step,
                    val: val,
                    options: options
                });
            }
        });
    }

    // Audio caps
    if (aTrack && aNode) {
        aNode.controls = [];
        const caps = aTrack.getCapabilities ? aTrack.getCapabilities() : {};
        const settings = aTrack.getSettings ? aTrack.getSettings() : {};
        const supported = navigator.mediaDevices.getSupportedConstraints();

        console.log("LWS Mixed Audio Caps:", caps);
        console.log("LWS Mixed Audio Settings:", settings);
        console.log("LWS Mixed Supported:", supported);

        ['gain', 'volume', 'echoCancellation', 'noiseSuppression', 'autoGainControl'].forEach(name => {
            if (caps[name] !== undefined || supported[name]) {
                const saved = localStorage.getItem(`${STORAGE_CTRL_PREFIX}${aNode.id}_${name}`);

                // Determine type
                let type = 'slider';
                const isBoolName = ['echoCancellation', 'noiseSuppression', 'autoGainControl'].includes(name);

                if (typeof caps[name] === 'boolean' || (supported[name] && caps[name] === undefined)) {
                    type = 'boolean';
                } else if (isBoolName && typeof caps[name] === 'object' && caps[name].min === 0 && caps[name].max === 1) {
                    // Some browsers expose bools as 0-1 range
                    type = 'boolean';
                } else if (isBoolName) {
                    // Force boolean for known boolean controls if they exist
                    type = 'boolean';
                } else if (Array.isArray(caps[name])) {
                    type = 'select';
                }

                // Default values based on type
                let min = 0, max = 1.0, step = 0.01, val = 1.0;

                if (type === 'slider') {
                     min = caps[name]?.min || 0;
                     max = caps[name]?.max || 1.0;
                     step = caps[name]?.step || 0.01;
                     const def = settings[name] !== undefined ? settings[name] : max;
                     val = saved !== null ? parseFloat(saved) : def;
                } else if (type === 'boolean') {
                    // For boolean, val 1.0 = true, 0.0 = false
                    const def = settings[name] !== undefined ? (settings[name] ? 1.0 : 0.0) : 1.0;
                    val = saved !== null ? parseFloat(saved) : def;
                }

                console.log(`Adding control ${name} as ${type}`);

                aNode.controls.push({
                    id: name,
                    type: type,
                    name: name === 'gain' ? 'Hardware Mic Gain' :
                          name === 'volume' ? 'Hardware Mic Volume' :
                          name.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase()), // camelCase to Title Case
                    min: min,
                    max: max,
                    step: step,
                    val: val
                });
            }
        });

        // Always add Software Gain
        const savedSoft = localStorage.getItem(`${STORAGE_CTRL_PREFIX}${aNode.id}_software-gain`);
        aNode.controls.push({
            id: 'software-gain',
            name: 'Mic Volume (Software)',
            min: 0,
            max: 2.0,
            step: 0.05,
            val: savedSoft !== null ? parseFloat(savedSoft) : 1.0
        });

        if (!audioCtx) {
            try {
                audioCtx = new (window.AudioContext || window.webkitAudioContext)();
                const source = audioCtx.createMediaStreamSource(localStream);
                gainNode = audioCtx.createGain();
                const savedSoft = localStorage.getItem(`${STORAGE_CTRL_PREFIX}${aNode.id}_software-gain`);
                gainNode.gain.value = savedSoft !== null ? parseFloat(savedSoft) : 1.0;
                source.connect(gainNode);
            } catch (e) {
                console.error("AudioContext failed:", e);
            }
        }
    }

    // Audio Output caps (Software only for now as hardware enumeration is strictly sinkId)
    const outNode = localNodes.find(n => n.kind === 'audiooutput' && n.id === audioOutputSelect.value);
    if (outNode) {
        outNode.controls = [];
        const savedVol = localStorage.getItem(`${STORAGE_CTRL_PREFIX}${outNode.id}_volume`);
        outNode.controls.push({
            id: 'volume',
            name: 'Output Volume',
            min: 0,
            max: 1.0,
            step: 0.05,
            val: savedVol !== null ? parseFloat(savedVol) : 1.0
        });
        // Sinks don't support constraints in the same way, so we purely use soft controls/setSinkId
    }

    renderControls(vNode, aNode, outNode);
}

function refreshDeviceUI() {
    const savedVideo = localStorage.getItem(STORAGE_VIDEO_ID);
    const savedAudio = localStorage.getItem(STORAGE_AUDIO_ID);
    const savedOutput = localStorage.getItem(STORAGE_OUTPUT_ID);

    videoSelect.innerHTML = '';
    audioSelect.innerHTML = '';
    if (audioOutputSelect) audioOutputSelect.innerHTML = '';

    // Add local options only (Remote nodes are handled via Participant Menu)
    const allNodes = [...localNodes];

    allNodes.forEach(node => {
        const option = document.createElement('option');
        option.value = node.id;
        option.text = node.label;

        if (node.kind === 'videoinput') {
            videoSelect.appendChild(option);
            if (node.id === savedVideo) videoSelect.value = node.id;
        } else if (node.kind === 'audioinput') {
            audioSelect.appendChild(option);
            if (node.id === savedAudio) audioSelect.value = node.id;
        } else if (node.kind === 'audiooutput' && audioOutputSelect) {
            audioOutputSelect.appendChild(option);
            if (node.id === savedOutput) audioOutputSelect.value = node.id;
        }
    });
}



function toggleVideoMute() {
    if (!localStream) return;
    const track = localStream.getVideoTracks()[0];
    const btn = document.getElementById('muteVideoBtn');
    if (track && btn) {
        track.enabled = !track.enabled;
        btn.classList.toggle('muted', !track.enabled);

        // Update Icon (optional, but color change via CSS is robust)
        // If we wanted to change the icon:
        if (!track.enabled) {
            btn.innerHTML = '<svg viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M1 1l22 22"></path><path d="M21 21l-3.5-3.5"></path><path d="M9 9l-7 5 7 5V9z"></path><path d="M17 17v-3.5"></path><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect></svg>';
        } else {
             btn.innerHTML = '<svg viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M23 7l-7 5 7 5V7z"></path><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect></svg>';
        }
    }
}

function toggleAudioMute() {
    if (!localStream) return;
    const track = localStream.getAudioTracks()[0];
    const btn = document.getElementById('muteAudioBtn');
    if (track && btn) {
        track.enabled = !track.enabled;
        btn.classList.toggle('muted', !track.enabled);

        if (!track.enabled) {
            btn.innerHTML = '<svg viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><line x1="1" y1="1" x2="23" y2="23"></line><path d="M9 9v3a3 3 0 0 0 5.12 2.12M15 9.34V4a3 3 0 0 0-5.94-.6"></path><path d="M17 16.95A7 7 0 0 1 5 12v-2m14 0v2a7 7 0 0 1-.11 1.23"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line></svg>';
        } else {
            btn.innerHTML = '<svg viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path><path d="M19 10v2a7 7 0 0 1-14 0v-2"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line></svg>';
        }
    }
}

async function initDevices() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
        log("Media devices not supported.", true);
        return;
    }

    try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        let vCount = 1, aCount = 1, oCount = 1;

        localNodes = devices
            .filter(d => d.kind === 'videoinput' || d.kind === 'audioinput' || d.kind === 'audiooutput')
            .map(d => {
                let label = d.label;
                if (!label) {
                    if (d.kind === 'videoinput') label = `Camera ${vCount++}`;
                    else if (d.kind === 'audioinput') label = `Mic ${aCount++}`;
                    else if (d.kind === 'audiooutput') label = `Speaker ${oCount++}`;
                }
                return new MediaNode(d.deviceId, label, d.kind);
            });

        refreshDeviceUI();
    } catch (e) {
        log("Error listing devices: " + e.message, true);
    }
}

async function connectSignalling() {
    if (ws) return;

    log("Connecting signalling...");
    const proto = window.location.protocol === "https:" ? "wss://" : "ws://";
    let ws_url = proto + window.location.host;
    if (window.location.search) {
        ws_url += window.location.search;
    }
    ws = new WebSocket(ws_url, "lws-webrtc-mixer");

    ws.onopen = () => {
        log("Signaling connected.");
        updateConnectionStatus(true);
        lastSentJoinedState = null; /* Force send on next check */
        lastSentStats = null;
        updateButtonState();
    };

    ws.onmessage = async (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'answer') {
                // Force the browser to respect the mixer's top codec choice by pruning the m=video line
                // This stops the browser from falling back to H.264 or other defaults if it
                // incorrectly considers multiple codecs in the answer.
                let sdpLines = msg.sdp.split(/\r?\n/);
                for (let i = 0; i < sdpLines.length; i++) {
                    if (sdpLines[i].startsWith('m=video')) {
                        const parts = sdpLines[i].split(' ');
                        if (parts.length > 4) {
                            // Keep m=video, port, proto, and the FIRST payload type
                            sdpLines[i] = parts.slice(0, 4).join(' ');
                        }
                    }
                }
                msg.sdp = sdpLines.join('\r\n');
                if (msg.sdp && !msg.sdp.endsWith('\r\n')) {
                    msg.sdp += '\r\n'; // ensure standard ending
                }

                await pc.setRemoteDescription(new RTCSessionDescription(msg));
            } else if (msg.type === 'candidate') {
                await pc.addIceCandidate(new RTCIceCandidate(msg.candidate));
            } else if (msg.type === 'device_controls') {
                log("Remote device controls received");
                // Create a virtual node for remote controls
                const rVideoNode = new MediaNode("remote_video", "Remote Camera", "videoinput", true);
                rVideoNode.controls = msg.video;
                const rAudioNode = new MediaNode("remote_audio", "Remote Audio", "audioinput", true);
                rAudioNode.controls = msg.audio;

                remoteNodes = [rVideoNode, rAudioNode];
                refreshDeviceUI();
            } else if (msg.type === 'request_res') {
                const track = localStream.getVideoTracks()[0];
                if (track) {
                    await track.applyConstraints({ width: { ideal: msg.width }, height: { ideal: msg.height } });
                }
            } else if (msg.type === 'remote_capabilities') {
                /* {"type":"remote_capabilities","target":"<name>","payload":{"type":"capabilities","kind":"video","controls":[...]}} */
                log("Remote caps received for " + msg.target);
                const payload = msg.payload;

                // Find or create remote node
                // We use ID = "remote_" + target_name + "_" + kind
                const id = `remote_${msg.target}_${payload.kind}`;
                const label = `${msg.target} (${payload.kind})`;
                const kind = payload.kind === 'video' ? 'videoinput' : 'audioinput';

                let node = remoteNodes.find(n => n.id === id);
                if (!node) {
                    node = new MediaNode(id, label, kind, true);
                    node.targetName = msg.target;
                    remoteNodes.push(node);
                }

                node.controls = payload.controls.map(c => {
                    // Map V4L2 types to frontend types
                    // 1=INTEGER, 2=BOOLEAN, 3=MENU, 4=BUTTON, 5=INT64, 6=CLASS, 7=STRING, 8=BITMASK, 9=INT_MENU
                    if (c.type === 2) {
                        c.type = 'boolean';
                    } else if (c.type === 3 || c.type === 9) {
                        c.type = 'select';
                         // We lack menu labels for now, so maybe treat as slider or numeric select?
                         // actually, let's keep it slider for now unless we iterate the menu items backend side
                         c.type = 'slider';
                    } else {
                        c.type = 'slider';
                    }
                    console.log(`[DEBUG] Mapped control ${c.name} (v4l2_type=${c.type_orig || 'unknown'}) to ${c.type}`);
                    return c;
                });

                // If remote modal is open for this participant, refresh it
                if (!remoteSettingsModal.classList.contains('hidden') &&
                    remoteModalTitle.innerText.includes(msg.target)) {
                     // Re-render
                     // Find all nodes for this target
                     const nodes = remoteNodes.filter(n => n.targetName === msg.target);
                     remoteModalBody.innerHTML = '';
                     nodes.forEach(n => {
                         const header = document.createElement('h3');
                         header.innerText = n.kind === 'videoinput' ? 'Camera' : 'Microphone';
                         remoteModalBody.appendChild(header);
                         const container = document.createElement('div');
                         remoteModalBody.appendChild(container); // create wrapper
                         renderNodeControls(n, container);
                     });
                }

                refreshDeviceUI();

            } else if (msg.type === 'client_list') {
                console.log("Received client list:", msg.clients);
                updateParticipants(msg.clients);
            } else if (msg.type === 'layout') {
                updateLayout(msg.regions);
            } else if (msg.type === 'presence_check') {
                /* Server requires this as a heartbeat! Do not suppress. */
                ws.send(JSON.stringify({
                    type: 'presence_report',
                    joined: inConference
                }));
            } else if (msg.type === 'sys_status') {
                const statDiv = document.getElementById('sysStatus');
                if (statDiv) {
                    const temp = (msg.temp / 1000).toFixed(1);
                    const load = msg.load.map(l => l.toFixed(2)).join(' ');
                    statDiv.innerText = `Temp: ${temp}°C | Load: ${load}`;
                    statDiv.classList.remove('hidden');
                }
            } else if (msg.type === 'audio_level') {
                const dot = document.getElementById('audioDot');
                if (dot) {
                     // level is 0-100. Opacity 0.2 to 1.0.
                     const op = 0.2 + (msg.level / 100) * 0.8;
                     dot.style.opacity = op;
                }
            } else if (msg.type === 'chat') {
                if (inConference) {
                    appendChatMessage(msg);
                }
            }
        } catch (e) {}
    };

    ws.onclose = () => {
        log("Connection lost");
        updateConnectionStatus(false);
        ws = null;
        inConference = false;
        tracksAdded = false;
        remoteStream = null;
        chatVisible = false;

        if (chatHistory) chatHistory.innerHTML = '';

        if (pc) {
            pc.close();
            pc = null;
        }

        if (chatOverlay) chatOverlay.classList.add('hidden');
        if (chatButton) chatButton.classList.remove('active');
        updateView();

        // Auto-reconnect
        setTimeout(connectSignalling, 1000);
    };
}

function createPeerConnection() {
    if (pc) {
        pc.close();
    }

    pc = new RTCPeerConnection({
        iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
    });

    pc.oniceconnectionstatechange = () => {
        log("ICE State: " + pc.iceConnectionState);
    };

    pc.onicecandidate = (event) => {
        if (event.candidate && ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'candidate', candidate: event.candidate }));
        }
    };

    pc.ontrack = (event) => {
        log("Remote track received: " + event.track.kind);
        if (event.streams && event.streams[0]) {
             remoteStream = event.streams[0];
             inConference = true;
             updateView();
        } else {
             // Fallback if no stream is associated (shouldn't happen with unified plan usually)
             if (!remoteStream) remoteStream = new MediaStream();
             remoteStream.addTrack(event.track);
             inConference = true;
             updateView();
        }
    };
}

let adaptationInterval = null;
let currentScaleFactor = 1.0;

function startAdaptationLoop() {
    if (adaptationInterval) clearInterval(adaptationInterval);

    adaptationInterval = setInterval(async () => {
        if (!pc || pc.signalingState !== 'stable') return;

        const senders = pc.getSenders();
        const videoSender = senders.find(s => s.track && s.track.kind === 'video');
        if (!videoSender) return;

        try {
            const stats = await pc.getStats();
            let packetsLost = 0;
            let totalPackets = 0;
            let rtt = 0;
            let currentFramesEncoded = 0;

            stats.forEach(report => {
                if (report.type === 'remote-inbound-rtp' && report.kind === 'video') {
                    packetsLost = report.packetsLost;
                    totalPackets = report.packetsReceived + report.packetsLost; // Approximation
                    rtt = report.roundTripTime;
                }
                if (report.type === 'outbound-rtp' && report.kind === 'video') {
                    currentFramesEncoded = report.framesEncoded || 0;
                }
            });

            // Calculate Outbound FPS
            var outboundFps = window.lastComputedFps || 0;
            if (window.lastFramesCount !== undefined && currentFramesCount > window.lastFramesCount) {
                 // Loop runs every 2s
                 var instantFps = Math.round((currentFramesCount - window.lastFramesCount) / 2);
                 outboundFps = Math.round((outboundFps * 0.5) + (instantFps * 0.5)); // Smoothing
            }
            window.lastFramesCount = currentFramesCount;
            window.lastComputedFps = outboundFps;

            // Calculate Recent Packet Loss
            var recentPacketsLost = 0;
            if (window.lastPacketsLost !== undefined) {
                 recentPacketsLost = currentPacketsLost - window.lastPacketsLost;
                 if (recentPacketsLost < 0) recentPacketsLost = 0;
            }
            window.lastFramesEncoded = currentFramesEncoded;

            // Simple heuristic
            let newScale = currentScaleFactor;
            if (packetsLost > 5 || rtt > 0.2) { // >5 packets lost or >200ms RTT
                 newScale = Math.min(newScale * 2.0, 4.0); // Downgrade
            } else if (packetsLost === 0 && rtt < 0.1) {
                 newScale = Math.max(newScale / 2.0, 1.0); // Upgrade
            }

            if (newScale !== currentScaleFactor) {

                currentScaleFactor = newScale;
                const params = videoSender.getParameters();
                if (!params.encodings) params.encodings = [{}];
                params.encodings[0].scaleResolutionDownBy = currentScaleFactor;
                await videoSender.setParameters(params);
            }

            // Report Stats
            if (localStream && localStream.getVideoTracks().length > 0) {
                const settings = localStream.getVideoTracks()[0].getSettings();
                const camW = settings.width || 0;
                const camH = settings.height || 0;
                const sentW = Math.round(camW / currentScaleFactor);
                const sentH = Math.round(camH / currentScaleFactor);



                let performance = "Excellent";
                if (currentScaleFactor >= 4.0) performance = "Poor";
                else if (currentScaleFactor >= 2.0) performance = "Fair";
                else if (currentScaleFactor > 1.0) performance = "Good";

                const statsStr = `${camW}x${camH} -> ${sentW}x${sentH} @ ${outboundFps}fps (${performance})`;

                if (ws && ws.readyState === WebSocket.OPEN) {
                    // Deduplicate stats messages
                    if (statsStr !== lastSentStats) {
                        ws.send(JSON.stringify({ type: 'stats', stats: statsStr }));
                        lastSentStats = statsStr;
                    }
                }
            }

        } catch (e) {

        }

    }, 2000); // Check every 2s
}

async function setupPreview() {
    if (localStream) {
        localStream.getTracks().forEach(t => t.stop());
        localStream = null;
    }

    const videoId = videoSelect.value;
    const audioId = audioSelect.value;

    // Is this a remote node?
    const isRemote = videoId && videoId.startsWith('remote_');
    if (isRemote) {
        log("Previewing remote node settings...");
        renderControls(
            [...localNodes, ...remoteNodes].find(n => n.id === videoId),
            [...localNodes, ...remoteNodes].find(n => n.id === audioId),
            null // Remote output control not yet supported in UI preview
        );
        return;
    }

    // Save persistence (avoid saving empty/undefined)
    if (videoId && videoId !== 'undefined') localStorage.setItem(STORAGE_VIDEO_ID, videoId);
    if (audioId && audioId !== 'undefined') localStorage.setItem(STORAGE_AUDIO_ID, audioId);

    // Output selection logic
    const outputId = audioOutputSelect ? audioOutputSelect.value : null;
    if (outputId && outputId !== 'undefined') {
        localStorage.setItem(STORAGE_OUTPUT_ID, outputId);
        if (displayVideo.setSinkId) {
            displayVideo.setSinkId(outputId)
                .catch(e => console.warn("Failed to set audio output:", e));
        }
    }

    const tryGetMedia = async (constraints) => {
        try {
            const stream = await navigator.mediaDevices.getUserMedia(constraints);
            return stream;
        } catch (e) {
            console.warn("GUM effort failed:", e.name, e.message, JSON.stringify(constraints));
            return null;
        }
    };

    // Stage 1: Preferred devices with ideal resolution
    // Stage 1: Preferred devices with exact ID and ideal resolution
    log(`Requesting camera: ${videoId || 'default'}...`);
    let constraints = {
        audio: (audioId && audioId !== 'undefined') ? { deviceId: { exact: audioId } } : true,
        video: (videoId && videoId !== 'undefined') ?
                { deviceId: { exact: videoId }, width: { min: 1280, ideal: 1280 }, height: { min: 720, ideal: 720 } } :
                { width: { min: 1280, ideal: 1280 }, height: { min: 720, ideal: 720 } }
    };

    localStream = await tryGetMedia(constraints);

    // Stage 1b: Fallback to ideal if exact fails
    if (!localStream && (videoId || audioId)) {
        log("Exact selection failed, trying ideal...");
        constraints = {
            audio: (audioId && audioId !== 'undefined') ? { deviceId: { ideal: audioId } } : true,
            video: (videoId && videoId !== 'undefined') ?
                    { deviceId: { ideal: videoId }, width: { min: 1280, ideal: 1280 }, height: { min: 720, ideal: 720 } } :
                    { width: { min: 1280, ideal: 1280 }, height: { min: 720, ideal: 720 } }
        };
        localStream = await tryGetMedia(constraints);
    }

    // Stage 1c: "Soft" 720p (Ideal) if "Hard" 720p (Min) failed
    if (!localStream) {
        constraints = {
            audio: (audioId && audioId !== 'undefined') ? { deviceId: { ideal: audioId } } : true,
            video: (videoId && videoId !== 'undefined') ?
                    { deviceId: { ideal: videoId }, width: { ideal: 1280 }, height: { ideal: 720 } } :
                    { width: { ideal: 1280 }, height: { ideal: 720 } }
        };
        localStream = await tryGetMedia(constraints);
    }


    // Stage 2: Generic fallback if specific IDs or resolutions fail
    if (!localStream) {
        localStream = await tryGetMedia({ video: true, audio: true });
    }

    // Stage 3: Extreme fallback (video only)
    if (!localStream) {
        localStream = await tryGetMedia({ video: true });
    }

    if (localStream) {
        const vTrack = localStream.getVideoTracks()[0];
        const aTrack = localStream.getAudioTracks()[0];

        updateView();

        // Populate labels and discover capabilities
        await initDevices();
        await discoverLocalCapabilities();
        await connectSignalling();
    } else {
        log("Camera error: Could not access any media device.", true);
    }
}

async function join() {
    // Ensure WS connection
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        connectSignalling();
        // We might validly be in a race here if WS wasn't open,
        // but for the "Persistent" case, WS should be open.
        // Failing that, we'll error on send, which is handled.
    }

    if (!pc || pc.signalingState === "closed") {
        createPeerConnection();
    }

    if (tracksAdded) return;

    if (!localStream) {
        log("No local stream available. Please check camera permissions.", true);
        return;
    }

    log("Joining conference...");
    localStream.getTracks().forEach(track => {
        pc.addTrack(track, localStream);
    });
    tracksAdded = true;

    // Apply Codec Preferences
    const codecSelect = document.getElementById('videoCodec');
    if (codecSelect && codecSelect.value !== 'auto') {
        const preferredCodec = codecSelect.value;
        if (RTCRtpReceiver.getCapabilities) {
            const codecs = RTCRtpReceiver.getCapabilities('video').codecs;
            const sortedCodecs = [];

            // Prioritize preferred codec
            codecs.forEach(codec => {
                if (codec.mimeType.toLowerCase() === `video/${preferredCodec.toLowerCase()}`) {
                    sortedCodecs.push(codec);
                }
            });

            // Append the rest
            codecs.forEach(codec => {
                if (codec.mimeType.toLowerCase() !== `video/${preferredCodec.toLowerCase()}`) {
                    sortedCodecs.push(codec);
                }
            });

            const transceivers = pc.getTransceivers();
            const videoTransceiver = transceivers.find(t => t.sender.track && t.sender.track.kind === 'video');
            if (videoTransceiver && videoTransceiver.setCodecPreferences) {
                console.log(`Setting codec preference to ${preferredCodec}`);
                videoTransceiver.setCodecPreferences(sortedCodecs);
            } else {
                console.warn("setCodecPreferences not supported or no video transceiver found.");
            }
        }
    }

    pc.createOffer().then(offer => {
        return pc.setLocalDescription(offer);
    }).then(() => {
        const name = nameInput.value.trim() || 'Anonymous';
        log(`Sending offer for ${name}...`);
        ws.send(JSON.stringify({
            type: pc.localDescription.type,
            sdp: pc.localDescription.sdp,
            name: name
        }));

        console.log("Sending explicit join for:", name);
        ws.send(JSON.stringify({ type: 'join', name: name }));
        inConference = true;
        startAdaptationLoop();
        updateView();
    }).catch(e => {
        log("Join failed: " + e.message, true);
    });
}

// Participant Context Menu
let activeParticipant = null;
const partMenu = document.createElement('div');
partMenu.className = 'dropdown part-menu';
partMenu.innerHTML = '<button id="partDeviceBtn">Devices...</button>';
document.body.appendChild(partMenu);

document.getElementById('partDeviceBtn').onclick = () => {
    if (!activeParticipant) return;

    // Check if we are actually joined
    const local = participantList.querySelector('.participant-item:not(.unjoined) .name');
    // ^ crude check. Better:
    if (!inConference) {
        log("You must join the conference to access remote devices.", true);
        partMenu.classList.remove('show');
        return;
    }

    const pName = activeParticipant;
    const vNode = remoteNodes.find(n => n.targetName === pName && n.kind === 'videoinput');

    if (!vNode) {
        // Request it
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'request_caps', target: pName }));
            log(`Requesting controls for ${pName}...`);
        }
    }

    // Open Remote Settings in Sidebar
    partMenu.classList.remove('show');

    const settingsPanel = document.getElementById('settingsPanel');
    const panelHeader = settingsPanel.querySelector('.panel-header h2');

    // Show Panel
    settingsPanel.classList.remove('hidden');
    // Remove 'remote' class as we now support coexistence or explicit sections
    settingsPanel.classList.remove('remote');

    // Update Main Title
    panelHeader.innerText = 'Settings';

    // Show Remote Section
    const remoteGroup = document.getElementById('remoteSettingsGroup');
    const remoteContainer = document.getElementById('remoteControlsContainer');
    const remoteHeader = remoteGroup.querySelector('.remote-header-container');

    remoteGroup.classList.remove('hidden');
    remoteContainer.innerHTML = '';

    // Inject Remote Title (Safe)
    remoteHeader.innerHTML = '';

    const rhDiv = document.createElement('div');
    rhDiv.style.display = 'flex';
    rhDiv.style.flexDirection = 'column';
    rhDiv.style.alignItems = 'flex-start';
    rhDiv.style.lineHeight = '1.2';
    rhDiv.style.marginBottom = '1rem';

    const rhTitle = document.createElement('div');
    rhTitle.style.fontWeight = '600';
    rhTitle.style.color = '#fff';
    rhTitle.innerText = 'Remote Control';

    const rhName = document.createElement('div');
    rhName.style.fontSize = '0.9em';
    rhName.style.fontWeight = '400';
    rhName.style.color = '#94a3b8';
    rhName.innerText = pName;

    rhDiv.appendChild(rhTitle);
    rhDiv.appendChild(rhName);
    remoteHeader.appendChild(rhDiv);

    // Show Local Section too (Coexistence)
    document.getElementById('localSettingsGroup').classList.remove('hidden');

    // Find all nodes for this target
    const nodes = remoteNodes.filter(n => n.targetName === pName);
    console.log(`[DEBUG] Opening sidebar settings for ${pName}. Found ${nodes.length} nodes.`);

    if (nodes.length === 0) {
        remoteContainer.innerHTML = '<div class="no-controls">Loading controls... (Request sent)</div>';
    } else {
        nodes.forEach(n => {
            // Create a sub-container for this node
            const nodeDiv = document.createElement('div');
            nodeDiv.className = 'remote-node-group';
            nodeDiv.style.marginBottom = '1.5rem';

            const header = document.createElement('h3');
            header.innerText = n.kind === 'videoinput' ? 'Camera' : (n.kind === 'audioinput' ? 'Microphone' : 'Output');
            header.className = 'remote-header'; // reused class, ensure style matches
            header.style.fontSize = '0.8rem';
            header.style.textTransform = 'uppercase';
            header.style.color = '#94a3b8';
            header.style.marginBottom = '0.5rem';

            nodeDiv.appendChild(header);

            // Render controls into this nodeDiv
            renderNodeControls(n, nodeDiv);

            remoteContainer.appendChild(nodeDiv);
        });
    }
};

function showParticipantMenu(e, name) {
    e.preventDefault();
    e.stopPropagation();
    activeParticipant = name;

    // Position menu
    partMenu.style.top = `${e.clientY}px`;
    partMenu.style.left = `${e.clientX}px`;
    partMenu.classList.add('show');

    // Close other menus
    menuDropdown.classList.remove('show');
}

window.addEventListener('click', () => {
    partMenu.classList.remove('show');
});

function updateParticipants(clients) {
    if (participantList) participantList.innerHTML = '';

    console.log("DIAGNOSTIC frontend updateParticipants: count=", clients.length, "clients=", JSON.stringify(clients));

    clients.forEach((c) => {
        // List in sidebar
        if (participantList) {
            const item = document.createElement('div');
            item.className = 'participant-item' + (c.joined ? '' : ' unjoined');
            item.style.cursor = 'pointer';

            item.onclick = (e) => showParticipantMenu(e, c.name);

            // Icon for everyone
            const icon = document.createElement('span');
            icon.className = 'icon-user-silhouette';
            icon.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>';

            if (c.joined) {
                // Determine a pseudo-color from name hash (requires stringToColor to exist, but using simple style or keeping it default if not)
                // Assuming CSS handles default color or we just don't touch it.
            } else {
                icon.style.color = '#888';
                icon.style.opacity = '0.5';
                item.title = "Connecting...";
            }
            
            item.appendChild(icon);

            const nameSpan = document.createElement('span');
            nameSpan.className = 'name';
            nameSpan.innerText = c.joined ? c.name : ''; // Hide name if unjoined
            item.appendChild(nameSpan);

            participantList.appendChild(item);
        }
    });
}

function updateLayout(regions) {
    if (!overlayContainer) return;
    overlayContainer.innerHTML = ''; // clear existing overlays

    regions.forEach(r => {
        const overlay = document.createElement('div');
        overlay.className = 'name-overlay';
        
        // Apply explicit positions rather than CSS classes
        overlay.style.left = r.x + '%';
        overlay.style.top = r.y + '%';
        // Note: we don't strictly set width/height as it's an overlay div,
        // but it's guaranteed to be within the sub-region.
        overlay.style.maxWidth = r.w + '%';
        
        // The text comes in as "Alice\nStats..."
        const parts = r.text.split('\n');
        
        const nameSpan = document.createElement('div');
        nameSpan.innerText = parts[0] || '';
        nameSpan.style.fontWeight = 'bold';
        overlay.appendChild(nameSpan);

        if (parts.length > 1 && parts[1]) {
            const statsSpan = document.createElement('div');
            statsSpan.innerText = parts[1];
            statsSpan.style.fontSize = '0.8em';
            statsSpan.style.opacity = '0.8';
            overlay.appendChild(statsSpan);
        }

        overlayContainer.appendChild(overlay);
    });
}

// UI Event Handlers
menuButton.onclick = (e) => {
    e.stopPropagation();
    menuDropdown.classList.toggle('show');
};

devicesMenuOption.onclick = () => {
    settingsPanel.classList.remove('hidden');
    document.querySelector('.panel-header h2').innerText = 'Settings';

    document.getElementById('remoteSettingsGroup').classList.add('hidden');
    document.getElementById('localSettingsGroup').classList.remove('hidden');

    menuDropdown.classList.remove('show');
    const vNode = [...localNodes, ...remoteNodes].find(n => n.kind === 'videoinput' && n.id === videoSelect.value);
    const aNode = [...localNodes, ...remoteNodes].find(n => n.kind === 'audioinput' && n.id === audioSelect.value);
    const oNode = [...localNodes].find(n => n.kind === 'audiooutput' && n.id === audioOutputSelect?.value);

    // Clear and re-render
    videoControls.innerHTML = '';
    audioControls.innerHTML = '';
    if (audioOutputControls) audioOutputControls.innerHTML = '';

    if (vNode) renderNodeControls(vNode, videoControls);
    if (aNode) renderNodeControls(aNode, audioControls);
    if (oNode) renderNodeControls(oNode, audioOutputControls);
};

closePanel.onclick = () => {
    settingsPanel.classList.add('hidden');
};

window.onclick = () => {
    menuDropdown.classList.remove('show');
};

function leaveConference() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        log("Leaving conference...");
        ws.send(JSON.stringify({ type: 'leave' }));
    }

    if (pc) {
        pc.close();
        pc = null;
    }

    if (adaptationInterval) {
        clearInterval(adaptationInterval);
        adaptationInterval = null;
    }

    inConference = false;
    tracksAdded = false;
    remoteStream = null;

    // Reset Chat Badge
    unreadCount = 0;
    if (unreadBadge) {
        unreadBadge.innerText = '0';
        unreadBadge.classList.add('hidden');
    }

    if (chatHistory) chatHistory.innerHTML = '';

    chatVisible = false;
    if (chatOverlay) chatOverlay.classList.add('hidden');
    if (chatButton) chatButton.classList.remove('active');

    updateView();
}

function toggleConference() {
    if (inConference) {
        leaveConference();
    } else {
        join();
    }
}

startButton.onclick = toggleConference;

videoSelect.onchange = () => {
    setupPreview();
    const vNode = [...localNodes, ...remoteNodes].find(n => n.kind === 'videoinput' && n.id === videoSelect.value);
    const aNode = [...localNodes, ...remoteNodes].find(n => n.kind === 'audioinput' && n.id === audioSelect.value);
    const oNode = [...localNodes].find(n => n.kind === 'audiooutput' && n.id === audioOutputSelect?.value);
    renderControls(vNode, aNode, oNode);
};

audioSelect.onchange = () => {
    setupPreview();
    const vNode = [...localNodes, ...remoteNodes].find(n => n.kind === 'videoinput' && n.id === videoSelect.value);
    const aNode = [...localNodes, ...remoteNodes].find(n => n.kind === 'audioinput' && n.id === audioSelect.value);
    const oNode = [...localNodes].find(n => n.kind === 'audiooutput' && n.id === audioOutputSelect?.value);
    renderControls(vNode, aNode, oNode);
};

if (audioOutputSelect) {
    audioOutputSelect.onchange = () => {
        setupPreview();
        const vNode = [...localNodes, ...remoteNodes].find(n => n.kind === 'videoinput' && n.id === videoSelect.value);
        const aNode = [...localNodes, ...remoteNodes].find(n => n.kind === 'audioinput' && n.id === audioSelect.value);
        const oNode = [...localNodes].find(n => n.kind === 'audiooutput' && n.id === audioOutputSelect.value);
        renderControls(vNode, aNode, oNode);
    };
}

document.addEventListener('DOMContentLoaded', () => {
    const savedName = localStorage.getItem(STORAGE_NAME);
    if (savedName) {
        nameInput.value = savedName;
    }

    nameInput.addEventListener('input', () => {
        const name = nameInput.value.trim();
        if (name) {
            localStorage.setItem(STORAGE_NAME, name);
        }
        updateButtonState();
    });

    updateButtonState();

    const mvBtn = document.getElementById('muteVideoBtn');
    if (mvBtn) mvBtn.onclick = toggleVideoMute;

    const maBtn = document.getElementById('muteAudioBtn');
    if (maBtn) maBtn.onclick = toggleAudioMute;

    initDevices().then(() => setupPreview());
});

/**
 * Chat Logic
 */
function toggleChat() {
    // Button should be disabled if not in conference, but safety check remains
    if (!inConference) return;

    chatVisible = !chatVisible;
    if (chatOverlay) chatOverlay.classList.toggle('hidden', !chatVisible);
    if (chatButton) chatButton.classList.toggle('active', chatVisible);

    if (chatVisible) {
        unreadCount = 0;
        if (unreadBadge) {
            unreadBadge.innerText = '0';
            unreadBadge.classList.add('hidden');
        }
        if (chatInput) setTimeout(() => chatInput.focus(), 100);
        // Scroll to bottom
        if (chatHistory) chatHistory.scrollTop = chatHistory.scrollHeight;
    }
}


if (chatButton) {
    chatButton.addEventListener('click', toggleChat);
}

if (chatInput) {
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const text = chatInput.value.trim();
            if (text && ws && ws.readyState === WebSocket.OPEN && inConference) {
                ws.send(JSON.stringify({
                    type: 'chat',
                    text: text
                }));
                // Optimistic append? No, let server echo back or just append locally if we want instant feedback.
                // The requirement says: "That includes the sender of a new text, it is cleared from his text widget and the server will send it to the chat history."
                // So we wait for server echo.
                chatInput.value = '';
            } else if (!inConference) {
                log("You must join the conference to chat.", true);
            }
        }
    });
}

function escapeHtml(text) {
    if (!text) return text;
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function linkify(text) {
    if (!text) return text;
    // Simple regex for https links
    // Note: requirements say "https:// links should be clickable"
    const urlRegex = /(https:\/\/[^\s]+)/g;
    return text.replace(urlRegex, function(url) {
        return '<a href="' + url + '" target="_blank" rel="noopener noreferrer">' + url + '</a>';
    });
}

function appendChatMessage(msg) {
    if (!chatHistory) return;

    const div = document.createElement('div');
    div.className = 'chat-msg';

    // msg object: { sender: "Name", text: "..." }
    const senderSpan = document.createElement('span');
    senderSpan.className = 'chat-sender';
    senderSpan.innerText = msg.sender + ':';

    const textSpan = document.createElement('span');
    textSpan.className = 'chat-text';
    textSpan.innerHTML = linkify(escapeHtml(msg.text));

    div.appendChild(senderSpan);
    div.appendChild(textSpan);

    chatHistory.appendChild(div);

    // Auto-scroll if near bottom
    if (chatVisible) {
        chatHistory.scrollTop = chatHistory.scrollHeight;
    } else {
        unreadCount++;
        if (unreadBadge) {
             const disp = unreadCount > 99 ? '99+' : unreadCount;
             unreadBadge.innerText = disp;
             unreadBadge.classList.remove('hidden');
        }
    }
}


