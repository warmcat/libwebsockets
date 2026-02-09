const remoteVideo = document.getElementById('remoteVideo');
const statusMsg = document.getElementById('status');
let pc;
let ws;

function log(msg) {
    console.log(msg);
    if (statusMsg.innerText !== "")
        statusMsg.innerText = msg;
}

remoteVideo.onplaying = () => {
    statusMsg.innerText = "";
};

function start() {
    log("Connecting...");
    const proto = window.location.protocol === "https:" ? "wss://" : "ws://";
    ws = new WebSocket(proto + window.location.host, "lws-webrtc");

    ws.onopen = () => {
        remoteVideo.classList.remove('disconnected');
        log("Signaling connected. Creating PeerConnection...");
        pc = new RTCPeerConnection({});

        pc.onicecandidate = (event) => {
            if (event.candidate) {
                ws.send(JSON.stringify({ type: 'candidate', candidate: event.candidate }));
            }
        };

        pc.ontrack = (event) => {
            log("Track received!");
            remoteVideo.srcObject = event.streams[0];
        };

        // Add audio/video transceivers to receive streams
        pc.addTransceiver('video', { direction: 'recvonly' });
        pc.addTransceiver('audio', { direction: 'recvonly' });

        pc.createOffer().then(offer => {
            log("Offer created. Sending to server...");
            return pc.setLocalDescription(offer);
        }).then(() => {
            ws.send(JSON.stringify(pc.localDescription));
        });
    };

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'answer') {
            log("Answer received. Setting remote description...");
            pc.setRemoteDescription(new RTCSessionDescription(msg));
        } else if (msg.type === 'candidate') {
            log("Candidate received. Adding...");
            pc.addIceCandidate(new RTCIceCandidate(msg.candidate));
        }
    };

    ws.onerror = (e) => log("WebSocket error: " + e);
    ws.onclose = () => {
        log("WebSocket closed");
        remoteVideo.classList.add('disconnected');
    };
}

window.onload = start;
