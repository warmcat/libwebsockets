const remoteVideo = document.getElementById('remoteVideo');
const statusMsg = document.getElementById('status');
let pc;
let ws;

function log(msg, isError) {
	console.log(msg);
	if (statusMsg) {
		statusMsg.innerText = msg;
		if (isError) {
			statusMsg.style.color = "red";
		} else {
			statusMsg.style.color = "unset";
		}
	}
}

remoteVideo.onplaying = () => {
	statusMsg.innerText = "";
};

function start() {
	log("Connecting...");
	const proto = window.location.protocol === "https:" ? "wss://" : "ws://";
	ws = new WebSocket(proto + window.location.host, "lws-webrtc-webcam");

	ws.onopen = () => {
		remoteVideo.classList.remove('disconnected');
		log("Signaling connected. Creating PeerConnection...");
		try {
			pc = new RTCPeerConnection({});
		} catch (e) {
			log("Failed to create PeerConnection: " + e, true);
			return;
		}

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
		try {
			pc.addTransceiver('video', { direction: 'recvonly' });
			pc.addTransceiver('audio', { direction: 'recvonly' });
		} catch (e) {
			log("Failed to add transceivers: " + e, true);
		}

		pc.createOffer().then(offer => {
			log("Offer created. Sending to server...");
			return pc.setLocalDescription(offer);
		}).then(() => {
			ws.send(JSON.stringify(pc.localDescription));
		}).catch(e => {
			log("Failed to create/set offer: " + e, true);
		});
	};

	ws.onmessage = (event) => {
		const msg = JSON.parse(event.data);
		if (msg.type === 'answer') {
			log("Answer received. Setting remote description...");
			pc.setRemoteDescription(new RTCSessionDescription(msg)).catch(e => {
				let m = "Failed to set remote description: " + e;
				if (e.message && e.message.indexOf("no codecs in common") !== -1)
					m = "WebRTC Error: No common codecs (H.264 required by server)";
				log(m, true);
			});
		} else if (msg.type === 'candidate') {
			log("Candidate received. Adding...");
			pc.addIceCandidate(new RTCIceCandidate(msg.candidate)).catch(e => {
				console.error("Failed to add ICE candidate", e);
			});
		}
	};

	ws.onerror = (e) => log("WebSocket error: " + e);
	ws.onclose = () => {
		log("WebSocket closed");
		remoteVideo.classList.add('disconnected');
	};
}

window.onload = start;
