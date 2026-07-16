const canvas = document.getElementById("renderCanvas");
let engine = null;
let scene = null;
let ground = null;
let boxes = [];
let shadowGenerator = null;
let sunLight = null;
let skyDome = null;
let myAvatar = null;
let camera = null;
let currentSeed = 12345;
let myPlayerId = null;

const otherAvatars = {};
const keys = {};

let localX = 0;
let localZ = 0;
let localAngle = 0;
let localIsMoving = false;

const stats = {
    sentCount: 0,
    recvCount: 0,
    lastSent: "",
    lastRecv: ""
};

window.addEventListener("keydown", (e) => { keys[e.code] = true; });
window.addEventListener("keyup", (e) => { keys[e.code] = false; });

async function initEngine() {
    try {
        engine = new BABYLON.WebGPUEngine(canvas);
        await engine.initAsync();
        console.log("WebGPU Engine initialized.");
    } catch (e) {
        console.warn("WebGPU not supported or failed to initialize, falling back to WebGL.");
        engine = new BABYLON.Engine(canvas, true);
    }

    window.addEventListener("resize", function () {
        if (engine) engine.resize();
    });
}

function initScene() {
    scene = new BABYLON.Scene(engine);
    
    const skyColor = new BABYLON.Color3(0.7, 0.8, 0.9);
    scene.clearColor = new BABYLON.Color4(skyColor.r, skyColor.g, skyColor.b, 1.0);

    camera = new BABYLON.TargetCamera("camera1", new BABYLON.Vector3(0, 100, -40), scene); // Start high to avoid spawning underground
    camera.maxZ = 4000;

    scene.collisionsEnabled = true;
    scene.gravity = new BABYLON.Vector3(0, -9.81, 0);

    // Click to capture mouse (Pointer Lock)
    canvas.addEventListener("click", () => {
        canvas.requestPointerLock = canvas.requestPointerLock || canvas.msRequestPointerLock || canvas.mozRequestPointerLock || canvas.webkitRequestPointerLock;
        if (canvas.requestPointerLock) {
            canvas.requestPointerLock();
        }
    });

    scene.fogMode = BABYLON.Scene.FOGMODE_EXP2;
    scene.fogColor = skyColor;
    scene.fogDensity = 0.001;

    const ambientLight = new BABYLON.HemisphericLight("ambient", new BABYLON.Vector3(0, 1, 0), scene);
    ambientLight.intensity = 0.3;
    ambientLight.groundColor = new BABYLON.Color3(0.2, 0.2, 0.2);

    sunLight = new BABYLON.DirectionalLight("sun", new BABYLON.Vector3(-1, -2, -1), scene);
    sunLight.position = new BABYLON.Vector3(100, 200, 100);
    sunLight.intensity = 1.2;

    shadowGenerator = new BABYLON.ShadowGenerator(2048, sunLight);
    shadowGenerator.useBlurExponentialShadowMap = true;
    shadowGenerator.blurKernel = 32;

    skyDome = BABYLON.MeshBuilder.CreateSphere("skyDome", {segments: 32, diameter: 8000}, scene);
    const skyMat = new BABYLON.StandardMaterial("skyMat", scene);
    skyMat.backFaceCulling = false;
    skyMat.disableLighting = true;
    skyMat.emissiveColor = skyColor;
    skyDome.material = skyMat;
}

function updateCamera() {
    if (!myAvatar) return;
    const avatarPos = myAvatar.pathWrapper.position;
    const angle = myAvatar.pathWrapper.rotation.y;
    
    const distance = 80;
    const height = 30;
    
    const camX = avatarPos.x - Math.sin(angle) * distance;
    const camZ = avatarPos.z - Math.cos(angle) * distance;
    const camY = getTerrainHeight(camX, camZ, currentSeed) + height;
    
    // Smooth follow
    camera.position.x = BABYLON.Scalar.Lerp(camera.position.x, camX, 0.1);
    camera.position.y = BABYLON.Scalar.Lerp(camera.position.y, camY, 0.1);
    camera.position.z = BABYLON.Scalar.Lerp(camera.position.z, camZ, 0.1);
    
    camera.setTarget(avatarPos);
}

function hash2D(x, y, seed) {
    let n = (Math.imul(x, 137) + Math.imul(y, 149) + seed) | 0;
    n = (n ^ (n >>> 13)) | 0;
    const n2 = Math.imul(n, Math.imul(n, n) * 15731 + 789221) + 1376312589;
    return (1.0 - ((n2 & 0x7fffffff) / 1073741824.0));
}

function smoothNoise2D(x, y, seed) {
    const intX = Math.floor(x);
    const fractX = x - intX;
    const intY = Math.floor(y);
    const fractY = y - intY;

    const v1 = hash2D(intX, intY, seed);
    const v2 = hash2D(intX + 1, intY, seed);
    const v3 = hash2D(intX, intY + 1, seed);
    const v4 = hash2D(intX + 1, intY + 1, seed);

    const fx = (1 - Math.cos(fractX * Math.PI)) * 0.5;
    const fy = (1 - Math.cos(fractY * Math.PI)) * 0.5;

    const i1 = v1 * (1 - fx) + v2 * fx;
    const i2 = v3 * (1 - fx) + v4 * fx;

    return i1 * (1 - fy) + i2 * fy;
}

function fbm(x, y, octaves, seed) {
    let total = 0;
    let frequency = 1;
    let amplitude = 1;
    let maxVal = 0;

    for (let i = 0; i < octaves; i++) {
        total += smoothNoise2D(x * frequency, y * frequency, seed + i) * amplitude;
        maxVal += amplitude;
        frequency *= 2.0;
    }

    return total / maxVal;
}

function getTerrainHeight(px, pz, seed) {
    let n = fbm(px * 0.005, pz * 0.005, 4, seed);
    const distFromCenter = Math.sqrt(px * px + pz * pz);
    const centerFlattening = Math.min(1.0, distFromCenter / 100.0);
    n = (n + 1.0) * 0.5;
    n = Math.pow(n, 2.0);
    return n * 80.0 * centerFlattening;
}

function buildWorld(seed) {
    if (ground) ground.dispose();
    boxes.forEach(b => {
        shadowGenerator.removeShadowCaster(b);
        b.dispose();
    });
    boxes = [];

    const groundSize = 4000;
    const groundSubdivisions = 250;
    
    ground = BABYLON.MeshBuilder.CreateGround("ground", {width: groundSize, height: groundSize, subdivisions: groundSubdivisions, updatable: true}, scene);
    ground.receiveShadows = true;
    ground.checkCollisions = true;
    
    let _s = seed;
    function prng() {
        _s = (_s * 9301 + 49297) % 233280;
        return _s / 233280;
    }

    const mat = new BABYLON.StandardMaterial("mat", scene);
    mat.diffuseColor = new BABYLON.Color3(0.15, 0.4, 0.15);
    mat.specularColor = new BABYLON.Color3(0.05, 0.05, 0.05);
    ground.material = mat;

    const positions = ground.getVerticesData(BABYLON.VertexBuffer.PositionKind);

    for (let i = 0; i < positions.length; i += 3) {
        positions[i + 1] = getTerrainHeight(positions[i], positions[i + 2], seed);
    }
    
    ground.updateVerticesData(BABYLON.VertexBuffer.PositionKind, positions);
    const normals = [];
    BABYLON.VertexData.ComputeNormals(positions, ground.getIndices(), normals);
    ground.updateVerticesData(BABYLON.VertexBuffer.NormalKind, normals);

    const numObjects = 800;
    for (let i = 0; i < numObjects; i++) {
        const isTree = prng() > 0.5;
        
        let mesh;
        if (isTree) {
            mesh = BABYLON.MeshBuilder.CreateCylinder("tree", {height: 10 + prng() * 15, diameterTop: 0, diameterBottom: 4}, scene);
            const tmat = new BABYLON.StandardMaterial("tmat", scene);
            tmat.diffuseColor = new BABYLON.Color3(0.1, 0.5 + prng() * 0.3, 0.1);
            mesh.material = tmat;
        } else {
            mesh = BABYLON.MeshBuilder.CreateBox("box", {size: 3 + prng() * 8}, scene);
            mesh.scaling.y = 1 + prng() * 3;
            const bmat = new BABYLON.StandardMaterial("bmat", scene);
            bmat.diffuseColor = BABYLON.Color3.FromHSV(prng() * 360, 0.7, 0.7);
            mesh.material = bmat;
        }

        const px = (prng() - 0.5) * (groundSize * 0.9);
        const pz = (prng() - 0.5) * (groundSize * 0.9);
        const py = getTerrainHeight(px, pz, seed);

        mesh.position.x = px;
        mesh.position.z = pz;
        
        if (isTree) {
            mesh.position.y = py + (mesh.scaling.y * 5);
        } else {
            mesh.position.y = py + (mesh.scaling.y * mesh.getBoundingInfo().boundingBox.extendSize.y);
            mesh.rotation.y = prng() * Math.PI * 2;
            mesh.rotation.x = (prng() - 0.5) * 0.5;
            mesh.rotation.z = (prng() - 0.5) * 0.5;
        }

        mesh.receiveShadows = true;
        shadowGenerator.addShadowCaster(mesh, true);
        boxes.push(mesh);
    }
}

class Avatar {
    constructor(meshes, animationGroups, skeletons, scene) {
        this.pathWrapper = new BABYLON.TransformNode("pathWrapper", scene);
        this.offsetWrapper = new BABYLON.TransformNode("offsetWrapper", scene);
        this.offsetWrapper.parent = this.pathWrapper;
        this.offsetWrapper.rotation = new BABYLON.Vector3(0, 0, 0);
        
        meshes.forEach(m => {
            if (!m.parent) {
                m.parent = this.offsetWrapper;
            }
            if (shadowGenerator) {
                shadowGenerator.addShadowCaster(m, true);
            }
            m.receiveShadows = true;
        });

        this.pathWrapper.scaling = new BABYLON.Vector3(10, 10, 10);

        this.walkRange = null;
        this.skeleton = null;
        if (skeletons && skeletons.length > 0) {
            this.skeleton = skeletons[0];
            const ranges = this.skeleton.getAnimationRanges();
            if (ranges && ranges.length > 0) {
                this.walkRange = ranges.find(r => r.name.toLowerCase().includes("walk")) || ranges[0];
            }
        }
        
        this.animControl = null;
        this.isMoving = false;
        this.speed = 100.0;
        this.rotationSpeed = 3.0;
    }

    setMoving(moving) {
        if (this.isMoving === moving) return;
        this.isMoving = moving;
        if (moving) {
            if (this.walkRange && this.skeleton) {
                this.animControl = scene.beginAnimation(this.skeleton, this.walkRange.from, this.walkRange.to, true, 1.0);
            }
        } else {
            if (this.animControl) {
                this.animControl.pause();
            }
        }
    }

    dispose() {
        if (this.pathWrapper) {
            this.pathWrapper.dispose();
        }
    }
}

function colorAvatar(avatar, id) {
    try {
        if (!avatar || !avatar.pathWrapper) return;
        console.log("Coloring avatar for player ID:", id);
        const hue = (id * 137.5) % 360;
        const color = BABYLON.Color3.FromHSV(hue, 0.8, 0.8);
        
        const meshes = avatar.pathWrapper.getChildMeshes();
        meshes.forEach(m => {
            if (m.material) {
                try {
                    m.material = m.material.clone("mat-" + id);
                    if (m.material.diffuseColor !== undefined) {
                        m.material.diffuseColor = color;
                    }
                    if (m.material.albedoColor !== undefined) {
                        m.material.albedoColor = color;
                    }
                } catch (e) {
                    console.warn("Could not clone or color material for mesh", m.name, e);
                }
            }
        });
    } catch (e) {
        console.error("Error in colorAvatar:", e);
    }
}

async function loadAvatar() {
    let path = window.location.pathname;
    if (!path.endsWith('/')) path += '/';
    
    try {
        const result = await BABYLON.SceneLoader.ImportMeshAsync("", path, "dummy3.babylon", scene);
        if (result.meshes.length === 0) {
            alert("Error: dummy3.babylon loaded but contained no meshes!");
            return;
        }
        myAvatar = new Avatar(result.meshes, result.animationGroups, result.skeletons, scene);
        console.log("Local Avatar loaded successfully!");
        if (myPlayerId !== null) {
            colorAvatar(myAvatar, myPlayerId);
        }
    } catch (e) {
        alert("Failed to load dummy3.babylon. Did you run 'cmake .. && make install'? Error: " + e.message);
        console.error("Failed to load avatar model:", e);
    }
}

async function spawnRemoteAvatar(id, x, z, angle, isMoving) {
    if (otherAvatars[id]) return;
    
    console.log("Spawning remote avatar placeholder for player ID:", id, "at", x, z);
    const placeholder = BABYLON.MeshBuilder.CreateSphere("placeholder-" + id, {diameter: 5}, scene);
    placeholder.position = new BABYLON.Vector3(x, getTerrainHeight(x, z, currentSeed), z);
    const mat = new BABYLON.StandardMaterial("placeholder-mat-" + id, scene);
    mat.diffuseColor = new BABYLON.Color3(0.8, 0.2, 0.2);
    placeholder.material = mat;
    
    otherAvatars[id] = { placeholder, avatar: null };
    
    let path = window.location.pathname;
    if (!path.endsWith('/')) path += '/';
    
    try {
        const result = await BABYLON.SceneLoader.ImportMeshAsync("", path, "dummy3.babylon", scene);
        if (otherAvatars[id]) {
            const currentPos = placeholder.position.clone();
            placeholder.dispose();
            
            const avatar = new Avatar(result.meshes, result.animationGroups, result.skeletons, scene);
            avatar.pathWrapper.position = currentPos;
            avatar.pathWrapper.rotation.y = angle;
            avatar.setMoving(isMoving);
            
            otherAvatars[id].avatar = avatar;
            otherAvatars[id].placeholder = null;
            colorAvatar(avatar, id);
            console.log("Remote avatar mesh spawned successfully for player ID:", id);
        } else {
            result.meshes.forEach(m => m.dispose());
        }
    } catch (e) {
        console.error("Failed to load remote avatar:", e);
    }
}

function updateRemoteAvatar(id, x, z, angle, isMoving) {
    const entry = otherAvatars[id];
    if (entry) {
        if (entry.avatar) {
            entry.avatar.pathWrapper.position = new BABYLON.Vector3(x, getTerrainHeight(x, z, currentSeed), z);
            entry.avatar.pathWrapper.rotation.y = angle;
            entry.avatar.setMoving(isMoving);
        } else if (entry.placeholder) {
            entry.placeholder.position = new BABYLON.Vector3(x, getTerrainHeight(x, z, currentSeed), z);
        }
    } else {
        spawnRemoteAvatar(id, x, z, angle, isMoving);
    }
}

function removeRemoteAvatar(id) {
    const entry = otherAvatars[id];
    if (entry) {
        if (entry.placeholder) entry.placeholder.dispose();
        if (entry.avatar) entry.avatar.dispose();
        delete otherAvatars[id];
        console.log("Remote avatar removed for player ID:", id);
    }
}

function tryReload() {
    if (window.isReloading) return;
    window.isReloading = true;
    console.log("Server disconnected. Waiting for it to come back...");
    
    const checkServer = async () => {
        try {
            const pathname = window.location.pathname;
            if (/^[a-zA-Z0-9\/\-_\.]+$/.test(pathname)) {
                const testUrl = pathname + "?cb=" + Date.now();
                const resp = await fetch(testUrl, { method: "HEAD", cache: "no-store" });
                if (resp.ok) {
                    console.log("Server is back! Reloading page...");
                    window.location.reload();
                    return;
                }
            }
            setTimeout(checkServer, 2000);
        } catch (e) {
            setTimeout(checkServer, 2000);
        }
    };
    setTimeout(checkServer, 2000);
}

function updateOverlay() {
    const overlay = document.getElementById("connection-overlay");
    if (!overlay) return;
    
    let typeText = "Connecting...";
    let typeClass = "connection-overlay";
    if (wtWriter) {
        typeText = "WebTransport (HTTP/3)";
        typeClass = "connection-overlay wt";
    } else if (wsConn && wsConn.readyState === WebSocket.OPEN) {
        typeText = "WebSocket (WSS)";
        typeClass = "connection-overlay ws";
    }
    
    overlay.className = typeClass;
    overlay.innerHTML = `
        <div class="overlay-title">${typeText}</div>
        <div class="overlay-stats">
            <div>Sent: <strong>${stats.sentCount}</strong></div>
            <div>Recv: <strong>${stats.recvCount}</strong></div>
        </div>
        <div class="overlay-json">
            <div><strong>Last Sent:</strong> <span class="json-text">${stats.lastSent || 'None'}</span></div>
            <div><strong>Last Recv:</strong> <span class="json-text">${stats.lastRecv || 'None'}</span></div>
        </div>
    `;
}

function handleServerMessage(msg) {
    console.log("handleServerMessage received raw:", msg);
    const parts = msg.split(/}\s*{/);
    for (let i = 0; i < parts.length; i++) {
        let part = parts[i].trim();
        if (!part) continue;
        if (i > 0) part = "{" + part;
        if (i < parts.length - 1) part = part + "}";
        
        try {
            const obj = JSON.parse(part);
            console.log("Parsed JSON message:", obj);
            stats.recvCount++;
            stats.lastRecv = part;
            updateOverlay();
            
            if (obj.seed) {
                myPlayerId = obj.player_id;
                console.log("Welcome message. Player ID:", myPlayerId, "Seed:", obj.seed, "Players in list:", obj.players);
                if (myAvatar) {
                    colorAvatar(myAvatar, myPlayerId);
                }
                if (obj.seed !== currentSeed) {
                    currentSeed = obj.seed;
                    console.log("Received new seed:", currentSeed);
                    buildWorld(currentSeed);
                }
                if (obj.players) {
                    obj.players.forEach(p => {
                        console.log("Spawning existing player ID:", p.id, "at pos", p.x, p.z);
                        spawnRemoteAvatar(p.id, p.x, p.z, p.angle, p.isMoving);
                    });
                }
            } else if (obj.join !== undefined) {
                console.log("Player ID joined:", obj.join);
                if (obj.join === myPlayerId) {
                    if (myAvatar) {
                        myAvatar.pathWrapper.position = new BABYLON.Vector3(0, getTerrainHeight(0, 0, currentSeed), 0);
                    }
                } else {
                    spawnRemoteAvatar(obj.join, 0, 0, 0, false);
                }
            } else if (obj.leave !== undefined) {
                console.log("Player ID left:", obj.leave);
                removeRemoteAvatar(obj.leave);
            } else if (obj.player_id !== undefined) {
                console.log("Player ID update:", obj.player_id, "Pos:", obj.x, obj.z, "Angle:", obj.angle, "isMoving:", obj.isMoving);
                if (obj.player_id === myPlayerId) {
                    if (myAvatar) {
                        myAvatar.pathWrapper.position = new BABYLON.Vector3(obj.x, getTerrainHeight(obj.x, obj.z, currentSeed), obj.z);
                        myAvatar.pathWrapper.rotation.y = obj.angle;
                        myAvatar.setMoving(obj.isMoving);
                    }
                } else {
                    updateRemoteAvatar(obj.player_id, obj.x, obj.z, obj.angle, obj.isMoving);
                }
            }
        } catch (e) {
            console.error("Error parsing JSON part:", part, e);
        }
    }
}

let wtWriter = null;
let wsConn = null;

function sendUpdate(obj) {
    const msg = JSON.stringify(obj);
    stats.sentCount++;
    stats.lastSent = msg;
    updateOverlay();
    
    if (wtWriter) {
        const encoder = new TextEncoder();
        wtWriter.write(encoder.encode(msg)).catch(e => console.error("WT write error:", e));
    } else if (wsConn && wsConn.readyState === WebSocket.OPEN) {
        wsConn.send(msg);
    }
}

let lastSentX = -999;
let lastSentZ = -999;
let lastSentAngle = -999;
let lastSentMoving = false;

setInterval(() => {
    // 1. Calculate intended position change from keys
    const deltaTime = 100; // tick interval
    const dtSec = deltaTime / 1000.0;
    let moving = false;
    const speed = 100.0;
    const rotationSpeed = 3.0;
    
    if (keys["KeyW"]) {
        localX += Math.sin(localAngle) * speed * dtSec;
        localZ += Math.cos(localAngle) * speed * dtSec;
        moving = true;
    }
    if (keys["KeyS"]) {
        localX -= Math.sin(localAngle) * speed * dtSec;
        localZ -= Math.cos(localAngle) * speed * dtSec;
        moving = true;
    }
    if (keys["KeyA"]) {
        localAngle -= rotationSpeed * dtSec;
        moving = true;
    }
    if (keys["KeyD"]) {
        localAngle += rotationSpeed * dtSec;
        moving = true;
    }
    localIsMoving = moving;
    
    // 2. Check if anything changed from last sent
    if (myPlayerId !== null && (Math.abs(localX - lastSentX) > 0.05 ||
        Math.abs(localZ - lastSentZ) > 0.05 ||
        Math.abs(localAngle - lastSentAngle) > 0.01 ||
        localIsMoving !== lastSentMoving)) {
        
        sendUpdate({
            x: Number.parseFloat(localX.toFixed(2)),
            z: Number.parseFloat(localZ.toFixed(2)),
            angle: Number.parseFloat(localAngle.toFixed(2)),
            isMoving: localIsMoving
        });
        
        lastSentX = localX;
        lastSentZ = localZ;
        lastSentAngle = localAngle;
        lastSentMoving = localIsMoving;
    }
}, 100);

async function connectAndInit() {
    await initEngine();
    initScene();
    
    currentSeed = 12345;
    buildWorld(currentSeed);
    loadAvatar();

    engine.runRenderLoop(function () {
        scene.render();
        if (myAvatar) {
            updateCamera();
        }
    });

    const host = window.location.host;
    const isHttps = window.location.protocol === "https:";
    const wsProto = isHttps ? "wss://" : "ws://";
    
    let path = window.location.pathname;
    if (!path.endsWith('/')) path += '/';
    
    const wsUrl = `${wsProto}${host}${path}`;
    const wtUrl = `https://${host}${path}`;

    let connected = false;
    updateOverlay();

    if (typeof WebTransport !== 'undefined') {
        try {
            console.log("Attempting WebTransport connection to", wtUrl);
            const transport = new WebTransport(wtUrl, {
                protocols: ['webtransport-shared-world']
            });
            
            await Promise.race([
                transport.ready,
                new Promise((_, reject) => setTimeout(() => reject(new Error("WT timeout")), 10000))
            ]);
            
            console.log("WebTransport connected!");
            
            const stream = await transport.createBidirectionalStream();
            if (stream) {
                const streamReader = stream.readable.getReader();
                wtWriter = stream.writable.getWriter();
                connected = true;
                updateOverlay();
                
                (async () => {
                    try {
                        while (true) {
                            const { value: data, done } = await streamReader.read();
                            if (done) {
                                console.log("WT stream done, reloading...");
                                tryReload();
                                break;
                            }
                            if (data) {
                                const msg = new TextDecoder().decode(data);
                                handleServerMessage(msg);
                            }
                        }
                    } catch (e) {
                        console.error("WT read error:", e);
                        tryReload();
                    }
                })();
            }
            
            (async () => {
                try {
                    await transport.closed;
                    console.log("WT session closed cleanly, reloading...");
                } catch (e) {
                    console.warn("WT session closed with error, reloading...", e);
                }
                tryReload();
            })();
            
        } catch (e) {
            console.warn("WebTransport connection failed or timed out:", e);
        }
    }

    if (!connected) {
        try {
            console.log("Attempting WebSocket connection to", wsUrl);
            await new Promise((resolve, reject) => {
                wsConn = new WebSocket(wsUrl, "webtransport-shared-world");
                wsConn.onmessage = (event) => {
                    try {
                        handleServerMessage(event.data);
                    } catch (e) {
                        console.error("Invalid WS message", e);
                    }
                };
                wsConn.onerror = (err) => {
                    console.error("WebSocket error:", err);
                    tryReload();
                    reject(new Error("WebSocket connection failed"));
                };
                wsConn.onclose = () => {
                    console.log("WS connection closed, reloading...");
                    tryReload();
                };
                wsConn.onopen = () => {
                    console.log("WebSocket connected!");
                    connected = true;
                    updateOverlay();
                    resolve();
                };
                
                setTimeout(() => { if (!connected) reject(new Error("WS timeout")); }, 3000);
            });
        } catch (e) {
            console.warn("WebSocket connection failed:", e);
        }
    }

    if (!connected) {
        console.log("Using default local seed due to connection failure.");
    }
}

connectAndInit();
