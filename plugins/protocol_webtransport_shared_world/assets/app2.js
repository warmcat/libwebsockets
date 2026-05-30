const canvas = document.getElementById("renderCanvas");
let engine = null;
let scene = null;
let ground = null;
let boxes = [];
let shadowGenerator = null;
let sunLight = null;
let skyDome = null;
let myAvatar = null;
let currentSeed = 12345;

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

    const camera = new BABYLON.FreeCamera("camera1", new BABYLON.Vector3(0, 100, -40), scene); // Start high to avoid spawning underground
    camera.setTarget(BABYLON.Vector3.Zero());
    camera.attachControl(canvas, true);
    
    // WASD Controls
    camera.keysUp.push(87);    // W
    camera.keysDown.push(83);  // S
    camera.keysLeft.push(65);  // A
    camera.keysRight.push(68); // D
    camera.speed = 2.0;
    camera.maxZ = 4000;

    // Enable Collisions and Gravity
    scene.collisionsEnabled = true;
    scene.gravity = new BABYLON.Vector3(0, -9.81, 0);
    camera.checkCollisions = true;
    camera.applyGravity = true;
    camera.ellipsoid = new BABYLON.Vector3(2, 5, 2);

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
        amplitude *= 0.5;
        frequency *= 2.0;
    }

    return total / maxVal;
}

// Function to calculate exact terrain height at any point
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
        // Create a parent wrapper to handle translation and lookAt along the circle
        this.pathWrapper = new BABYLON.TransformNode("pathWrapper", scene);
        
        // Create an inner wrapper (kept for clean hierarchy, but with 0 rotation since the model faces +Z natively)
        this.offsetWrapper = new BABYLON.TransformNode("offsetWrapper", scene);
        this.offsetWrapper.parent = this.pathWrapper;
        this.offsetWrapper.rotation = new BABYLON.Vector3(0, 0, 0);
        
        // Parent ALL imported root meshes to the offsetWrapper (this ensures the skeleton/bones are rotated too!)
        meshes.forEach(m => {
            if (!m.parent) {
                m.parent = this.offsetWrapper;
            }
            if (shadowGenerator) {
                shadowGenerator.addShadowCaster(m, true);
            }
            m.receiveShadows = true;
        });

        // The overall scale can be applied to the pathWrapper
        this.pathWrapper.scaling = new BABYLON.Vector3(10, 10, 10);

        // Try playing via AnimationGroups (newer glTF/GLB)
        if (animationGroups && animationGroups.length > 0) {
            const walkAnim = animationGroups.find(ag => ag.name.toLowerCase().includes("walk")) || animationGroups[0];
            walkAnim.play(true);
        } 
        // Fallback to older .babylon skeleton animations (like dummy3.babylon)
        else if (skeletons && skeletons.length > 0) {
            const skeleton = skeletons[0];
            const ranges = skeleton.getAnimationRanges();
            let walkRange = null;
            
            if (ranges && ranges.length > 0) {
                walkRange = ranges.find(r => r.name.toLowerCase().includes("walk")) || ranges[0];
            }
            
            if (walkRange) {
                scene.beginAnimation(skeleton, walkRange.from, walkRange.to, true, 1.0);
            } else {
                scene.beginAnimation(skeleton, 0, 100, true, 1.0);
            }
        }

        this.angle = 0;
        this.radius = 20; // Radius of the circle to walk in
        this.speed = 0.5;
        this.center = new BABYLON.Vector3(0, 0, 0);
    }

    update(deltaTime) {
        if (!this.pathWrapper) return;
        
        this.angle -= (this.speed * deltaTime) / 1000.0;
        
        const px = this.center.x + Math.cos(this.angle) * this.radius;
        const pz = this.center.z + Math.sin(this.angle) * this.radius;
        const py = getTerrainHeight(px, pz, currentSeed);
        
        this.pathWrapper.position = new BABYLON.Vector3(px, py, pz);
        
        // Point the pathWrapper in the direction of travel (tangent of the circle)
        const tx = this.center.x + Math.cos(this.angle - 0.1) * this.radius;
        const tz = this.center.z + Math.sin(this.angle - 0.1) * this.radius;
        const ty = getTerrainHeight(tx, tz, currentSeed);
        this.pathWrapper.lookAt(new BABYLON.Vector3(tx, ty, tz));
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
        console.log("Avatar loaded successfully!");
    } catch (e) {
        alert("Failed to load dummy3.babylon. Did you run 'cmake .. && make install'? Error: " + e.message);
        console.error("Failed to load avatar model:", e);
    }
}

function tryReload() {
    console.log("Server disconnected. Waiting for it to come back...");
    const checkServer = async () => {
        try {
            const resp = await fetch(window.location.href, { method: "HEAD" });
            if (resp.ok) {
                window.location.reload();
            } else {
                setTimeout(checkServer, 2000);
            }
        } catch (e) {
            setTimeout(checkServer, 2000);
        }
    };
    setTimeout(checkServer, 2000);
}

async function connectAndInit() {
    await initEngine();
    initScene();
    
    currentSeed = 12345;
    buildWorld(currentSeed);

    // Kick off avatar loading
    loadAvatar();

    engine.runRenderLoop(function () {
        scene.render();
        if (myAvatar) {
            myAvatar.update(engine.getDeltaTime());
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

    if (typeof WebTransport !== 'undefined') {
        try {
            console.log("Attempting WebTransport connection to", wtUrl);
            const transport = new WebTransport(wtUrl);
            
            await Promise.race([
                transport.ready,
                new Promise((_, reject) => setTimeout(() => reject(new Error("WT timeout")), 3000))
            ]);
            
            console.log("WebTransport connected!");
            
            const stream = await transport.createBidirectionalStream();
            if (stream) {
                const streamReader = stream.readable.getReader();
                const { value: data, done } = await streamReader.read();
                if (done) {
                    console.log("WT stream closed, waiting to reload...");
                    tryReload();
                } else if (data) {
                    const msg = new TextDecoder().decode(data);
                    const obj = JSON.parse(msg);
                    if (obj.seed && obj.seed !== currentSeed) {
                        currentSeed = obj.seed;
                        console.log("Received WT seed:", currentSeed);
                        buildWorld(currentSeed);
                    }
                }
            }
            connected = true;
            
            // Handle WT close
            transport.closed.then(() => {
                console.log("WT connection closed, waiting to reload...");
                tryReload();
            }).catch(() => {
                console.log("WT connection error, waiting to reload...");
                tryReload();
            });
            
        } catch (e) {
            console.warn("WebTransport connection failed or timed out:", e);
        }
    }

    if (!connected) {
        try {
            console.log("Attempting WebSocket connection to", wsUrl);
            await new Promise((resolve, reject) => {
                const ws = new WebSocket(wsUrl, "webtransport-shared-world");
                ws.onmessage = (event) => {
                    try {
                        const obj = JSON.parse(event.data);
                        if (obj.seed && obj.seed !== currentSeed) {
                            currentSeed = obj.seed;
                            console.log("Received WS seed:", currentSeed);
                            buildWorld(currentSeed);
                            connected = true;
                        }
                    } catch (e) {
                        console.error("Invalid WS message", e);
                    }
                    resolve();
                };
                ws.onerror = reject;
                ws.onclose = () => {
                    console.log("WS connection closed, waiting to reload...");
                    tryReload();
                };
                ws.onopen = () => console.log("WebSocket connected!");
                
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
