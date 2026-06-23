/**
 * BIGIL — Three.js Premium Particle Network Background
 * Floating cyber nodes connected by data-flow edges.
 * Capped at 300 particles, pauses when tab is hidden.
 */

(function () {
  'use strict';

  const canvas = document.getElementById('three-canvas');
  if (!canvas || typeof THREE === 'undefined') return;

  // ── Scene Setup ───────────────────────────────────────────────────────────
  const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(window.innerWidth, window.innerHeight);
  renderer.setClearColor(0x000000, 0);

  const scene  = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 1000);
  camera.position.z = 28;

  // ── Particles ─────────────────────────────────────────────────────────────
  const PARTICLE_COUNT = 280;
  const FIELD_SIZE = 36;

  const positions = new Float32Array(PARTICLE_COUNT * 3);
  const colors    = new Float32Array(PARTICLE_COUNT * 3);
  const velocities = [];

  const palette = [
    new THREE.Color(0xe8e8e8), // neon white
    new THREE.Color(0x9b9b9b), // grey
    new THREE.Color(0xc0c0c0), // silver
    new THREE.Color(0x4a4a4a), // dim grey
    new THREE.Color(0xffffff), // bright neon
  ];

  for (let i = 0; i < PARTICLE_COUNT; i++) {
    const i3 = i * 3;
    positions[i3]     = (Math.random() - 0.5) * FIELD_SIZE;
    positions[i3 + 1] = (Math.random() - 0.5) * FIELD_SIZE;
    positions[i3 + 2] = (Math.random() - 0.5) * FIELD_SIZE;

    const col = palette[Math.floor(Math.random() * palette.length)];
    colors[i3]     = col.r;
    colors[i3 + 1] = col.g;
    colors[i3 + 2] = col.b;

    velocities.push(
      (Math.random() - 0.5) * 0.012,
      (Math.random() - 0.5) * 0.012,
      (Math.random() - 0.5) * 0.006
    );
  }

  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
  geo.setAttribute('color',    new THREE.BufferAttribute(colors, 3));

  const mat = new THREE.PointsMaterial({
    size: 0.18,
    vertexColors: true,
    transparent: true,
    opacity: 0.75,
    sizeAttenuation: true,
    depthWrite: false
  });

  const points = new THREE.Points(geo, mat);
  scene.add(points);

  // ── Intelligence Hub Node (core network graph) ───────────────────────────────
  const HUB_COUNT = 6;
  const hubNodes = [];
  const hubRadius = 5;
  for (let i = 0; i < HUB_COUNT; i++) {
    const angle = (i / HUB_COUNT) * Math.PI * 2;
    const geo = new THREE.SphereGeometry(0.25, 8, 8);
    const mat = new THREE.MeshBasicMaterial({
      color: i === 0 ? 0xffffff : 0x9b9b9b,
      transparent: true,
      opacity: 0.6
    });
    const node = new THREE.Mesh(geo, mat);
    node.position.set(Math.cos(angle) * hubRadius, Math.sin(angle) * hubRadius * 0.6, -4);
    scene.add(node);
    hubNodes.push(node);
  }
  const coreGeo = new THREE.SphereGeometry(0.45, 12, 12);
  const coreMat = new THREE.MeshBasicMaterial({ color: 0xe8e8e8, transparent: true, opacity: 0.5 });
  const coreNode = new THREE.Mesh(coreGeo, coreMat);
  coreNode.position.set(0, 0, -4);
  scene.add(coreNode);

  const hubLines = [];
  for (let i = 0; i < HUB_COUNT; i++) {
    const pts = new Float32Array([0, 0, -4,
      hubNodes[i].position.x, hubNodes[i].position.y, hubNodes[i].position.z]);
    const lGeo = new THREE.BufferGeometry();
    lGeo.setAttribute('position', new THREE.BufferAttribute(pts, 3));
    const line = new THREE.Line(lGeo, new THREE.LineBasicMaterial({
      color: 0xc0c0c0, transparent: true, opacity: 0.15
    }));
    scene.add(line);
    hubLines.push(line);
  }

  // ── Connection Lines ───────────────────────────────────────────────────────
  const lineGeo     = new THREE.BufferGeometry();
  const MAX_LINES   = 400;
  const linePositions = new Float32Array(MAX_LINES * 6);
  const lineOpacities = new Float32Array(MAX_LINES);

  lineGeo.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));

  const lineMat = new THREE.LineSegments(
    lineGeo,
    new THREE.LineBasicMaterial({ color: 0x9b9b9b, transparent: true, opacity: 0.06, depthWrite: false })
  );
  scene.add(lineMat);

  // ── Mouse Interaction ──────────────────────────────────────────────────────
  let mouseX = 0, mouseY = 0;
  document.addEventListener('mousemove', (e) => {
    mouseX = (e.clientX / window.innerWidth  - 0.5) * 2;
    mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
  });

  // ── Resize ─────────────────────────────────────────────────────────────────
  window.addEventListener('resize', () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
  });

  // ── Animation Loop ─────────────────────────────────────────────────────────
  let frameId;
  let isHidden = false;
  document.addEventListener('visibilitychange', () => {
    isHidden = document.hidden;
    if (!isHidden) animate();
  });

  const LINK_DIST_SQ = 7 * 7; // squared for performance
  let lineCount = 0;
  let tick = 0;

  function animate() {
    tick++;
    if (isHidden) return;
    frameId = requestAnimationFrame(animate);

    const posArr = geo.attributes.position.array;
    lineCount = 0;

    // Update particle positions
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const i3 = i * 3;
      const v3 = i * 3;

      posArr[i3]     += velocities[v3];
      posArr[i3 + 1] += velocities[v3 + 1];
      posArr[i3 + 2] += velocities[v3 + 2];

      const half = FIELD_SIZE / 2;
      if (Math.abs(posArr[i3])     > half) velocities[v3]     *= -1;
      if (Math.abs(posArr[i3 + 1]) > half) velocities[v3 + 1] *= -1;
      if (Math.abs(posArr[i3 + 2]) > half) velocities[v3 + 2] *= -1;
    }

    // Build connection lines (only between nearby particles, skip if enough)
    const linePosArr = lineGeo.attributes.position.array;
    for (let i = 0; i < PARTICLE_COUNT && lineCount < MAX_LINES; i++) {
      for (let j = i + 1; j < PARTICLE_COUNT && lineCount < MAX_LINES; j++) {
        const dx = posArr[i*3]   - posArr[j*3];
        const dy = posArr[i*3+1] - posArr[j*3+1];
        const dz = posArr[i*3+2] - posArr[j*3+2];
        const distSq = dx*dx + dy*dy + dz*dz;
        if (distSq < LINK_DIST_SQ) {
          const base = lineCount * 6;
          linePosArr[base]   = posArr[i*3];   linePosArr[base+1] = posArr[i*3+1]; linePosArr[base+2] = posArr[i*3+2];
          linePosArr[base+3] = posArr[j*3];   linePosArr[base+4] = posArr[j*3+1]; linePosArr[base+5] = posArr[j*3+2];
          lineCount++;
        }
      }
    }

    geo.attributes.position.needsUpdate = true;
    lineGeo.attributes.position.needsUpdate = true;
    lineGeo.setDrawRange(0, lineCount * 2);

    // Subtle camera drift following mouse
    camera.position.x += (mouseX * 3 - camera.position.x) * 0.02;
    camera.position.y += (-mouseY * 2 - camera.position.y) * 0.02;
    camera.lookAt(scene.position);

    // Slow rotation
    points.rotation.y += 0.0008;
    lineMat.rotation.y += 0.0008;
    coreNode.rotation.y += 0.004;
    hubNodes.forEach((n, i) => {
      const a = (i / HUB_COUNT) * Math.PI * 2 + tick * 0.001;
      n.position.x = Math.cos(a) * hubRadius;
      n.position.y = Math.sin(a) * hubRadius * 0.6;
    });

    renderer.render(scene, camera);
  }

  animate();

})();
