// Interactive 3D network: hosts as glowing shapes, live traffic particles,
// predicted attack path as animated arcs, status effects (breach shockwave,
// isolation cage, healing ring, predicted-target reticle).

const N3D_COLORS = {
  normal: 0xd4d4d4, compromised: 0xef4444, isolated: 0x94a3b8, healing: 0x10b981, attacker: 0xef4444,
};
const N3D_KIND_TINT = { firewall: 0x94a3b8, switch: 0x94a3b8, cloud: 0x64748b, monitor: 0x94a3b8, critical: 0xe2e8f0 };

function n3dGlowTexture() {
  const c = document.createElement('canvas');
  c.width = c.height = 128;
  const g = c.getContext('2d');
  const grd = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  grd.addColorStop(0, 'rgba(255,255,255,1)');
  grd.addColorStop(0.25, 'rgba(255,255,255,.55)');
  grd.addColorStop(1, 'rgba(255,255,255,0)');
  g.fillStyle = grd;
  g.fillRect(0, 0, 128, 128);
  return new THREE.CanvasTexture(c);
}

function n3dLabel(text, sub) {
  const c = document.createElement('canvas');
  c.width = 512; c.height = 128;
  const g = c.getContext('2d');
  g.font = '600 46px Inter, sans-serif';
  g.textAlign = 'center';
  g.shadowColor = 'rgba(0,0,0,.8)';
  g.shadowBlur = 16;
  g.fillStyle = '#e6edff';
  g.fillText(text, 256, 56);
  if (sub) {
    g.shadowBlur = 0;
    g.font = '400 30px JetBrains Mono, monospace';
    g.fillStyle = '#8b98ad';
    g.fillText(sub, 256, 104);
  }
  const tex = new THREE.CanvasTexture(c);
  const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
  sp.scale.set(3.2, 0.8, 1);
  return sp;
}

function n3dGeometry(kind) {
  switch (kind) {
    case 'attacker': return new THREE.TetrahedronGeometry(0.6);
    case 'cloud': return new THREE.SphereGeometry(0.5, 24, 16);
    case 'firewall': return new THREE.BoxGeometry(0.95, 0.6, 0.4);
    case 'switch': return new THREE.CylinderGeometry(0.6, 0.6, 0.24, 28);
    case 'db': return new THREE.CylinderGeometry(0.42, 0.42, 0.8, 28);
    case 'workstation': return new THREE.BoxGeometry(0.7, 0.48, 0.16);
    case 'atm': return new THREE.BoxGeometry(0.46, 0.88, 0.36);
    case 'critical': return new THREE.OctahedronGeometry(0.65);
    case 'monitor': return new THREE.TorusKnotGeometry(0.28, 0.09, 64, 8);
    default: return new THREE.BoxGeometry(0.52, 0.82, 0.52);
  }
}

function Network3D({ state, height = 520, onSelect, selected, showLabels = true, autoRotate = true }) {
  const mountRef = React.useRef(null);
  const ctxRef = React.useRef(null);
  const [hover, setHover] = React.useState(null);
  const onSelectRef = React.useRef(onSelect);
  onSelectRef.current = onSelect;

  // ------------------------------------------------------------ scene setup (once)
  React.useEffect(() => {
    if (!window.THREE) return;
    const mount = mountRef.current;
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mount.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x0a0d14, 0.028);
    const camera = new THREE.PerspectiveCamera(48, 1, 0.1, 400);
    camera.position.set(2, 9, 21);

    const controls = new THREE.OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.06;
    controls.autoRotate = autoRotate;
    controls.autoRotateSpeed = 0.55;
    controls.enableZoom = false;
    controls.minDistance = 8;
    controls.maxDistance = 40;
    controls.target.set(0, -0.5, 0);
    let resumeTimer;
    controls.addEventListener('start', () => { controls.autoRotate = false; clearTimeout(resumeTimer); });
    controls.addEventListener('end', () => { resumeTimer = setTimeout(() => { controls.autoRotate = autoRotate; }, 5000); });

    scene.add(new THREE.AmbientLight(0x6688ff, 0.55));
    const p1 = new THREE.PointLight(0xdbe7ff, 1.2, 60); p1.position.set(0, 12, 10); scene.add(p1);
    const p2 = new THREE.PointLight(0x64748b, 0.8, 60); p2.position.set(-12, 6, -10); scene.add(p2);
    const p3 = new THREE.PointLight(0xf43f5e, 0.0, 30); p3.position.set(0, 4, 0); scene.add(p3);

    // floor grid + radar sweep
    const grid = new THREE.GridHelper(44, 44, 0x334155, 0x1e293b);
    grid.position.y = -5.2;
    grid.material.transparent = true;
    grid.material.opacity = 0.28;
    scene.add(grid);
    const radar = new THREE.Mesh(
      new THREE.CircleGeometry(16, 64, 0, Math.PI / 7),
      new THREE.MeshBasicMaterial({ color: 0xd4d4d4, transparent: true, opacity: 0.05, side: THREE.DoubleSide, depthWrite: false })
    );
    radar.rotation.x = -Math.PI / 2;
    radar.position.y = -5.15;
    scene.add(radar);
    for (let r = 4; r <= 16; r += 4) {
      const ring = new THREE.Mesh(
        new THREE.RingGeometry(r - 0.03, r, 96),
        new THREE.MeshBasicMaterial({ color: 0x334155, transparent: true, opacity: 0.5, side: THREE.DoubleSide })
      );
      ring.rotation.x = -Math.PI / 2;
      ring.position.y = -5.14;
      scene.add(ring);
    }

    // starfield
    const starGeo = new THREE.BufferGeometry();
    const starPos = new Float32Array(1500 * 3);
    for (let i = 0; i < 1500; i++) {
      const r = 40 + Math.random() * 60;
      const th = Math.random() * Math.PI * 2;
      const ph = Math.acos(2 * Math.random() - 1);
      starPos[i * 3] = r * Math.sin(ph) * Math.cos(th);
      starPos[i * 3 + 1] = r * Math.cos(ph);
      starPos[i * 3 + 2] = r * Math.sin(ph) * Math.sin(th);
    }
    starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
    const stars = new THREE.Points(starGeo, new THREE.PointsMaterial({ color: 0xcbd5e1, size: 0.12, transparent: true, opacity: 0.4 }));
    scene.add(stars);

    const glowTex = n3dGlowTexture();
    const ctx = {
      renderer, scene, camera, controls, glowTex, p3,
      nodes: {}, links: {}, arcs: new THREE.Group(), particles: [], pickables: [],
      clock: new THREE.Clock(), lastTick: -1, pathKey: '',
    };
    scene.add(ctx.arcs);
    ctxRef.current = ctx;

    // picking
    const ray = new THREE.Raycaster();
    const mouse = new THREE.Vector2();
    const pick = (e) => {
      const r = renderer.domElement.getBoundingClientRect();
      mouse.x = ((e.clientX - r.left) / r.width) * 2 - 1;
      mouse.y = -((e.clientY - r.top) / r.height) * 2 + 1;
      ray.setFromCamera(mouse, camera);
      const hit = ray.intersectObjects(ctx.pickables, false)[0];
      return { id: hit ? hit.object.userData.id : null, x: e.clientX - r.left, y: e.clientY - r.top };
    };
    const onMove = (e) => {
      const p = pick(e);
      renderer.domElement.style.cursor = p.id ? 'pointer' : 'grab';
      setHover(p.id ? p : null);
    };
    const onClick = (e) => { const p = pick(e); if (p.id && onSelectRef.current) onSelectRef.current(p.id); };
    renderer.domElement.addEventListener('pointermove', onMove);
    renderer.domElement.addEventListener('click', onClick);
    renderer.domElement.addEventListener('pointerleave', () => setHover(null));

    const resize = () => {
      const w = mount.clientWidth;
      const h = mount.clientHeight;
      renderer.setSize(w, h);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    };
    const ro = new ResizeObserver(resize);
    ro.observe(mount);
    resize();

    // ---------------------------------------------------------- animation loop
    let raf;
    const loop = () => {
      const dt = Math.min(ctx.clock.getDelta(), 0.05);
      const t = ctx.clock.elapsedTime;
      radar.rotation.z -= dt * 0.9;
      stars.rotation.y += dt * 0.01;
      Object.values(ctx.nodes).forEach((n, i) => {
        const s = n.status;
        n.group.position.y = n.base.y + Math.sin(t * 1.3 + i) * 0.09;
        n.shell.rotation.y += dt * 0.5;
        n.shell.rotation.x += dt * 0.2;
        n.core.rotation.y += dt * (s === 'compromised' ? 2.2 : 0.4);
        const pulse = s === 'compromised' ? 1 + 0.18 * Math.sin(t * 7) : s === 'healing' ? 1 + 0.08 * Math.sin(t * 3) : 1;
        n.core.scale.setScalar(pulse);
        n.halo.material.opacity = (s === 'compromised' ? 0.75 + 0.25 * Math.sin(t * 7) : 0.45) * (n.selected ? 1.4 : 1);
        n.halo.scale.setScalar((n.selected ? 3.4 : 2.6) * (s === 'compromised' ? 1.2 : 1));
        // breach shockwave
        if (s === 'compromised') {
          const k = (t * 0.9 + i * 0.13) % 1;
          n.wave.visible = true;
          n.wave.scale.setScalar(0.6 + k * 3.2);
          n.wave.material.opacity = 0.8 * (1 - k);
        } else n.wave.visible = false;
        n.cage.visible = s === 'isolated';
        if (n.cage.visible) { n.cage.rotation.y += dt * 0.8; n.cage.material.opacity = 0.55 + 0.3 * Math.sin(t * 4); }
        n.heal.visible = s === 'healing';
        if (n.heal.visible) { n.heal.rotation.z += dt * 3; n.heal.position.y = Math.sin(t * 2.5) * 0.5; }
        n.target.visible = n.predicted;
        if (n.predicted) { n.target.rotation.z -= dt * 1.6; n.target.scale.setScalar(1 + 0.15 * Math.sin(t * 5)); }
      });
      // attack arcs comets
      ctx.arcs.children.forEach((obj) => {
        if (obj.userData.curve) {
          obj.userData.t = (obj.userData.t + dt * obj.userData.speed) % 1;
          obj.position.copy(obj.userData.curve.getPoint(obj.userData.t));
        } else if (obj.material && obj.userData.tube) {
          obj.material.opacity = 0.55 + 0.35 * Math.sin(t * 6);
        }
      });
      // traffic particles
      ctx.particles = ctx.particles.filter((p) => {
        p.t += dt / p.dur;
        if (p.t >= 1) { scene.remove(p.sprite); p.sprite.material.dispose(); return false; }
        const tt = Math.max(0, p.t);
        p.sprite.position.copy(p.curve.getPoint(tt));
        p.sprite.material.opacity = Math.sin(tt * Math.PI);
        return true;
      });
      ctx.p3.intensity = ctx.alarm ? 1.6 + Math.sin(t * 8) : 0;
      controls.update();
      renderer.render(scene, camera);
      raf = requestAnimationFrame(loop);
    };
    loop();

    return () => {
      cancelAnimationFrame(raf);
      clearTimeout(resumeTimer);
      ro.disconnect();
      controls.dispose();
      renderer.dispose();
      scene.traverse((o) => {
        if (o.geometry) o.geometry.dispose();
        if (o.material) (Array.isArray(o.material) ? o.material : [o.material]).forEach((m) => { if (m.map) m.map.dispose(); m.dispose(); });
      });
      if (renderer.domElement.parentNode) renderer.domElement.parentNode.removeChild(renderer.domElement);
    };
  }, []);

  // ------------------------------------------------------------ sync with simulation state
  React.useEffect(() => {
    const ctx = ctxRef.current;
    if (!ctx || !state) return;
    const { scene, glowTex } = ctx;
    const hosts = state.network.hosts;
    const posOf = (id) => ctx.nodes[id] ? ctx.nodes[id].group.position : new THREE.Vector3();

    // build nodes once
    if (!Object.keys(ctx.nodes).length) {
      hosts.forEach((h) => {
        const group = new THREE.Group();
        const base = new THREE.Vector3(h.pos[0] * 1.15, h.pos[1], h.pos[2] * 1.15);
        group.position.copy(base);
        const color = N3D_KIND_TINT[h.kind] || N3D_COLORS[h.status] || N3D_COLORS.normal;
        const core = new THREE.Mesh(n3dGeometry(h.kind), new THREE.MeshStandardMaterial({
          color, emissive: color, emissiveIntensity: 0.55, metalness: 0.6, roughness: 0.25,
        }));
        core.userData.id = h.id;
        const shell = new THREE.Mesh(new THREE.IcosahedronGeometry(0.95, 1),
          new THREE.MeshBasicMaterial({ color, wireframe: true, transparent: true, opacity: 0.16 }));
        const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, color, transparent: true, opacity: 0.45, blending: THREE.AdditiveBlending, depthWrite: false }));
        halo.scale.setScalar(2.6);
        const wave = new THREE.Mesh(new THREE.RingGeometry(0.9, 1.0, 48),
          new THREE.MeshBasicMaterial({ color: 0xf43f5e, transparent: true, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }));
        wave.rotation.x = -Math.PI / 2;
        wave.visible = false;
        const cage = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(1.7, 1.7, 1.7)),
          new THREE.LineBasicMaterial({ color: 0x94a3b8, transparent: true, opacity: 0.8 }));
        cage.visible = false;
        const heal = new THREE.Mesh(new THREE.TorusGeometry(1.05, 0.05, 8, 64),
          new THREE.MeshBasicMaterial({ color: 0x22c55e, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending }));
        heal.rotation.x = Math.PI / 2;
        heal.visible = false;
        const target = new THREE.Mesh(new THREE.RingGeometry(1.25, 1.4, 4, 1),
          new THREE.MeshBasicMaterial({ color: 0xf59e0b, transparent: true, opacity: 0.9, side: THREE.DoubleSide, blending: THREE.AdditiveBlending }));
        target.visible = false;
        group.add(core, shell, halo, wave, cage, heal, target);
        if (showLabels) {
          const label = n3dLabel(h.label, h.ip);
          label.position.y = 1.35;
          group.add(label);
        }
        scene.add(group);
        ctx.pickables.push(core);
        ctx.nodes[h.id] = { group, core, shell, halo, wave, cage, heal, target, base, kind: h.kind, status: h.status };
      });
      state.network.links.forEach((l) => {
        const geo = new THREE.BufferGeometry().setFromPoints([posOf(l.source).clone(), posOf(l.target).clone()]);
        const line = new THREE.Line(geo, new THREE.LineBasicMaterial({ color: 0x475569, transparent: true, opacity: 0.5 }));
        scene.add(line);
        ctx.links[l.source + '|' + l.target] = line;
      });
    }

    // statuses
    const predicted = new Set((state.prediction || []).slice(0, 1).map((p) => p.node));
    hosts.forEach((h) => {
      const n = ctx.nodes[h.id];
      if (!n) return;
      n.status = h.status;
      n.predicted = predicted.has(h.id);
      n.selected = selected === h.id;
      const c = h.status === 'normal' ? (N3D_KIND_TINT[h.kind] || N3D_COLORS.normal) : N3D_COLORS[h.status];
      n.core.material.color.setHex(c);
      n.core.material.emissive.setHex(c);
      n.core.material.emissiveIntensity = h.status === 'compromised' ? 1.1 : 0.55;
      n.shell.material.color.setHex(c);
      n.halo.material.color.setHex(c);
    });
    state.network.links.forEach((l) => {
      const line = ctx.links[l.source + '|' + l.target];
      if (!line) return;
      const bad = [l.source, l.target].some((id) => state.compromised.includes(id));
      line.material.color.setHex(l.cut ? 0x334155 : bad ? 0xef4444 : 0x475569);
      line.material.opacity = l.cut ? 0.08 : bad ? 0.7 : 0.32;
    });
    ctx.alarm = state.compromised.length > 0;

    // predicted attack path arcs (rebuild only when the path changes)
    const path = state.best_path || [];
    const key = path.join('>');
    if (key !== ctx.pathKey) {
      ctx.pathKey = key;
      ctx.arcs.children.slice().forEach((o) => { ctx.arcs.remove(o); o.geometry && o.geometry.dispose(); o.material && o.material.dispose(); });
      for (let i = 0; i < path.length - 1; i++) {
        const a = posOf(path[i]).clone();
        const b = posOf(path[i + 1]).clone();
        const mid = a.clone().add(b).multiplyScalar(0.5);
        mid.y += 2.2 + a.distanceTo(b) * 0.15;
        const curve = new THREE.QuadraticBezierCurve3(a, mid, b);
        const tube = new THREE.Mesh(new THREE.TubeGeometry(curve, 48, 0.045, 8, false),
          new THREE.MeshBasicMaterial({ color: 0xef4444, transparent: true, opacity: 0.8, blending: THREE.AdditiveBlending, depthWrite: false }));
        tube.userData.tube = true;
        ctx.arcs.add(tube);
        for (let k = 0; k < 3; k++) {
          const comet = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, color: 0xfca5a5, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }));
          comet.scale.setScalar(0.7);
          comet.userData = { curve, t: k / 3, speed: 0.55 };
          ctx.arcs.add(comet);
        }
      }
    }

    // traffic particles for this tick
    if (state.tick !== ctx.lastTick) {
      ctx.lastTick = state.tick;
      (state.traffic.flows || []).forEach((f, i) => {
        if (!ctx.nodes[f.src] || !ctx.nodes[f.dst]) return;
        const a = posOf(f.src).clone();
        const b = posOf(f.dst).clone();
        const mid = a.clone().add(b).multiplyScalar(0.5);
        mid.y += 0.6 + Math.random() * 0.8;
        const color = f.flagged ? 0xf59e0b : f.label ? 0xef4444 : 0xd4d4d4;
        const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, color, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }));
        sp.scale.setScalar(f.flagged ? 0.75 : 0.45);
        sp.position.copy(a);
        scene.add(sp);
        ctx.particles.push({ sprite: sp, curve: new THREE.QuadraticBezierCurve3(a, mid, b), t: -i * 0.04, dur: 0.8 + Math.random() * 0.5 });
      });
    }
  }, [state, selected, showLabels]);

  const hh = hover && state && state.network.hosts.find((h) => h.id === hover.id);
  return (
    <div className="scene-wrap" style={{ height }}>
      <div ref={mountRef} className="absolute inset-0" />
      {!window.THREE && <div className="absolute inset-0 grid place-items-center text-slate-400">WebGL library failed to load.</div>}
      <span className="hud-corner hud-tl" /><span className="hud-corner hud-tr" />
      <span className="hud-corner hud-bl" /><span className="hud-corner hud-br" />
      {hh && (
        <div className="scene-tooltip" style={{ left: hover.x, top: hover.y }}>
          <div className="flex items-center gap-2 mb-1">
            <Icon name={(KIND_ICONS[hh.kind] || 'icon-server').replace('icon-', '')} className="text-white" />
            <b className="text-white">{hh.label}</b>
          </div>
          <div className="mono text-[11px] text-slate-400">{hh.ip} · {hh.zone}</div>
          <div className="mt-1.5 flex items-center gap-2">
            <Pill color={STATUS_COLORS[hh.status] || '#d4d4d4'}>{hh.status}</Pill>
            {state.risk[hh.id] != null && <span className="mono text-[11px] text-amber-300">risk {state.risk[hh.id].toFixed(2)}</span>}
          </div>
          {hh.vulns.length > 0 && (
            <div className="mt-1.5 text-[11px] text-slate-300">
              {hh.vulns.map((v) => (
                <div key={v.cve} className={v.patched ? 'line-through text-slate-500' : ''}>{v.cve} · p={v.exploitability}</div>
              ))}
            </div>
          )}
          <div className="mt-1 text-[10px] text-white/80">click to inspect</div>
        </div>
      )}
    </div>
  );
}
