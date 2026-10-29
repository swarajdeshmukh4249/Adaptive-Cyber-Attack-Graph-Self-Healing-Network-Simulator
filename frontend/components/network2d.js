// Layered 2D topology.
//
// Zones are fixed left-to-right columns, so an attack moving inward toward the
// critical systems is literally movement across the screen. Positions are
// deterministic, which means no occlusion, no colliding labels, and the same
// picture every time you screenshot it -- the things the 3D scene cannot give.

const ZONE_COLS = [
  ['external', 'External'],
  ['perimeter', 'Perimeter'],
  ['dmz', 'DMZ'],
  ['internal', 'Internal'],
  ['atm', 'ATM'],
  ['secure', 'Secure'],
  ['critical', 'Critical'],
];

const VB_W = 1280;
const VB_H = 600;
const COL_W = 170;
const COL_X0 = 95;
const ROW_GAP = 92;
const MID_Y = 330;
const MGMT_Y = 92;
const NODE_W = 126;
const NODE_H = 44;

// Where every host sits. Pure function of the host list, so it never jitters.
function layout(hosts) {
  const pos = {};
  ZONE_COLS.forEach(([zone], ci) => {
    const inZone = hosts.filter((h) => h.zone === zone);
    const x = COL_X0 + ci * COL_W;
    inZone.forEach((h, j) => {
      const y = MID_Y - ((inZone.length - 1) * ROW_GAP) / 2 + j * ROW_GAP;
      pos[h.id] = { x, y, col: ci };
    });
  });
  // the monitoring plane watches everything, so it sits above the flow
  hosts.filter((h) => h.zone === 'mgmt').forEach((h, j) => {
    pos[h.id] = { x: COL_X0 + 3 * COL_W + j * COL_W, y: MGMT_Y, col: -1 };
  });
  return pos;
}

function edgePath(a, b) {
  if (!a || !b) return '';
  const dx = b.x - a.x;
  const curve = Math.abs(dx) < 1 ? 46 : Math.min(Math.abs(dx) * 0.28, 60);
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2 - (a.y === b.y ? 0 : curve * 0.35);
  return `M ${a.x} ${a.y} Q ${mx} ${my} ${b.x} ${b.y}`;
}

const KIND_ICON = {
  attacker: 'crosshair', cloud: 'globe', firewall: 'shield', switch: 'git-branch',
  server: 'server', db: 'database', workstation: 'monitor', atm: 'credit-card',
  critical: 'landmark', monitor: 'eye',
};

function Node2D({ h, p, selected, onSelect, onPath, predicted, priv }) {
  const color = STATUS_COLORS[h.status] || '#9ca3af';
  const standby = !!h.standby_for;
  const compromised = h.status === 'compromised';
  return (
    <g
      transform={`translate(${p.x},${p.y})`}
      className="cursor-pointer n2d-node"
      onClick={(e) => { e.stopPropagation(); onSelect(selected ? null : h.id); }}
    >
      {predicted && (
        <rect x={-NODE_W / 2 - 7} y={-NODE_H / 2 - 7} width={NODE_W + 14} height={NODE_H + 14}
              rx="12" fill="none" stroke="#f59e0b" strokeWidth="1.6"
              strokeDasharray="5 4" className="n2d-predict" />
      )}
      <rect
        x={-NODE_W / 2} y={-NODE_H / 2} width={NODE_W} height={NODE_H} rx="9"
        fill={compromised ? 'rgba(239,68,68,.16)' : 'rgba(255,255,255,.035)'}
        stroke={selected ? '#fff' : color}
        strokeWidth={selected ? 2 : onPath ? 1.7 : 1}
        strokeDasharray={standby ? '4 3' : undefined}
        className={compromised ? 'n2d-pulse' : undefined}
      />
      <circle cx={-NODE_W / 2 + 15} cy={0} r="4.5" fill={color} />
      <text x={-NODE_W / 2 + 27} y={-3} fill="#fff" fontSize="11.5" fontWeight="500">
        {h.label.length > 15 ? h.label.slice(0, 14) + '…' : h.label}
      </text>
      <text x={-NODE_W / 2 + 27} y={10} fill="rgba(255,255,255,.4)" fontSize="8.5"
            fontFamily="ui-monospace, monospace">
        {standby ? 'standby' : h.ip}
      </text>
      {priv && (
        <text x={NODE_W / 2 - 6} y={NODE_H / 2 - 5} fill="#ef4444" fontSize="7.5"
              textAnchor="end" fontFamily="ui-monospace, monospace">{priv}</text>
      )}
    </g>
  );
}

function Network2D({ state, height = 560, selected, onSelect }) {
  const hosts = state.network.hosts;
  const pos = React.useMemo(() => layout(hosts), [hosts.length]);
  const byId = React.useMemo(() => {
    const m = {}; hosts.forEach((h) => { m[h.id] = h; }); return m;
  }, [hosts]);

  const path = state.best_path || [];
  const onPath = new Set(path);
  const pathEdges = new Set();
  for (let i = 0; i < path.length - 1; i++) pathEdges.add(path[i] + '>' + path[i + 1]);
  const predicted = new Set((state.prediction || []).slice(0, 1).map((p) => p.node));
  const services = (state.services && state.services.services) || [];
  const flows = ((state.traffic && state.traffic.flows) || []).slice(0, 10);

  return (
    <div className="relative w-full bg-[#060606]" style={{ height }} onClick={() => onSelect(null)}>
     <div className="h-full w-full lg:pr-[186px]">
      <div className="relative h-full w-full">
      <svg viewBox={`0 0 ${VB_W} ${VB_H}`} className="w-full h-full" preserveAspectRatio="xMidYMid meet">
        <defs>
          <marker id="n2d-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
            <path d="M0,0 L7,3.5 L0,7 z" fill="rgba(239,68,68,.85)" />
          </marker>
        </defs>

        {/* zone bands give the diagram a fixed reading order */}
        {ZONE_COLS.map(([zone, label], i) => (
          <g key={zone}>
            <rect x={COL_X0 + i * COL_W - COL_W / 2 + 8} y={132}
                  width={COL_W - 16} height={VB_H - 170} rx="12"
                  fill={zone === 'critical' ? 'rgba(239,68,68,.045)' : 'rgba(255,255,255,.016)'}
                  stroke="rgba(255,255,255,.05)" />
            <text x={COL_X0 + i * COL_W} y={152} textAnchor="middle"
                  fill="rgba(255,255,255,.34)" fontSize="9.5"
                  letterSpacing="2.2">{label.toUpperCase()}</text>
          </g>
        ))}

        {/* links */}
        {state.network.links.map((l, i) => {
          const a = pos[l.source], b = pos[l.target];
          if (!a || !b) return null;
          const hot = pathEdges.has(l.source + '>' + l.target) || pathEdges.has(l.target + '>' + l.source);
          return (
            <path
              key={i} d={edgePath(a, b)} fill="none"
              stroke={l.cut ? 'rgba(239,68,68,.25)' : hot ? 'rgba(239,68,68,.8)' : 'rgba(255,255,255,.12)'}
              strokeWidth={hot ? 2.2 : 1}
              strokeDasharray={l.cut ? '3 5' : undefined}
              markerEnd={hot ? 'url(#n2d-arrow)' : undefined}
              className={hot ? 'n2d-flow' : undefined}
            />
          );
        })}

        {/* live packets: grey = benign, red = hostile. Re-keyed each tick so every
            tick launches a fresh wave. */}
        {flows.map((f, i) => {
          const a = pos[f.src], b = pos[f.dst];
          if (!a || !b) return null;
          const d = edgePath(a, b);
          const hostile = !!f.label;
          return (
            <circle key={`${state.tick}-${i}`} r={hostile ? 3.4 : 2.4}
                    fill={hostile ? '#ef4444' : f.flagged ? '#f59e0b' : 'rgba(255,255,255,.55)'}
                    opacity={hostile ? 0.95 : 0.5}>
              <animateMotion dur={`${1.1 + (i % 4) * 0.22}s`} begin={`${(i % 5) * 0.12}s`}
                             repeatCount="1" fill="freeze" path={d} />
              <animate attributeName="opacity" values="0;1;1;0" dur={`${1.1 + (i % 4) * 0.22}s`}
                       begin={`${(i % 5) * 0.12}s`} repeatCount="1" fill="freeze" />
            </circle>
          );
        })}

        {hosts.map((h) => {
          const p = pos[h.id];
          if (!p) return null;
          return (
            <Node2D key={h.id} h={h} p={p} selected={selected === h.id} onSelect={onSelect}
                    onPath={onPath.has(h.id)} predicted={predicted.has(h.id)}
                    priv={(state.privileges || {})[h.id]} />
          );
        })}

      {/* Service chips. Rendered INSIDE the svg so they share the viewBox
          coordinate system -- an HTML overlay drifts out of alignment because the
          svg letterboxes. A CSS transform transition makes a chip visibly slide
          from one server to another when its workload fails over. */}
      <g>
        {services.map((s) => {
          const p = pos[s.host];
          if (!p) return null;
          const peers = services.filter((x) => x.host === s.host);
          const idx = peers.findIndex((x) => x.id === s.id);
          const w = s.id.length * 4.3 + 9;
          const cx = p.x - NODE_W / 2 + 2 + (idx % 2) * 64;
          const cy = p.y + NODE_H / 2 + 4 + Math.floor(idx / 2) * 15;
          const tone = s.status === 'failing_over' ? ['rgba(56,189,248,.3)', '#7dd3fc', '#e0f2fe']
            : s.status === 'degraded' ? ['rgba(245,158,11,.25)', '#fcd34d', '#fef3c7']
            : s.status === 'down' ? ['rgba(239,68,68,.3)', '#fca5a5', '#fee2e2']
            : ['rgba(255,255,255,.1)', 'rgba(255,255,255,.22)', 'rgba(255,255,255,.72)'];
          return (
            <g key={s.id} className="n2d-chip"
               style={{ transform: `translate(${cx}px, ${cy}px)` }}>
              <title>{`${s.label} — ${s.status} on ${s.host}`}</title>
              <rect width={w} height="12" rx="3" fill={tone[0]} stroke={tone[1]} strokeWidth="0.7" />
              <text x={w / 2} y="8.6" textAnchor="middle" fill={tone[2]} fontSize="7.2"
                    fontFamily="ui-monospace, monospace">{s.id}</text>
            </g>
          );
        })}
      </g>
      </svg>
      </div>
     </div>
    </div>
  );
}
