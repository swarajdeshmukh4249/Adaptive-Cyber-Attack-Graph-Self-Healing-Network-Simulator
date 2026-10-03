// Section 2: Attack Graph Construction - directed graph of possible attacker movement.

const AG_LAYOUT = {
  attacker: [60, 210],
  web: [210, 120], mail: [210, 300],
  user1: [380, 90], user2: [380, 210], user3: [380, 330],
  db: [560, 110], admin: [560, 230], backup: [560, 350],
  atm1: [740, 60], core: [760, 220], atm2: [740, 370],
};

function AttackGraphSVG({ state }) {
  const hosts = Object.fromEntries(state.network.hosts.map((h) => [h.id, h]));
  const path = state.best_path || [];
  const onPath = new Set(path.slice(0, -1).map((n, i) => n + '>' + path[i + 1]));
  const comp = new Set(['attacker', ...state.compromised]);
  const next = state.prediction && state.prediction[0] ? state.prediction[0].node : null;
  const edges = state.attack_graph.edges.filter((e) => AG_LAYOUT[e.source] && AG_LAYOUT[e.target]);
  const R = 24;
  const geom = (e) => {
    const [x1, y1] = AG_LAYOUT[e.source];
    const [x2, y2] = AG_LAYOUT[e.target];
    const dx = x2 - x1, dy = y2 - y1;
    const len = Math.hypot(dx, dy) || 1;
    const ux = dx / len, uy = dy / len;
    const bend = 0.18 * len;
    const cx = (x1 + x2) / 2 - uy * bend, cy = (y1 + y2) / 2 + ux * bend;
    const sx = x1 + ux * R, sy = y1 + uy * R;
    const ex = x2 - ux * (R + 6), ey = y2 - uy * (R + 6);
    return `M${sx},${sy} Q${cx},${cy} ${ex},${ey}`;
  };
  const style = (e) => {
    const k = e.source + '>' + e.target;
    if (onPath.has(k)) return { stroke: '#ef4444', width: 3.2, cls: 'dash-flow-fast', marker: 'agRed', op: 1 };
    if (comp.has(e.source) && e.target === next) return { stroke: '#f59e0b', width: 2.4, cls: 'dash-flow', marker: 'agYellow', op: 1 };
    if (comp.has(e.source)) return { stroke: '#f59e0b', width: 1.6, cls: '', marker: 'agOrange', op: 0.75 };
    return { stroke: '#64748b', width: 1, cls: '', marker: 'agGrey', op: 0.28 };
  };
  const sorted = [...edges].sort((a, b) => style(a).width - style(b).width);
  return (
    <svg viewBox="0 0 830 420" className="w-full h-auto">
      <defs>
        {[['agRed', '#ef4444'], ['agYellow', '#f59e0b'], ['agOrange', '#f59e0b'], ['agGrey', '#64748b']].map(([id, c]) => (
          <marker key={id} id={id} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill={c} />
          </marker>
        ))}
      </defs>
      {['External', 'DMZ', 'Internal', 'Secure', 'Critical / ATM'].map((z, i) => (
        <g key={z}>
          <rect x={[20, 160, 330, 505, 690][i]} y="10" width={[85, 105, 105, 110, 125][i]} height="400" rx="14" fill="rgba(148,163,184,.035)" stroke="rgba(148,163,184,.08)" />
          <text x={[62, 212, 382, 560, 752][i]} y="28" textAnchor="middle" fontSize="10" fill="#64748b" letterSpacing="2">{z.toUpperCase()}</text>
        </g>
      ))}
      {sorted.map((e) => {
        const s = style(e);
        return (
          <path key={e.source + e.target} d={geom(e)} fill="none" stroke={s.stroke} strokeWidth={s.width} opacity={s.op}
            className={s.cls} markerEnd={`url(#${s.marker})`} style={{ transition: 'stroke .4s, opacity .4s' }}>
            <title>{`${e.source} → ${e.target}: ${e.technique} (p=${e.p})`}</title>
          </path>
        );
      })}
      {Object.entries(AG_LAYOUT).map(([id, [x, y]]) => hosts[id] && (
        <SvgHost key={id} x={x} y={y} host={hosts[id]} r={R}
          ring={id === next ? '#f59e0b' : id === 'core' ? '#f59e0b' : null}
          dim={!state.attack_graph.nodes.includes(id)} />
      ))}
    </svg>
  );
}

function SectionAttackGraph({ state }) {
  const c = state.campaign;
  const stage = c ? c.stage : -1;
  const dm = state.dm;
  return (
    <Section id="attack-graph" num={2} title="Attack Graph Construction" color="green" icon="share-2"
      subtitle="The network is modelled as a directed graph where nodes are hosts/services and edges are possible attacker movements (reachability × unpatched vulnerability). It is rebuilt automatically after every defensive action.">
      <div className="grid xl:grid-cols-[1fr_300px] gap-4">
        <SubPanel title="Cyber attack graph (directed)" icon="workflow" color="#10b981"
          right={<span className="mono text-[11px] text-slate-400">|E| = <span className="text-emerald-300">{dm.graphs.attack_edges}</span> · paths = <span className="text-red-300">{dm.combinatorics.paths.toLocaleString()}</span></span>}>
          <AttackGraphSVG state={state} />
          <div className="mt-2 flex flex-wrap gap-4 text-[12px] text-slate-400">
            <span className="flex items-center gap-2"><span className="h-0.5 w-6 bg-red-500" /> most-probable attack path</span>
            <span className="flex items-center gap-2"><span className="h-0.5 w-6 bg-amber-400" /> predicted next move</span>
            <span className="flex items-center gap-2"><span className="h-0.5 w-6 bg-amber-400" /> edge from compromised node</span>
            <span className="flex items-center gap-2"><span className="h-0.5 w-6 bg-slate-500" /> possible movement</span>
          </div>
        </SubPanel>
        <div className="space-y-4">
          <SubPanel title="Example attack path" icon="route" color="#ef4444" className="border-red-500/30">
            <ol className="space-y-1.5">
              {state.kill_chain.map((s, i) => (
                <li key={s} className={cn('flex items-center gap-2 text-[13px] rounded-lg px-2 py-1 transition-all duration-500',
                  i === stage ? 'bg-red-500/15 text-red-200 translate-x-1' : i < stage ? 'text-slate-300' : 'text-slate-500')}>
                  <span className={cn('grid place-items-center h-5 w-5 rounded-full text-[10px] font-bold',
                    i <= stage ? 'bg-red-500 text-white shadow-[0_0_10px_#ef4444]' : 'bg-slate-800 text-slate-400')}>{i + 1}</span>
                  {s}
                </li>
              ))}
            </ol>
          </SubPanel>
          <SubPanel title="Observed moves" icon="footprints" color="#94a3b8">
            {c && c.moves.length ? (
              <div className="space-y-1.5 max-h-48 overflow-auto">
                {c.moves.slice().reverse().map((m, i) => (
                  <div key={m.tick + m.to} className="row-in text-[12px]" style={{ animationDelay: i * 40 + 'ms' }}>
                    <span className="mono text-slate-500">t{m.tick}</span>{' '}
                    <span className="text-slate-300">{hostLabel(state, m.from)}</span> <span className="text-red-400">→</span>{' '}
                    <span className="text-white font-semibold">{hostLabel(state, m.to)}</span>
                    <div className="text-[11px] text-amber-300/80 pl-6">{m.technique}</div>
                  </div>
                ))}
              </div>
            ) : <div className="text-[12px] text-slate-500">No attacker movement yet. Launch an attack scenario.</div>}
          </SubPanel>
        </div>
      </div>
    </Section>
  );
}
