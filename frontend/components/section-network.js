// Section 1: Network Simulation Environment

function SvgHost({ x, y, host, r = 22, ring, dim, label = true }) {
  const color = host.status === 'normal' ? '#d4d4d4' : STATUS_COLORS[host.status];
  const icon = (KIND_ICONS[host.kind] || 'icon-server');
  return (
    <g transform={`translate(${x},${y})`} style={{ transition: 'opacity .5s', opacity: dim ? 0.35 : 1 }}>
      {host.status === 'compromised' && (
        <circle r={r} fill="none" stroke="#ef4444" strokeWidth="2">
          <animate attributeName="r" values={`${r};${r * 2};${r}`} dur="1.4s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.9;0;0.9" dur="1.4s" repeatCount="indefinite" />
        </circle>
      )}
      {ring && (
        <rect x={-r - 7} y={-r - 7} width={2 * r + 14} height={2 * r + 14} fill="none" stroke={ring} strokeWidth="2" strokeDasharray="6 4" rx="4">
          <animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="6s" repeatCount="indefinite" />
        </rect>
      )}
      <circle r={r} fill="#0b1324" stroke={color} strokeWidth="2.5" style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: 'stroke .5s' }} />
      {host.status === 'isolated' && <circle r={r + 5} fill="none" stroke="#d4d4d4" strokeWidth="2" strokeDasharray="3 3" />}
      <foreignObject x={-r} y={-r} width={2 * r} height={2 * r} style={{ pointerEvents: 'none' }}>
        <div style={{ width: 2 * r, height: 2 * r, display: 'grid', placeItems: 'center', color, fontSize: r * 0.85 }}>
          <i className={icon} />
        </div>
      </foreignObject>
      {label && (
        <text y={r + 15} textAnchor="middle" fontSize="11.5" fill="#cbd5e1" fontWeight="600">{host.label}</text>
      )}
    </g>
  );
}

function TopologyDiagram({ state }) {
  const hosts = Object.fromEntries(state.network.hosts.map((h) => [h.id, h]));
  const P = {
    internet: [70, 60], firewall: [250, 60], switch: [450, 60], siem: [640, 60],
    web: [60, 190], mail: [160, 190], db: [270, 190], admin: [380, 190], backup: [490, 190], core: [600, 190],
    user1: [120, 320], user2: [230, 320], user3: [340, 320], atm1: [460, 320], atm2: [570, 320],
  };
  const links = state.network.links.filter((l) => P[l.source] && P[l.target]);
  return (
    <svg viewBox="0 0 680 370" className="w-full h-auto">
      <defs>
        <linearGradient id="busg" x1="0" x2="1"><stop offset="0" stopColor="#d4d4d4" /><stop offset="1" stopColor="#d4d4d4" /></linearGradient>
      </defs>
      {links.map((l) => {
        const [x1, y1] = P[l.source];
        const [x2, y2] = P[l.target];
        const bad = state.compromised.includes(l.source) || state.compromised.includes(l.target);
        const midY = (y1 + y2) / 2;
        const d = l.source === 'switch' ? `M${x1},${y1 + 22} L${x1},${midY + 10} L${x2},${midY + 10} L${x2},${y2 - 22}` : `M${x1},${y1} L${x2},${y2}`;
        return (
          <g key={l.source + l.target}>
            <path d={d} fill="none" stroke={l.cut ? '#334155' : bad ? '#ef4444' : '#1e3a5f'} strokeWidth="2.5" />
            {!l.cut && <path d={d} fill="none" stroke={bad ? '#ef4444' : 'url(#busg)'} strokeWidth="2" className={bad ? 'dash-flow-fast' : 'dash-flow'} opacity=".85" />}
            {l.cut && <text x={(x1 + x2) / 2} y={(y1 + y2) / 2} fill="#ef4444" fontSize="16" textAnchor="middle">✕</text>}
          </g>
        );
      })}
      {Object.entries(P).map(([id, [x, y]]) => hosts[id] && <SvgHost key={id} x={x} y={y} host={hosts[id]} />)}
    </svg>
  );
}

function SectionNetwork({ state }) {
  const hosts = state.network.hosts.filter((h) => h.kind !== 'attacker');
  return (
    <Section id="network" num={1} title="Network Simulation Environment" color="blue" icon="network"
      subtitle="A virtual network representing real-world financial / ATM infrastructure with multiple zones, devices and services. Node status updates live as the simulation runs.">
      <div className="grid xl:grid-cols-[1.25fr_1fr] gap-4">
        <SubPanel title="Topology" icon="git-fork">
          <TopologyDiagram state={state} />
          <div className="mt-3 flex flex-wrap gap-2">
            {[['git-graph', 'Graph engine (pure Python)'], ['cpu', 'Custom Python simulator'], ['box', 'Three.js 3D visualiser'], ['brain', 'From-scratch ML models']].map(([i, t]) => (
              <span key={t} className="inline-flex items-center gap-1.5 rounded-lg bg-white/10 border border-white/20 px-2.5 py-1 text-[12px] text-white"><Icon name={i} /> {t}</span>
            ))}
          </div>
        </SubPanel>
        <SubPanel title="Host inventory" icon="list" right={<span className="mono text-[11px] text-slate-500">{hosts.length} hosts · {state.dm.graphs.E} links</span>}>
          <div className="max-h-[380px] overflow-auto pr-1">
            <table className="w-full text-[12px]">
              <thead className="text-slate-500 text-[10px] uppercase tracking-wider sticky top-0 bg-[#070d1c]">
                <tr><th className="text-left py-1.5">Host</th><th className="text-left">Zone</th><th className="text-left">IP</th><th className="text-left">Vulns</th><th className="text-left">Status</th></tr>
              </thead>
              <tbody>
                {hosts.map((h) => {
                  const open = h.vulns.filter((v) => !v.patched).length;
                  return (
                    <tr key={h.id} className="border-t border-white/5 hover:bg-white/[.03] transition-colors">
                      <td className="py-1.5 flex items-center gap-2"><i className={KIND_ICONS[h.kind]} style={{ color: STATUS_COLORS[h.status] || '#d4d4d4' }} /> {h.label}</td>
                      <td className="text-slate-400">{h.zone}</td>
                      <td className="mono text-slate-400">{h.ip}</td>
                      <td>{h.vulns.length ? <span className={open ? 'text-red-300' : 'text-emerald-400'}>{open}/{h.vulns.length}</span> : <span className="text-slate-600">—</span>}</td>
                      <td><Pill color={STATUS_COLORS[h.status] || '#d4d4d4'} pulse={h.status === 'compromised'}>{h.status}</Pill></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {state.network.rules.length > 0 && (
            <div className="mt-3">
              <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">Dynamic firewall rules</div>
              {state.network.rules.slice(-4).reverse().map((r) => (
                <div key={r.id} className="mono text-[11px] text-amber-300 row-in">#{r.id} {r.action.toUpperCase()} {r.src} → {r.dst} <span className="text-slate-500">({r.reason})</span></div>
              ))}
            </div>
          )}
        </SubPanel>
      </div>
    </Section>
  );
}
