// Section 5: Automated Response (Self-Healing)

const ACTION_ICONS = {
  isolate: ['circle-minus', '#94a3b8'], block_ip: ['shield-ban', '#94a3b8'], firewall: ['brick-wall', '#94a3b8'],
  reroute: ['route', '#94a3b8'], restore: ['history', '#94a3b8'], restart: ['wrench', '#94a3b8'], patch: ['bandage', '#94a3b8'],
};

function MiniStar({ node, edges, after }) {
  const others = Array.from(new Set(edges.map((e) => (e.source === node ? e.target : e.source)))).slice(0, 8);
  const W = 220, H = 150, cx = W / 2, cy = H / 2;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto">
      {others.map((o, i) => {
        const a = (i / Math.max(others.length, 1)) * Math.PI * 2 - Math.PI / 2;
        const x = cx + Math.cos(a) * 58, y = cy + Math.sin(a) * 52;
        const out = edges.some((e) => e.source === node && e.target === o);
        return (
          <g key={o}>
            <line x1={cx} y1={cy} x2={x} y2={y} stroke={after ? '#10b981' : out ? '#ef4444' : '#f59e0b'} strokeWidth="2" className={after ? '' : 'dash-flow-fast'} opacity=".9" />
            <circle cx={x} cy={y} r="9" fill="#0b1324" stroke={after ? '#10b981' : '#94a3b8'} strokeWidth="2" />
            <text x={x} y={y + 21} textAnchor="middle" fontSize="9" fill="#94a3b8">{o}</text>
          </g>
        );
      })}
      <circle cx={cx} cy={cy} r="15" fill="#0b1324" stroke={after ? '#d4d4d4' : '#ef4444'} strokeWidth="3" style={{ filter: `drop-shadow(0 0 8px ${after ? '#d4d4d4' : '#ef4444'})` }} />
      {after
        ? <text x={cx} y={cy + 6} textAnchor="middle" fontSize="18" fill="#ef4444" fontWeight="700">✕</text>
        : <circle cx={cx} cy={cy} r="5" fill="#ef4444"><animate attributeName="r" values="4;8;4" dur="1s" repeatCount="indefinite" /></circle>}
      <text x={cx} y={H - 4} textAnchor="middle" fontSize="10" fill="#e2e8f0">{node}</text>
    </svg>
  );
}

function SectionResponse({ state }) {
  const recent = new Set(state.actions.filter((a) => a.tick >= state.tick - 1).map((a) => a.action));
  const counts = state.actions.reduce((m, a) => { m[a.action] = (m[a.action] || 0) + 1; return m; }, {});
  const stages = new Set(state.incidents.map((i) => i.stage));
  const mech = [
    ['Detection', 'Attack identified', 'from-red-600 to-red-500', stages.has('detected') || state.phase === 'detect'],
    ['Response', 'Execute defence', 'from-neutral-300 to-neutral-300', stages.has('responded') || state.phase === 'respond'],
    ['Recovery', 'Verify & restore', 'from-emerald-600 to-emerald-500', stages.has('restoring') || state.phase === 'recover'],
  ];
  const ba = state.before_after;
  return (
    <Section id="response" num={5} title="Automated Response (Self-Healing)" color="red" icon="shield-plus"
      subtitle="When an attack is confirmed the engine selects and executes defensive actions based on the detected node and the predicted path, then restores the host and verifies it is clean."
      right={<Pill color={state.auto_heal ? '#10b981' : '#94a3b8'} pulse={state.auto_heal}>{state.auto_heal ? 'auto-heal on' : 'auto-heal off'}</Pill>}>
      <div className="grid lg:grid-cols-[1fr_0.8fr_1.3fr] gap-4">
        <SubPanel title="Possible actions" icon="list" color="#94a3b8">
          <div className="space-y-1.5">
            {Object.entries(state.actions_catalog).map(([k, label]) => {
              const [icon, color] = ACTION_ICONS[k] || ['zap', '#fff'];
              const on = recent.has(k);
              return (
                <div key={k + (on ? state.tick : '')} className={cn('flex items-center gap-3 rounded-lg px-2.5 py-2 transition-all duration-300', on ? 'flash bg-white/10 translate-x-1' : 'bg-white/[.02]')} style={{ color }}>
                  <span className="h-7 w-7 rounded-full grid place-items-center" style={{ background: color + '22' }}><Icon name={icon} /></span>
                  <span className="text-[13px] text-slate-200 flex-1">{label}</span>
                  {counts[k] ? <span className="mono text-[11px] text-slate-400">×{counts[k]}</span> : null}
                </div>
              );
            })}
          </div>
        </SubPanel>
        <SubPanel title="Self-healing mechanism" icon="heart-pulse" color="#94a3b8">
          <div className="flex flex-col items-stretch gap-2">
            {mech.map(([t, s, g, on], i) => (
              <React.Fragment key={t}>
                <div className={cn('rounded-xl px-4 py-3 text-center bg-gradient-to-r transition-all duration-500', g,
                  on ? 'scale-[1.04] shadow-[0_0_30px_rgba(255,255,255,.25)] ring-2 ring-white/40' : 'opacity-60')}>
                  <div className="font-semibold text-white">{t}</div>
                  <div className="text-[11px] text-white/80">({s})</div>
                </div>
                {i < 2 && <div className="text-center text-slate-400"><Icon name="arrow-down" className={on ? 'text-white animate-bounce' : ''} /></div>}
              </React.Fragment>
            ))}
          </div>
          <div className="mt-3 text-[11px] text-slate-400 text-center">
            {state.incidents.length ? `${state.incidents.length} incident(s) in progress` : 'No open incidents'}
          </div>
        </SubPanel>
        <div className="space-y-4">
          <SubPanel title="Before vs after" icon="git-compare" color="#94a3b8">
            {ba ? (
              <div key={ba.tick} className="pop-in">
                <div className="grid grid-cols-[1fr_auto_1fr] items-center gap-2">
                  <div className="text-center">
                    <div className="text-[12px] text-slate-300 font-semibold mb-1">Before response</div>
                    <MiniStar node={ba.node} edges={ba.before.edges} />
                  </div>
                  <Icon name="arrow-right" className="text-2xl text-slate-400" />
                  <div className="text-center">
                    <div className="text-[12px] text-slate-300 font-semibold mb-1">After response</div>
                    <MiniStar node={ba.node} edges={ba.before.edges.filter((e) => ba.after.edges.some((x) => x.source === e.source && x.target === e.target))} after />
                  </div>
                </div>
                <div className="mt-2 text-center text-[12px] text-slate-300">
                  <b>{ba.label}</b> isolated · attack paths to critical system:{' '}
                  <span className="mono text-red-300">{ba.before.paths.toLocaleString()}</span> → <span className="mono text-emerald-300"><CountUp value={ba.after.paths} /></span>
                </div>
              </div>
            ) : <div className="text-[12px] text-slate-500 py-10 text-center">Comparison appears after the first automated response.</div>}
          </SubPanel>
          <SubPanel title="Response log" icon="terminal" color="#94a3b8">
            <div className="max-h-44 overflow-auto space-y-1 mono text-[11px]">
              {state.actions.length ? state.actions.map((a, i) => {
                const [icon, color] = ACTION_ICONS[a.action] || ['zap', '#fff'];
                return (
                  <div key={a.tick + a.action + i} className="row-in flex gap-2" style={{ color }}>
                    <span className="text-slate-500">t{a.tick}</span><Icon name={icon} /><span className="text-slate-300">{a.detail}</span>
                  </div>
                );
              }) : <div className="text-slate-500">idle — waiting for detections<span className="caret" /></div>}
            </div>
          </SubPanel>
        </div>
      </div>
    </Section>
  );
}
