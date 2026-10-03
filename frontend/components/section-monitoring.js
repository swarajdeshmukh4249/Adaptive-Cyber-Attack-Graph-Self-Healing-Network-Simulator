// Section 6: Continuous Monitoring & Adaptation

const LOOP_STEPS = [
  { key: 'monitor', title: 'Monitor', sub: 'traffic + graph state', icon: 'search', color: '#d4d4d4', angle: -90 },
  { key: 'detect', title: 'Detect & Predict', sub: 'using ML', icon: 'brain', color: '#d4d4d4', angle: 0 },
  { key: 'respond', title: 'Respond', sub: 'automated defence', icon: 'cog', color: '#ef4444', angle: 90 },
  { key: 'recover', title: 'Recover & Adapt', sub: 'update graph', icon: 'refresh-cw', color: '#10b981', angle: 180 },
];

function HealingLoop({ phase }) {
  const R = 118, C = 160;
  const activeIdx = Math.max(0, LOOP_STEPS.findIndex((s) => s.key === phase));
  return (
    <div className="relative mx-auto" style={{ width: 320, height: 320, perspective: 900 }}>
      <div className="absolute inset-0" style={{ transform: 'rotateX(18deg)', transformStyle: 'preserve-3d' }}>
        <svg viewBox="0 0 320 320" className="absolute inset-0 spin-slow" style={{ animationDuration: '30s' }}>
          <defs>
            <linearGradient id="loopg" x1="0" x2="1" y1="0" y2="1">
              <stop offset="0" stopColor="#475569" /><stop offset="1" stopColor="#334155" />
            </linearGradient>
          </defs>
          <circle cx={C} cy={C} r={R} fill="none" stroke="url(#loopg)" strokeWidth="3" strokeDasharray="10 8" className="dash-flow" opacity=".7" />
          <circle cx={C} cy={C} r={R - 22} fill="none" stroke="rgba(148,163,184,.12)" strokeWidth="1" />
        </svg>
        <svg viewBox="0 0 320 320" className="absolute inset-0">
          <circle r="6" fill="#fff" style={{ filter: 'drop-shadow(0 0 8px #d4d4d4)' }}>
            <animateMotion dur="5s" repeatCount="indefinite" path={`M ${C} ${C - R} A ${R} ${R} 0 1 1 ${C - 0.1} ${C - R}`} />
          </circle>
        </svg>
      </div>
      <div className="absolute inset-0 grid place-items-center text-center pointer-events-none">
        <div>
          <div className="text-[15px] font-semibold text-white leading-tight">Continuous<br />Self-Healing<br />Loop</div>
        </div>
      </div>
      {LOOP_STEPS.map((s, i) => {
        const a = (s.angle * Math.PI) / 180;
        const x = C + Math.cos(a) * R, y = C + Math.sin(a) * R;
        const on = i === activeIdx;
        return (
          <div key={s.key} className={cn('absolute -translate-x-1/2 -translate-y-1/2 rounded-2xl px-3 py-2 flex items-center gap-2 border transition-all duration-500 glass',
            on ? 'scale-110 z-10' : 'opacity-75')}
            style={{ left: x, top: y, borderColor: s.color + (on ? 'cc' : '44'), boxShadow: on ? `0 0 30px ${s.color}88` : 'none' }}>
            <span className="h-8 w-8 rounded-full grid place-items-center text-white" style={{ background: s.color }}>
              <Icon name={s.icon} className={on ? 'spin-slow' : ''} style={on ? { animationDuration: '3s' } : null} />
            </span>
            <div className="leading-tight text-left">
              <div className="text-[12px] font-bold" style={{ color: s.color }}>{s.title}</div>
              <div className="text-[10px] text-slate-400">{s.sub}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

const EVENT_COLORS = { attack: '#ef4444', detect: '#d4d4d4', respond: '#10b981', defense: '#d4d4d4', system: '#94a3b8', config: '#f59e0b' };

function SectionMonitoring({ state }) {
  const hist = state.history;
  return (
    <Section id="monitoring" num={6} title="Continuous Monitoring & Adaptation" color="teal" icon="radar"
      subtitle="The network and attack graph are updated after each response. The system verifies recovery and keeps monitoring for new threats — every tick runs the full monitor → detect → respond → recover cycle.">
      <div className="grid xl:grid-cols-[340px_1fr_1fr] gap-4 items-start">
        <SubPanel className="grid place-items-center"><HealingLoop phase={state.phase} /></SubPanel>
        <div className="space-y-4">
          <SubPanel title="Network health %" icon="heart-pulse" color="#94a3b8" right={<span className="mono text-emerald-300 text-sm"><CountUp value={state.health} decimals={1} />%</span>}>
            <LineChart data={hist} series={[{ key: 'health', color: '#10b981' }]} max={100} height={110} />
          </SubPanel>
          <SubPanel title="Compromised hosts & max open risk" icon="trending-up" color="#94a3b8">
            <LineChart data={hist.map((h) => ({ ...h, risk10: h.risk * 10 }))} series={[{ key: 'compromised', color: '#ef4444' }, { key: 'risk10', color: '#f59e0b', area: false }]} height={110} />
            <div className="flex gap-4 text-[11px] text-slate-400 mt-1">
              <span className="flex items-center gap-1"><span className="h-0.5 w-4 bg-red-500" /> compromised</span>
              <span className="flex items-center gap-1"><span className="h-0.5 w-4 bg-amber-500" /> max risk ×10</span>
            </div>
          </SubPanel>
        </div>
        <div className="space-y-4">
          <SubPanel title="Attack paths to critical system" icon="git-branch" color="#94a3b8" right={<span className="mono text-white text-sm">{state.dm.combinatorics.paths.toLocaleString()}</span>}>
            <LineChart data={hist} series={[{ key: 'paths', color: '#d4d4d4' }]} height={110} />
          </SubPanel>
          <SubPanel title="Security event stream" icon="terminal" color="#94a3b8">
            <div className="h-[150px] overflow-auto mono text-[11px] space-y-0.5 pr-1">
              {state.events.map((e, i) => (
                <div key={state.events.length - i + e.msg} className="row-in flex gap-2" style={{ animationDelay: Math.min(i, 6) * 30 + 'ms' }}>
                  <span className="text-slate-600 shrink-0">[{String(e.tick).padStart(3, '0')}]</span>
                  <span className="shrink-0 uppercase" style={{ color: EVENT_COLORS[e.kind] || '#94a3b8' }}>{e.kind.padEnd(7, ' ')}</span>
                  <span className="text-slate-300">{e.msg}</span>
                </div>
              ))}
            </div>
          </SubPanel>
        </div>
      </div>
    </Section>
  );
}
