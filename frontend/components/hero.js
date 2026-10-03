// Hero: centred editorial headline, square CTA, and a "product showcase" of the
// live 3D topology with the Threat Console card overlapping it.

function ControlDock({ sim, scenario, setScenario }) {
  const { state, playing, setPlaying, speed, setSpeed, actions } = sim;
  const ctl = 'h-10 rounded-[3px] px-3.5 text-[12px] uppercase tracking-[0.08em] font-medium border border-white/15 text-white/85 hover:border-white/40 hover:text-white transition-colors flex items-center gap-2';
  return (
    <div className="flex flex-wrap items-center justify-center gap-2.5">
      <button onClick={() => setPlaying(!playing)} className={cn(ctl, playing && 'bg-white text-black hover:text-black border-white')}>
        <Icon name={playing ? 'pause' : 'play'} /> {playing ? 'Pause' : 'Run'}
      </button>
      <button onClick={() => actions.step(1)} className={ctl}><Icon name="step-forward" /> Step</button>
      <label className={cn(ctl, 'cursor-default')}>
        Speed {speed}×
        <input type="range" min="0.5" max="4" step="0.5" value={speed} onChange={(e) => setSpeed(parseFloat(e.target.value))} className="w-20 accent-white" />
      </label>
      <select value={scenario} onChange={(e) => setScenario(e.target.value)} className={cn(ctl, 'cyber-select bg-transparent outline-none normal-case tracking-normal text-[13px]')}>
        {Object.entries(state.scenarios).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
      </select>
      <button onClick={() => actions.config({ auto_heal: !state.auto_heal })} className={ctl}>
        <span className={cn('switch scale-90', state.auto_heal ? 'on bg-emerald-500' : 'bg-neutral-600')}><span className="knob" /></span>
        Self-healing {state.auto_heal ? 'on' : 'off'}
      </button>
      <button onClick={() => actions.reset(scenario)} className={ctl}><Icon name="rotate-ccw" /> Reset</button>
    </div>
  );
}

function NodeInspector({ state, id, onClose, onHeal }) {
  const h = state.network.hosts.find((x) => x.id === id);
  if (!h) return null;
  const risk = state.risk[id];
  return (
    <div className="glass rounded-[10px] p-4 w-[290px] max-w-full pop-in text-left">
      <div className="flex items-start justify-between">
        <div>
          <div className="text-white font-medium">{h.label}</div>
          <div className="mono text-[11px] text-neutral-500">{h.ip} · {h.zone}</div>
        </div>
        <button onClick={onClose} className="text-neutral-500 hover:text-white"><Icon name="x" /></button>
      </div>
      <div className="mt-3 grid grid-cols-3 gap-2 text-[11px]">
        {[['Status', h.status, STATUS_COLORS[h.status]], ['Risk', risk != null ? risk.toFixed(2) : '—'], ['Anomaly', (state.anomaly[id] || 0).toFixed(2)]].map(([k, v, c]) => (
          <div key={k} className="panel-inner p-2"><div className="text-neutral-500">{k}</div><div className="font-medium" style={{ color: c || '#fff' }}>{v}</div></div>
        ))}
      </div>
      {h.vulns.map((v) => (
        <div key={v.cve} className={cn('mt-2 text-[11px] mono', v.patched ? 'text-neutral-600 line-through' : 'text-neutral-300')}>{v.cve} · {v.name}</div>
      ))}
      {h.status === 'compromised' && (
        <button onClick={() => onHeal(id)} className="btn-box btn-white w-full mt-3 !py-2.5">Heal this node</button>
      )}
    </div>
  );
}

function Hero({ sim, scenario, setScenario }) {
  const { state, playing, setPlaying, actions } = sim;
  const [selected, setSelected] = React.useState(null);
  const c = state.campaign;
  const words1 = ['A', 'network', 'that'];
  const words2 = ['heals', 'itself.'];
  return (
    <section id="top" className="band-dark relative overflow-hidden">
      <div className="hero-bg" />
      <div className="relative mx-auto max-w-[1440px] px-6 md:px-10 pt-36 pb-24">
        <div className="text-center">
          <div className="eyebrow text-white/60 mb-6">Adaptive Cyber Attack Graph &amp; Self-Healing Network Simulator</div>
          <h1 className="headline text-white text-[56px] sm:text-[80px] lg:text-[104px]">
            {words1.map((w, i) => <span key={w} className="word-up mr-[0.22em]" style={{ animationDelay: i * 90 + 'ms' }}>{w}</span>)}
            <br />
            {words2.map((w, i) => <span key={w} className="word-up mr-[0.22em]" style={{ animationDelay: 300 + i * 90 + 'ms' }}>{w}</span>)}
          </h1>
          <div className="mt-10 flex justify-center gap-3">
            <button onClick={() => setPlaying(!playing)} className="btn-box btn-white">{playing ? 'Pause simulation' : 'Run simulation'}</button>
            <button onClick={() => openTab('network')} className="btn-box btn-outline">How it works</button>
          </div>
          <p className="mt-5 text-[14px] text-white/70">Attack graph · machine-learning detection · automated recovery · tamper-proof audit.</p>
        </div>

        {/* product showcase */}
        <div className="relative mt-16 lg:pr-[220px]">
          <div className="relative rounded-[14px] overflow-hidden border border-white/10 shadow-[0_40px_120px_rgba(0,0,0,.7)] reveal in">
            <div className="flex items-center justify-between px-4 h-9 bg-[#0c0c0c] border-b border-white/10 text-[10px] uppercase tracking-[0.14em] text-white/50">
              <span>CyberHeal / live topology</span>
              <span className="flex gap-5"><span>{c ? c.name : 'idle'}</span><span>{c ? c.status : 'no campaign'}</span><span className="mono normal-case tracking-normal">t{state.tick}</span></span>
            </div>
            <Network3D state={state} height={560} selected={selected} onSelect={setSelected} />
            <div className="pointer-events-none absolute left-4 bottom-4 flex flex-wrap gap-4 text-[11px] text-white/60">
              {[['normal', 'Normal'], ['compromised', 'Compromised'], ['isolated', 'Isolated'], ['healing', 'Healing']].map(([k, l]) => (
                <span key={k} className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: STATUS_COLORS[k] }} />{l}</span>
              ))}
              <span className="flex items-center gap-1.5"><span className="h-0.5 w-4 bg-red-500" />Predicted path</span>
            </div>
            {selected && (
              <div className="absolute right-4 top-12"><NodeInspector state={state} id={selected} onClose={() => setSelected(null)} onHeal={actions.heal} /></div>
            )}
          </div>
          <div className="hidden lg:block absolute right-0 top-14 w-[400px] float" style={{ transform: 'rotate(1.5deg)' }}>
            <ThreatConsoleCard sim={sim} scenario={scenario} setScenario={setScenario} />
          </div>
        </div>
        <div className="lg:hidden mt-8 max-w-[420px] mx-auto"><ThreatConsoleCard sim={sim} scenario={scenario} setScenario={setScenario} /></div>

        <div className="mt-12"><ControlDock sim={sim} scenario={scenario} setScenario={setScenario} /></div>
        <p className="mt-4 text-center text-[12px] text-white/40">Drag to orbit · hover for details · click a node to inspect it</p>
      </div>
    </section>
  );
}
