// Editorial landing sections: Threat Console card, stats band, pipeline carousel,
// platform cards and footer.

// ------------------------------------------------------------------ typing hook
function useTypewriter(phrases, { type = 70, erase = 35, hold = 1600 } = {}) {
  const [i, setI] = React.useState(0);
  const [text, setText] = React.useState('');
  const [deleting, setDeleting] = React.useState(false);
  const list = phrases.length ? phrases : [''];
  const target = list[i % list.length];
  React.useEffect(() => {
    let t;
    if (!deleting && text === target) t = setTimeout(() => setDeleting(true), hold);
    else if (deleting && text === '') { setDeleting(false); setI((n) => (n + 1) % list.length); }
    else if (deleting) t = setTimeout(() => setText(text.slice(0, -1)), erase);
    else t = setTimeout(() => setText(target.slice(0, text.length + 1)), type);
    return () => clearTimeout(t);
  }, [text, deleting, target, list.length]);
  return { text, index: i % list.length };
}

// ------------------------------------------------------------------ Threat Console (reference card)
function ThreatConsoleCard({ sim, scenario, setScenario }) {
  const { state, actions } = sim;
  const active = state.campaign && state.campaign.status === 'active';
  const keys = Object.keys(state.scenarios);
  const phrases = active
    ? [state.output.predicted ? `Next target: ${state.output.predicted}` : 'Watching the attacker', state.output.detected ? `Isolating ${state.output.detected}` : `Stage: ${state.campaign.stage_name}`]
    : keys.map((k) => state.scenarios[k]);
  const { text, index } = useTypewriter(phrases);
  const risk = state.output.risk_score || 0;
  const level = risk > 0.6 ? 'HIGH' : risk > 0.3 ? 'MED' : 'LOW';
  const tilt = useTilt(8);
  return (
    <div ref={tilt.ref} onMouseMove={tilt.onMouseMove} onMouseLeave={tilt.onMouseLeave} className="tilt ai-card relative px-7 pt-7 pb-9 text-white overflow-visible">
      <div className="tilt-shine" />
      <div className="flex items-start justify-between">
        <div className="rounded-[12px] bg-[#2a2a2a] w-[86px] h-[100px] grid place-items-center">
          <div className="relative w-[54px] h-[74px] text-center pt-2" style={{ background: level === 'HIGH' ? '#d93a32' : '#3b3b3b', clipPath: 'polygon(0 0,100% 0,100% 100%,50% 82%,0 100%)', transition: 'background .5s' }}>
            <div className="text-[8px] tracking-[0.1em]">THREAT</div>
            <div className="text-[15px] font-bold leading-none mt-0.5">{level}</div>
            <div className="text-[8px] mt-1 bg-black/80 mx-1 py-[1px]">LEVEL</div>
          </div>
        </div>
        <span className="text-[10px] uppercase tracking-[0.16em] text-white/40 mt-1">{active ? 'live' : 'ready'}</span>
      </div>

      {/* bleeding pill input */}
      <div className="ai-pill relative -mr-12 mt-12 mb-20 h-[86px] flex items-center pl-6 pr-4 tilt-depth">
        <span className="dots-logo relative w-[44px] h-[40px] mr-3 shrink-0">
          <span style={{ width: 24, height: 24, left: 0, top: 0 }} />
          <span style={{ width: 14, height: 14, left: 26, top: 14 }} />
          <span style={{ width: 11, height: 11, left: 8, top: 27 }} />
        </span>
        <span className="text-[28px] font-medium tracking-[-0.02em] text-white/90 whitespace-nowrap overflow-hidden">{text}</span>
        <span className="caret-bar h-[46px]" />
      </div>

      <div className="text-center">
        <div className="text-[15px] font-medium">Threat Console</div>
        <p className="mt-4 text-[19px] leading-snug text-white/50 px-2">
          {active ? 'An attack is underway. Watch the network detect, respond and heal.' : 'Pick a scenario and let the self-healing network do the rest.'}
        </p>
        {active
          ? <button onClick={() => openTab('response')} className="link-arrow mt-6 text-[26px]">Watch it heal <Icon name="arrow-right" /></button>
          : <button onClick={() => actions.launch(keys[index] || scenario)} className="link-arrow mt-6 text-[26px]">Launch attack <Icon name="arrow-right" /></button>}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ stats band
function StatsBand({ state }) {
  const o = state.outcomes;
  const ref = useReveal();
  const stats = [
    [o.detection_rate == null ? null : o.detection_rate * 100, '%', 1, 'Attack flows detected'],
    [state.dm.combinatorics.paths, '', 0, 'Live attack paths to core'],
    [o.mttr, ' t', 1, 'Mean time to recover'],
    [o.healed, '', 0, 'Nodes healed'],
  ];
  return (
    <section className="band-dark border-t border-white/5">
      <div ref={ref} className="reveal mx-auto max-w-[1200px] px-6 py-24 text-center">
        <p className="text-[14px] text-white/70">Measured live from the running simulation.</p>
        <div className="mt-12 grid grid-cols-2 md:grid-cols-4 gap-y-12">
          {stats.map(([v, suf, d, label]) => (
            <div key={label}>
              <div className="headline text-white text-[52px] md:text-[64px] font-normal">
                {v == null ? '—' : <CountUp value={v} decimals={d} suffix={suf} />}
              </div>
              <div className="mt-3 text-[13px] text-white/70">{label}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ------------------------------------------------------------------ pipeline carousel
const PIPELINE = [
  ['network', 'Network', 'Network simulation'],
  ['attack-graph', 'Attack graph', 'Attack graph construction'],
  ['traffic', 'Traffic', 'Data collection'],
  ['detection', 'Detection', 'Detection & prediction'],
  ['response', 'Self-healing', 'Automated response'],
  ['monitoring', 'Monitoring', 'Continuous monitoring'],
  ['ledger', 'Ledger', 'Blockchain audit'],
  ['dm', 'DM concepts', 'Discrete mathematics'],
];

function renderSlide(id, state, actions) {
  switch (id) {
    case 'network': return <SectionNetwork state={state} />;
    case 'attack-graph': return <SectionAttackGraph state={state} />;
    case 'traffic': return <SectionTraffic state={state} />;
    case 'detection': return <SectionDetection state={state} actions={actions} />;
    case 'response': return <SectionResponse state={state} />;
    case 'monitoring': return <SectionMonitoring state={state} />;
    case 'ledger': return <SectionLedger state={state} actions={actions} />;
    default: return <SectionDM state={state} />;
  }
}

function ExploreCarousel({ state, actions }) {
  const [idx, setIdx] = React.useState(0);
  const [auto, setAuto] = React.useState(false);
  const [hover, setHover] = React.useState(false);
  const ref = useReveal();
  React.useEffect(() => {
    const on = (e) => { const i = PIPELINE.findIndex((p) => p[0] === e.detail); if (i >= 0) { setIdx(i); setAuto(false); } };
    window.addEventListener('open-tab', on);
    return () => window.removeEventListener('open-tab', on);
  }, []);
  React.useEffect(() => {
    if (!auto || hover) return;
    const t = setInterval(() => setIdx((i) => (i + 1) % PIPELINE.length), 7000);
    return () => clearInterval(t);
  }, [auto, hover]);
  const go = (d) => setIdx((i) => (i + d + PIPELINE.length) % PIPELINE.length);
  const prev = PIPELINE[(idx - 1 + PIPELINE.length) % PIPELINE.length];
  const next = PIPELINE[(idx + 1) % PIPELINE.length];
  return (
    <section id="explore" className="band-light scroll-mt-16">
      <div ref={ref} className="reveal mx-auto max-w-[1440px] px-6 md:px-10 pt-28 pb-24">
        <div className="text-center">
          <h2 className="headline text-[44px] md:text-[56px] font-normal">Explore the pipeline</h2>
          <p className="mt-4 text-[15px] text-neutral-600">Seven stages, one continuous self-healing loop. Every panel is live.</p>
        </div>
        <div className="mt-10 flex justify-center gap-1 overflow-x-auto pb-2">
          {PIPELINE.map(([id, label], i) => (
            <button key={id} onClick={() => { setIdx(i); setAuto(false); }} className={cn('tab-pill', i === idx && 'active')}>{label}</button>
          ))}
        </div>

        <div className="mt-10 relative" onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}>
          {/* neighbour peeks, like a carousel */}
          <button onClick={() => go(-1)} className="hidden 2xl:flex absolute -left-[150px] top-0 bottom-0 w-[120px] rounded-[12px] bg-[#141414] text-white/80 p-5 items-start text-left hover:-translate-x-1 transition-transform" aria-label="Previous">
            <span className="text-[17px] leading-tight">{prev[2]}</span>
          </button>
          <button onClick={() => go(1)} className="hidden 2xl:flex absolute -right-[150px] top-0 bottom-0 w-[120px] rounded-[12px] bg-[#141414] text-white/80 p-5 items-start text-left hover:translate-x-1 transition-transform" aria-label="Next">
            <span className="text-[17px] leading-tight">{next[2]}</span>
          </button>
          <div key={PIPELINE[idx][0]} className="slide-enter relative">
            {renderSlide(PIPELINE[idx][0], state, actions)}
            <div className="absolute bottom-5 right-5 flex gap-2">
              <button onClick={() => go(-1)} className="h-9 w-9 grid place-items-center rounded-full text-white/80 hover:bg-white/10" aria-label="Previous stage"><Icon name="arrow-left" /></button>
              <button onClick={() => go(1)} className="h-9 w-9 grid place-items-center rounded-full text-white/80 hover:bg-white/10" aria-label="Next stage"><Icon name="arrow-right" /></button>
            </div>
          </div>
        </div>

        <div className="mt-8 flex items-center justify-center gap-2 relative">
          {PIPELINE.map(([id], i) => <button key={id} onClick={() => setIdx(i)} className={cn('dot', i === idx && 'active')} aria-label={`Stage ${i + 1}`} />)}
          <button onClick={() => setAuto(!auto)} className="absolute right-0 h-8 w-8 rounded-full border border-neutral-300 grid place-items-center text-neutral-700 hover:border-neutral-500" aria-label={auto ? 'Pause' : 'Autoplay'}>
            <Icon name={auto ? 'pause' : 'play'} className="text-[12px]" />
          </button>
        </div>
      </div>
    </section>
  );
}

// ------------------------------------------------------------------ platform cards
function PlatformCard({ title, desc, onOpen, children, i }) {
  const t = useTilt(6);
  return (
    <button ref={t.ref} onMouseMove={t.onMouseMove} onMouseLeave={t.onMouseLeave} onClick={onOpen}
      className="tilt group relative text-left rounded-[10px] bg-[#1c1c1c] text-white p-5 aspect-[4/5] flex flex-col overflow-hidden"
      style={{ transitionDelay: i * 40 + 'ms' }}>
      <div className="tilt-shine" />
      <div className="text-[17px] font-medium">{title}</div>
      <p className="mt-1.5 text-[12.5px] leading-snug text-white/70">{desc}</p>
      <div className="flex-1 grid place-items-center tilt-depth">{children}</div>
      <Icon name="arrow-right" className="absolute bottom-5 right-5 text-white/80 transition-transform group-hover:translate-x-1" />
    </button>
  );
}

function PlatformBand({ state }) {
  const ref = useReveal();
  const ml = state.ml.results;
  const blocks = state.chain.blocks.slice(-5).reverse();
  const pred = state.prediction[0];
  return (
    <section className="band-light border-t border-neutral-100">
      <div ref={ref} className="reveal mx-auto max-w-[1440px] px-6 md:px-10 py-24">
        <div className="grid md:grid-cols-2 gap-8 items-end">
          <h2 className="headline text-[40px] md:text-[48px] font-normal">Everything the SOC needs,<br />in one loop</h2>
          <p className="text-[15px] text-neutral-600 max-w-md">Detection, prediction, response and audit work together — each defensive action rewrites the attack graph, and every step is recorded on a tamper-evident ledger.</p>
        </div>
        <div className="mt-12 grid sm:grid-cols-2 lg:grid-cols-4 gap-5">
          <PlatformCard i={0} title="Detection models" desc="Four models trained from scratch; the best F1 runs live." onOpen={() => openTab('detection')}>
            <div className="w-full space-y-2.5">
              {ml.map((r) => (
                <div key={r.name} className="text-[11px]">
                  <div className="flex justify-between text-white/70"><span>{r.name}</span><span className="mono">{(r.f1 * 100).toFixed(1)}</span></div>
                  <div className="h-1 mt-1 rounded bg-white/10"><div className="h-full rounded bg-white bar-grow" style={{ width: `${Math.max(0, (r.f1 - 0.85) / 0.15) * 100}%` }} /></div>
                </div>
              ))}
            </div>
          </PlatformCard>
          <PlatformCard i={1} title="Predicted next move" desc="The attack graph forecasts where the adversary goes next." onOpen={() => openTab('attack-graph')}>
            <div className="text-center">
              <div className="text-[11px] uppercase tracking-[0.16em] text-white/50">next target</div>
              <div className="mt-2 text-[26px] font-medium tracking-tight">{pred ? hostLabel(state, pred.node) : '—'}</div>
              <div className="mt-1 mono text-white/60 text-sm">{pred ? `p = ${pred.prob.toFixed(2)}` : 'no active campaign'}</div>
            </div>
          </PlatformCard>
          <PlatformCard i={2} title="Self-healing" desc="Isolate, block, patch, restore and verify — automatically." onOpen={() => openTab('response')}>
            <Donut value={state.health / 100} size={150} stroke={6} color={state.health > 85 ? '#ffffff' : state.health > 60 ? '#f59e0b' : '#ef4444'}>
              <div className="text-[34px] font-medium tracking-tight"><CountUp value={state.health} decimals={0} /></div>
              <div className="text-[10px] uppercase tracking-[0.16em] text-white/50">health</div>
            </Donut>
          </PlatformCard>
          <PlatformCard i={3} title="Audit ledger" desc="SHA-256 hash chain with proof-of-work; tampering is caught instantly." onOpen={() => openTab('ledger')}>
            <div className="w-full flex flex-col items-end gap-1.5">
              {blocks.map((b, i) => (
                <span key={b.index} className={cn('mono text-[11px] rounded-full px-3 py-1 transition-all', i === 0 ? 'bg-white text-black w-full flex justify-between' : 'bg-white/10 text-white/70')}>
                  {i === 0 ? <><span>#{b.index} {b.hash.slice(0, 10)}…</span><span>{state.chain.verify.valid ? 'verified' : 'broken'}</span></> : `#${b.index} ${b.hash.slice(0, 8)}`}
                </span>
              ))}
            </div>
          </PlatformCard>
        </div>
      </div>
    </section>
  );
}

// ------------------------------------------------------------------ footer
function Footer() {
  return (
    <footer className="band-dark">
      <div className="mx-auto max-w-[1440px] px-6 md:px-10 py-16 grid md:grid-cols-[1.5fr_1fr_1fr] gap-10">
        <div>
          <div className="text-[15px] font-semibold tracking-[0.14em] uppercase">CyberHeal</div>
          <p className="mt-3 text-[13px] text-white/50 max-w-sm">Adaptive Cyber Attack Graph &amp; Self-Healing Network Simulator. Pure-Python engine, React + Three.js interface.</p>
        </div>
        <div className="text-[13px] space-y-2">
          <div className="eyebrow text-white/40 mb-3">Pipeline</div>
          {PIPELINE.slice(0, 4).map(([id, label]) => <button key={id} onClick={() => openTab(id)} className="block text-white/70 hover:text-white">{label}</button>)}
        </div>
        <div className="text-[13px] space-y-2">
          <div className="eyebrow text-white/40 mb-3">Defence</div>
          {PIPELINE.slice(4).map(([id, label]) => <button key={id} onClick={() => openTab(id)} className="block text-white/70 hover:text-white">{label}</button>)}
        </div>
      </div>
    </footer>
  );
}
