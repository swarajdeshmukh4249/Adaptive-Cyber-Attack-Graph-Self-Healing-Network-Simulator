// Expected outcomes: live KPIs + Monte-Carlo experiment (self-healing on vs off).

function KPI({ icon, label, value, suffix = '', decimals = 0, color, hint }) {
  return (
    <GlowCard innerClassName="p-4" maxTilt={10}>
      <div className="tilt-depth">
        <div className="flex items-center gap-2 text-[12px] text-slate-400"><Icon name={icon} style={{ color }} /> {label}</div>
        <div className="mt-1 text-3xl font-semibold tracking-tight" style={{ color }}>
          {value == null ? '—' : <CountUp value={value} decimals={decimals} suffix={suffix} />}
        </div>
        {hint && <div className="text-[11px] text-slate-500 mt-0.5">{hint}</div>}
      </div>
    </GlowCard>
  );
}

function ExperimentPanel() {
  const [exp, setExp] = React.useState({ status: 'idle', result: null });
  React.useEffect(() => {
    if (exp.status !== 'running') return;
    const id = setInterval(async () => {
      try { setExp(await API.get('experiment')); } catch (e) { setExp({ status: 'error', error: e.message }); }
    }, 800);
    return () => clearInterval(id);
  }, [exp.status]);
  const start = async () => setExp(await API.post('experiment', { runs: 12, ticks: 45 }));
  const r = exp.result;
  const rows = r && [
    ['Breach rate', r.without_healing.breach_rate * 100, r.with_healing.breach_rate * 100, '%'],
    ['Avg compromised hosts', r.without_healing.avg_compromised, r.with_healing.avg_compromised, ''],
  ];
  return (
    <SubPanel title="Monte-Carlo validation" icon="flask-conical" color="#94a3b8"
      right={<button onClick={start} disabled={exp.status === 'running'} className="btn-box btn-white !py-2 !px-4">
        {exp.status === 'running' ? <span className="flex items-center gap-1.5"><Icon name="loader" className="spin-slow" style={{ animationDuration: '1s' }} /> running…</span> : 'Run experiment'}
      </button>}>
      <p className="text-[12px] text-slate-400 mb-3">Runs 12 attack campaigns (all scenarios) twice — with and without self-healing — and compares the outcomes.</p>
      {rows ? (
        <div className="space-y-3 pop-in">
          {rows.map(([k, off, on, suf]) => {
            const mx = Math.max(off, on, 1);
            return (
              <div key={k}>
                <div className="text-[12px] text-slate-300 mb-1">{k}</div>
                {[['without healing', off, '#ef4444'], ['with healing', on, '#10b981']].map(([l, v, c]) => (
                  <div key={l} className="flex items-center gap-2 text-[11px] mb-1">
                    <span className="w-24 text-slate-400">{l}</span>
                    <div className="flex-1 h-3 rounded bg-white/5 overflow-hidden"><div className="h-full rounded bar-grow" style={{ width: `${(v / mx) * 100}%`, background: c, boxShadow: `0 0 10px ${c}` }} /></div>
                    <span className="mono w-14 text-right" style={{ color: c }}>{v.toFixed(1)}{suf}</span>
                  </div>
                ))}
              </div>
            );
          })}
          <div className="text-[11px] text-slate-500">avg MTTR with healing: {r.with_healing.avg_mttr ?? '—'} ticks · {r.runs} runs × {r.ticks} ticks</div>
        </div>
      ) : exp.status === 'error' ? <div className="text-red-300 text-[12px]">{exp.error}</div>
        : <div className="text-[12px] text-slate-500">No results yet.</div>}
    </SubPanel>
  );
}

function SectionOutcomes({ state }) {
  const o = state.outcomes;
  const pct = (x) => (x == null ? null : x * 100);
  return (
    <Section id="outcomes" title="Expected Outcomes" color="indigo" icon="trophy"
      subtitle="Measured live from the running simulation.">
      <div className="grid lg:grid-cols-[1.4fr_1fr] gap-4">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          <KPI icon="scan-eye" label="Attack-flow detection rate" value={pct(o.detection_rate)} suffix="%" decimals={1} color="#d4d4d4" hint="accurate detection" />
          <KPI icon="target" label="Next-target prediction" value={pct(o.prediction_accuracy)} suffix="%" decimals={0} color="#f59e0b" hint="attack path prediction" />
          <KPI icon="timer" label="Mean time to detect" value={o.mttd} suffix=" t" decimals={1} color="#d4d4d4" hint="ticks after compromise" />
          <KPI icon="heart-pulse" label="Mean time to recover" value={o.mttr} suffix=" t" decimals={1} color="#10b981" hint="self-healing response" />
          <KPI icon="shield-check" label="Nodes healed" value={o.healed} color="#10b981" hint={`${o.contained} campaign(s) contained`} />
          <KPI icon="skull" label="Critical breaches" value={o.breaches} color="#ef4444" hint={`${o.attacks_blocked} exploit attempts failed`} />
        </div>
        <div className="space-y-4">
          <SubPanel title="Outcomes" icon="badge-check" color="#94a3b8">
            {[
              ['chart-bar', 'Accurate attack detection and prediction'],
              ['shield', 'Automated and effective self-healing response'],
              ['refresh-cw', 'Dynamic attack graph that adapts after each response'],
              ['clock', 'Reduced attacker success rate'],
              ['file-lock', `Transparent, immutable logging (${o.chain_valid ? 'chain valid' : 'chain broken!'})`],
            ].map(([i, t]) => (
              <div key={t} className="flex items-center gap-2.5 text-[13px] text-slate-300 py-1"><Icon name={i} className="text-white" /> {t}</div>
            ))}
          </SubPanel>
          <ExperimentPanel />
        </div>
      </div>
    </Section>
  );
}
