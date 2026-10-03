// Section 4: Attack Detection & Prediction (ML)

function ModelRow({ r, active, onPick, best }) {
  return (
    <button onClick={() => onPick(r.name)}
      className={cn('w-full text-left rounded-xl p-3 border transition-all duration-300 group',
        active ? 'border-white/60 bg-white/15 shadow-[0_0_24px_rgba(229,229,229,.25)]' : 'border-white/5 bg-white/[.02] hover:border-white/30 hover:-translate-y-0.5')}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={cn('h-2.5 w-2.5 rounded-full', active ? 'bg-white shadow-[0_0_8px_#d4d4d4]' : 'bg-slate-600')} />
          <span className="font-semibold text-white text-[14px]">{r.name}</span>
          {best && <Pill color="#f59e0b">best F1</Pill>}
          {active && <Pill color="#d4d4d4" pulse>active</Pill>}
        </div>
        <span className="mono text-[10px] text-slate-500">{r.train_ms} ms train · {r.infer_us} µs/flow</span>
      </div>
      <div className="text-[11px] text-slate-500 mt-0.5">{r.family}</div>
      <div className="grid grid-cols-4 gap-3 mt-2">
        {[['Accuracy', r.accuracy, '#d4d4d4'], ['Precision', r.precision, '#d4d4d4'], ['Recall', r.recall, '#d4d4d4'], ['F1', r.f1, '#d4d4d4']].map(([k, v, c]) => (
          <div key={k}>
            <div className="flex justify-between text-[10px] text-slate-400"><span>{k}</span><span className="mono text-slate-200">{(v * 100).toFixed(1)}%</span></div>
            <div className="h-1.5 mt-1 rounded-full bg-white/5 overflow-hidden">
              <div className="h-full rounded-full bar-grow" style={{ width: `${Math.max(0, (v - 0.8) / 0.2) * 100}%`, background: c, boxShadow: `0 0 8px ${c}` }} />
            </div>
          </div>
        ))}
      </div>
    </button>
  );
}

function OutputCard({ icon, color, title, value, sub, children, flashKey }) {
  const [flash, setFlash] = React.useState(false);
  useOnChange(flashKey, () => { setFlash(true); setTimeout(() => setFlash(false), 1400); });
  return (
    <div className={cn('panel-inner p-4 text-center flex flex-col items-center', flash && 'flash')} style={{ color }}>
      <div className="h-12 w-12 rounded-2xl grid place-items-center mb-2 float" style={{ background: color + '22', boxShadow: `0 0 24px ${color}44` }}>
        <Icon name={icon} className="text-2xl" />
      </div>
      <div className="text-[13px] font-semibold text-white">{title}</div>
      {children || <div className="text-sm mt-1" style={{ color }}>{value || '—'}</div>}
      {sub && <div className="text-[11px] text-slate-500 mt-0.5">{sub}</div>}
    </div>
  );
}

function SectionDetection({ state, actions }) {
  const ml = state.ml;
  const best = ml.results.reduce((a, b) => (b.f1 > a.f1 ? b : a), ml.results[0] || {});
  const out = state.output;
  const riskList = Object.entries(state.risk)
    .map(([id, v]) => ({ id, v, h: state.network.hosts.find((x) => x.id === id) }))
    .filter((r) => r.h && r.h.kind !== 'attacker')
    .sort((a, b) => b.v - a.v)
    .slice(0, 7);
  return (
    <Section id="detection" num={4} title="Attack Detection & Prediction (ML)" color="violet" icon="brain-circuit"
      subtitle={`Machine learning detects malicious flows and predicts the attacker's next likely move in the graph. All four models are trained from scratch at start-up on ${ml.n_train} labelled flows and evaluated on ${ml.n_test} held-out flows. Click a model to make it the live detector.`}>
      <div className="grid xl:grid-cols-[1.15fr_1fr] gap-4">
        <SubPanel title="ML models (compared)" icon="cpu" color="#94a3b8">
          <div className="space-y-2">
            {ml.results.map((r) => (
              <ModelRow key={r.name} r={r} active={ml.active === r.name} best={r.name === best.name} onPick={(m) => actions.config({ model: m })} />
            ))}
          </div>
          <div className="mt-3">
            <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1.5">Random-Forest feature importance</div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1">
              {ml.feature_importance.slice(0, 8).map((f, i) => (
                <div key={f.feature} className="text-[11px]">
                  <div className="flex justify-between text-slate-400"><span>{f.feature}</span><span className="mono">{(f.value * 100).toFixed(1)}%</span></div>
                  <div className="h-1 rounded-full bg-white/5 overflow-hidden"><div className="h-full bar-grow bg-gradient-to-r from-neutral-300 to-neutral-300" style={{ width: `${(f.value / ml.feature_importance[0].value) * 100}%`, animationDelay: i * 80 + 'ms' }} /></div>
                </div>
              ))}
            </div>
          </div>
        </SubPanel>
        <div className="space-y-4">
          <SubPanel title="Tasks" icon="list-checks" color="#94a3b8">
            <div className="space-y-2">
              {[
                ['Anomaly detection', 'Is this traffic malicious?', `${state.traffic.flagged}/${state.traffic.n} flows flagged this tick`, 'scan-eye'],
                ['Attack path prediction', 'What is the next likely target?', out.predicted ? `→ ${out.predicted}` : 'awaiting attacker activity', 'target'],
                ['Risk scoring', 'Which nodes are most at risk?', out.risk_node ? `${out.risk_node} (${out.risk_score.toFixed(2)})` : '—', 'flame'],
              ].map(([t, q, live, icon], i) => (
                <div key={t} className="flex items-start gap-3 rounded-xl p-2.5 bg-gradient-to-r from-white/10 to-transparent border border-white/10">
                  <span className="h-7 w-7 rounded-lg grid place-items-center bg-white/20 text-white font-bold text-sm">{i + 1}</span>
                  <div className="flex-1">
                    <div className="text-[13px] font-semibold text-white flex items-center gap-1.5"><Icon name={icon} className="text-white" /> {t}</div>
                    <div className="text-[11px] text-slate-500">{q}</div>
                    <div className="text-[12px] text-white mono mt-0.5">{live}</div>
                  </div>
                </div>
              ))}
            </div>
          </SubPanel>
          <SubPanel title="Model output" icon="radar" color="#94a3b8">
            <div className="grid grid-cols-3 gap-2">
              <OutputCard icon="triangle-alert" color="#ef4444" title="Attack detected" value={out.detected || 'none'} sub={out.detected ? 'node under response' : 'all clear'} flashKey={out.detected} />
              <OutputCard icon="chevrons-right" color="#f59e0b" title="Predicted next target" flashKey={out.predicted}>
                <div className="text-sm mt-1 text-amber-300">{out.predicted || '—'}</div>
                <div className="w-full mt-1 space-y-0.5">
                  {state.prediction.slice(0, 3).map((p) => (
                    <div key={p.node} className="flex items-center gap-1 text-[10px] text-slate-400">
                      <span className="w-12 truncate text-left">{p.node}</span><Bar value={p.prob} color="#f59e0b" height={3} /><span className="mono w-7 text-right">{Math.round(p.prob * 100)}%</span>
                    </div>
                  ))}
                </div>
              </OutputCard>
              <OutputCard icon="gauge" color="#f59e0b" title="Risk score" flashKey={out.risk_node}>
                <Gauge value={out.risk_score || 0} size={110} label={(out.risk_score || 0).toFixed(2)} />
                <div className="text-[11px] text-slate-400 -mt-1">{out.risk_node}</div>
              </OutputCard>
            </div>
          </SubPanel>
          <SubPanel title="Risk heat-map (Bayesian attack graph)" icon="flame" color="#f59e0b">
            <div className="space-y-1.5">
              {riskList.map((r) => (
                <div key={r.id} className="flex items-center gap-2 text-[12px]">
                  <span className="w-28 truncate text-slate-300">{r.h.label}</span>
                  <Bar value={r.v} color={r.v > 0.6 ? '#ef4444' : r.v > 0.3 ? '#f59e0b' : '#10b981'} height={6} />
                  <span className="mono w-10 text-right text-slate-400">{r.v.toFixed(2)}</span>
                </div>
              ))}
            </div>
          </SubPanel>
        </div>
      </div>
    </Section>
  );
}
