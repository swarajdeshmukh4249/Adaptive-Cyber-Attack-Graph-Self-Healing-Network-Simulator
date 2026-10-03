// Section 3: Data Collection & Feature Extraction

const FEATURE_LABELS = {
  duration: 'Flow duration (s)', bytes_log: 'Bytes (log)', packets_log: 'Packets (log)', avg_pkt_size: 'Avg packet size',
  protocol: 'Protocol id', port_entropy: 'Port entropy', conn_rate: 'Connection count', failed_auth: 'Failed auth',
  src_degree: 'Source node degree', dst_centrality: 'Dest. centrality', hops_to_critical: 'Path length → critical',
  rate_change: 'Rate of change', rolling_mean: 'Rolling mean bytes',
};

function FeatureGroup({ title, icon, color, names, means, sample, featureNames }) {
  return (
    <div className="panel-inner p-3 hover:border-white/20 transition-colors">
      <div className="flex items-center gap-2 mb-2">
        <div className="h-8 w-8 rounded-lg grid place-items-center float" style={{ background: color + '22', color }}><Icon name={icon} /></div>
        <div className="text-[13px] font-semibold text-white">{title}</div>
      </div>
      <div className="space-y-1.5">
        {names.map((n) => {
          const idx = featureNames.indexOf(n);
          const v = sample ? sample.x[idx] : null;
          return (
            <div key={n} className="text-[11.5px]">
              <div className="flex justify-between text-slate-400"><span>{FEATURE_LABELS[n] || n}</span><span className="mono text-slate-200">{means[n] != null ? means[n].toFixed(2) : '—'}</span></div>
              {v != null && <Bar value={Math.min(1, Math.abs(v) / (Math.abs(means[n] || 1) * 2.5 || 1))} color={color} height={3} className="mt-0.5" />}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SectionTraffic({ state }) {
  const tr = state.traffic;
  const names = state.features.names;
  return (
    <Section id="traffic" num={3} title="Data Collection & Feature Extraction" color="orange" icon="activity"
      subtitle="Normal and attack traffic are simulated every tick. Each flow is turned into a 13-dimensional vector of traffic, graph and time-based features that feeds the ML models.">
      <div className="grid xl:grid-cols-2 gap-4">
        <SubPanel title="Network traffic" icon="audio-waveform" color="#94a3b8"
          right={<span className="mono text-[11px] text-slate-400">{tr.n} flows · <span className="text-red-300">{tr.attack} malicious</span></span>}>
          <div className="grid grid-cols-2 gap-3">
            <div className="panel-inner p-2"><WaveCanvas data={tr.wave.normal} color="#d4d4d4" height={110} label="Normal traffic" /></div>
            <div className={cn('panel-inner p-2 transition-colors', tr.attack ? 'border-red-500/40' : '')}><WaveCanvas data={tr.wave.attack} color="#ef4444" height={110} label="Attack traffic" /></div>
          </div>
          <div className="mt-3 max-h-[250px] overflow-auto">
            <table className="w-full text-[11.5px]">
              <thead className="text-slate-500 text-[10px] uppercase tracking-wider sticky top-0 bg-[#070d1c]">
                <tr><th className="text-left py-1">src → dst</th><th className="text-left">kind</th><th className="text-left">proto</th><th className="text-right">bytes</th><th className="text-left pl-3 w-28">ML score</th></tr>
              </thead>
              <tbody key={state.tick}>
                {tr.flows.map((f, i) => (
                  <tr key={i} className={cn('border-t border-white/5 row-in', f.flagged && 'bg-amber-500/[.06]')} style={{ animationDelay: i * 25 + 'ms' }}>
                    <td className="py-1 text-slate-300">{f.src} <span className="text-slate-600">→</span> {f.dst}</td>
                    <td className={f.label ? 'text-red-300' : 'text-white'}>{f.kind}</td>
                    <td className="mono text-slate-400">{f.protocol}</td>
                    <td className="mono text-right text-slate-400">{f.bytes.toLocaleString()}</td>
                    <td className="pl-3">
                      <div className="flex items-center gap-1.5">
                        <Bar value={f.score} color={f.flagged ? '#f59e0b' : '#d4d4d4'} height={4} />
                        <span className="mono text-[10px] w-8 text-right" style={{ color: f.flagged ? '#f59e0b' : '#64748b' }}>{f.score.toFixed(2)}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SubPanel>
        <SubPanel title="Feature extraction" icon="scan-search" color="#94a3b8"
          right={tr.sample && <span className="mono text-[11px] text-slate-400">highest-scoring flow: <span className="text-amber-300">{tr.sample.kind}</span></span>}>
          <div className="grid md:grid-cols-3 gap-3">
            <FeatureGroup title="Traffic features" icon="file-text" color="#d4d4d4" names={state.features.groups.traffic} means={tr.feature_means} sample={tr.sample} featureNames={names} />
            <FeatureGroup title="Graph features" icon="waypoints" color="#d4d4d4" names={state.features.groups.graph} means={tr.feature_means} sample={tr.sample} featureNames={names} />
            <FeatureGroup title="Time-based features" icon="clock" color="#d4d4d4" names={state.features.groups.time} means={tr.feature_means} sample={tr.sample} featureNames={names} />
          </div>
          {tr.sample && (
            <div className="mt-3 panel-inner p-3">
              <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-2">Feature vector x ∈ ℝ¹³ — {tr.sample.src} → {tr.sample.dst} (score {tr.sample.score.toFixed(2)})</div>
              <div className="grid grid-cols-13 gap-1" style={{ gridTemplateColumns: 'repeat(13, minmax(0, 1fr))' }}>
                {tr.sample.x.map((v, i) => {
                  const m = Math.abs(tr.feature_means[names[i]] || 1) || 1;
                  const k = Math.min(1, Math.abs(v) / (m * 2));
                  return (
                    <div key={i} title={`${names[i]} = ${v}`} className="h-9 rounded-md grid place-items-center text-[9px] mono transition-colors duration-500"
                      style={{ background: `rgba(229, 229, 229, ${0.08 + 0.55 * k})` }}>
                      {Math.abs(v) >= 100 ? Math.round(v) : v.toFixed(1)}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </SubPanel>
      </div>
    </Section>
  );
}
