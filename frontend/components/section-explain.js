// Section 0: Explain this run.
// Turns the engine's own decision records into something a reader can follow:
// what happened this tick, why each side chose what it chose, and which
// features drove the detector's verdict.

const NARR_META = {
  traffic: { color: '#94a3b8', label: 'Traffic' },
  attack: { color: '#ef4444', label: 'Adversary' },
  defence: { color: '#10b981', label: 'Defence' },
  state: { color: '#d4d4d4', label: 'State' },
};

const POSTURE_COPY = {
  probing: ['Probing', 'Scanning from outside, no entry point committed yet.'],
  advancing: ['Advancing', 'Moving along the highest-probability attack path.'],
  dormant: ['Dormant', 'Noticed the defence and went quiet to avoid another alert.'],
  stalled: ['Stalled', 'No reachable unpatched target left from any foothold.'],
};

// --- the adversary's state of mind, which is what makes its moves legible
function AdversaryMind({ campaign }) {
  if (!campaign) {
    return (
      <div className="text-[12px] text-white/40 py-6 text-center">
        No campaign running. Launch an attack to see the adversary reason.
      </div>
    );
  }
  const heat = campaign.heat || 0;
  const [title, copy] = POSTURE_COPY[campaign.posture] || ['Idle', ''];
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-[15px] font-semibold text-white">{title}</div>
          <div className="text-[11.5px] text-white/50 leading-snug mt-0.5 max-w-[34ch]">{copy}</div>
        </div>
        <Pill color={heat > 0.6 ? '#ef4444' : heat > 0.3 ? '#f59e0b' : '#10b981'} pulse={heat > 0.6}>
          {campaign.status}
        </Pill>
      </div>
      <div>
        <div className="flex justify-between mono text-[10px] text-white/45 mb-1">
          <span>DETECTION PRESSURE</span><span>{heat.toFixed(2)}</span>
        </div>
        <Bar value={heat * 100} color={heat > 0.6 ? '#ef4444' : '#f59e0b'} />
        <div className="text-[10.5px] text-white/40 mt-1.5 leading-snug">
          Rises when the defence takes a foothold away or blocks traffic. Above 0.60 the
          adversary pauses instead of pushing on.
        </div>
      </div>
      <div>
        <div className="flex justify-between mono text-[10px] text-white/45 mb-1">
          <span>BLENDING INTO NORMAL TRAFFIC</span>
          <span>{Math.round((campaign.stealth || 0) * 100)}%</span>
        </div>
        <Bar value={(campaign.stealth || 0) * 100} color="#a78bfa" />
        <div className="text-[10.5px] text-white/40 mt-1.5 leading-snug">
          Under pressure it mimics benign activity harder, which makes it measurably
          more difficult to detect.
        </div>
      </div>
      {!!(campaign.lost || []).length && (
        <div className="mono text-[10.5px] text-white/45">
          Footholds lost: <span className="text-red-300">{campaign.lost.join(', ')}</span>
        </div>
      )}
    </div>
  );
}

// --- why the detector said what it said
function EvidencePanel({ incidents }) {
  const withEvidence = (incidents || []).filter((i) => i.evidence && i.evidence.contributions);
  if (!withEvidence.length) {
    return (
      <div className="text-[12px] text-white/40 py-6 text-center">
        No open incident. When the detector raises one, the features behind its
        verdict appear here.
      </div>
    );
  }
  const inc = withEvidence[0];
  const ev = inc.evidence;
  const max = Math.max(...ev.contributions.map((c) => Math.abs(c.contribution)), 0.01);
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="mono text-[11px] text-white/70">
          {ev.src} → {ev.dst} <span className="text-white/40">({ev.kind})</span>
        </div>
        <Pill color={inc.true_positive ? '#ef4444' : '#f59e0b'}>
          {inc.true_positive ? 'true positive' : 'false positive'}
        </Pill>
      </div>
      <div className="text-[11.5px] text-white/55 leading-snug">
        {ev.model} scored this flow <span className="text-white font-semibold">{ev.score}</span>.
        Each bar is how far the score moves when that one feature is replaced by its
        typical value — the engine's actual reason, not a guess.
      </div>
      <div className="space-y-2">
        {ev.contributions.map((c) => (
          <div key={c.feature}>
            <div className="flex justify-between mono text-[10px] text-white/50">
              <span>{c.feature} <span className="text-white/30">({c.group})</span></span>
              <span>{c.value} <span className="text-white/30">vs {c.typical}</span></span>
            </div>
            <Bar
              value={(Math.abs(c.contribution) / max) * 100}
              color={c.direction === 'raises' ? '#ef4444' : '#38bdf8'}
            />
          </div>
        ))}
      </div>
      <div className="mono text-[10px] text-white/35">
        red = pushed toward “attack” · blue = pushed toward “benign”
      </div>
    </div>
  );
}

function SectionExplain({ state }) {
  const narrative = state.narrative || [];
  const decisions = state.decisions || [];
  const cfg = state.config || {};
  return (
    <Section
      id="explain"
      num="00"
      title="Read This Run"
      subtitle="Every sentence below is generated from the numbers the engine actually acted on — the adversary's reasoning, the detector's evidence and the cost of each response."
      icon="book-open"
      right={<Pill color="#d4d4d4">{state.clock} elapsed</Pill>}
    >
      <div className="grid lg:grid-cols-3 gap-4">
        <SubPanel title="What is happening" icon="activity" className="lg:col-span-2">
          {narrative.length ? (
            <div className="space-y-2.5">
              {narrative.map((l, i) => {
                const m = NARR_META[l.kind] || NARR_META.state;
                return (
                  <div key={i} className="flex gap-2.5 items-start">
                    <span className="mt-[7px] h-1.5 w-1.5 rounded-full shrink-0" style={{ background: m.color }} />
                    <div>
                      <span className="eyebrow mr-2" style={{ color: m.color }}>{m.label}</span>
                      <span className="text-[12.5px] text-white/80 leading-relaxed">{l.text}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-[12px] text-white/40 py-6 text-center">
              Step the simulation to generate a narration.
            </div>
          )}
        </SubPanel>

        <SubPanel title="Inside the adversary" icon="crosshair">
          <AdversaryMind campaign={state.campaign} />
        </SubPanel>

        <SubPanel title="Why the detector fired" icon="brain" className="lg:col-span-2">
          <EvidencePanel incidents={state.incidents} />
        </SubPanel>

        <SubPanel title="Decision trace" icon="list">
          <div className="space-y-2 max-h-[320px] overflow-y-auto pr-1">
            {decisions.length ? decisions.map((d, i) => (
              <div key={i} className="border-l-2 pl-2.5 py-0.5"
                   style={{ borderColor: d.side === 'attacker' ? '#ef4444' : '#10b981' }}>
                <div className="mono text-[9.5px] text-white/40">t{d.tick} · {d.side}</div>
                <div className="text-[11.5px] text-white/85 leading-snug">{d.choice}</div>
                <div className="text-[10.5px] text-white/45 leading-snug">{d.why}</div>
              </div>
            )) : <div className="text-[12px] text-white/40 py-6 text-center">No decisions yet.</div>}
          </div>
        </SubPanel>
      </div>

      <div className="mt-4 grid sm:grid-cols-4 gap-3">
        {[
          ['Clock', state.clock, `1 tick = ${state.tick_seconds}s`],
          ['SOC response delay', `${cfg.latency} ticks`, 'approval before action'],
          ['Alert threshold', Number(cfg.threshold || 0).toFixed(2), 'anomaly score to open an incident'],
          ['Concept drift', Number(cfg.drift || 0).toFixed(2), 'traffic shift since training'],
        ].map(([k, v, note]) => (
          <div key={k} className="glass rounded-[10px] p-3">
            <div className="eyebrow text-white/45">{k}</div>
            <div className="text-[16px] font-semibold text-white mt-0.5">{v}</div>
            <div className="text-[10.5px] text-white/40 leading-snug mt-0.5">{note}</div>
          </div>
        ))}
      </div>
    </Section>
  );
}
