// Discrete Mathematics concepts - each card shows values computed live by the engine.

function DMCard({ title, icon, glyph, children, i }) {
  const t = useTilt(12);
  return (
    <div ref={t.ref} onMouseMove={t.onMouseMove} onMouseLeave={t.onMouseLeave}
      className="tilt relative panel-inner p-3.5 hover:border-slate-500/50"
      style={{ animationDelay: i * 70 + 'ms' }}>
      <div className="tilt-shine" />
      <div className="tilt-depth">
        <div className="flex items-center justify-between mb-2">
          <h4 className="font-bold text-white text-[14px]">{title}</h4>
          <span className="text-slate-500 text-lg font-serif italic">{glyph || <Icon name={icon} />}</span>
        </div>
        <div className="text-[11.5px] text-slate-300 space-y-1">{children}</div>
      </div>
    </div>
  );
}

const KV = ({ k, v, c = 'text-slate-200' }) => (
  <div className="flex justify-between gap-2"><span className="text-slate-400">{k}</span><span className={cn('mono text-right', c)}>{v}</span></div>
);

function SectionDM({ state }) {
  const d = state.dm;
  const setStr = (a) => (a.length ? `{${a.join(', ')}}` : '∅');
  return (
    <Section id="dm" title="Discrete Mathematics (DM) Concepts Used" color="amber" icon="sigma"
      subtitle="Several DM concepts are applied in modelling, analysis and design of the system — the values below are computed by the engine in real time.">
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-7 gap-3">
        <DMCard i={0} title="Graphs" icon="share-2">
          <KV k="|V| hosts" v={d.graphs.V} /><KV k="|E| links" v={d.graphs.E} />
          <KV k="attack edges (directed)" v={d.graphs.attack_edges} /><KV k="avg degree" v={d.graphs.avg_degree} />
        </DMCard>
        <DMCard i={1} title="Sets" icon="circle-dot">
          <KV k="|V|" v={d.sets.V} /><KV k="C (compromised)" v={setStr(d.sets.C)} c="text-red-300" />
          <KV k="I (isolated)" v={setStr(d.sets.I)} c="text-white" /><KV k="|R| reachable" v={d.sets.R} />
          <KV k="R ∩ critical" v={setStr(d.sets.R_cap_critical)} c="text-amber-300" />
        </DMCard>
        <DMCard i={2} title="Combinatorics" glyph="ⁿCᵣ">
          <KV k="simple attack paths" v={d.combinatorics.paths.toLocaleString()} c="text-red-300" />
          <KV k="baseline paths" v={d.combinatorics.baseline_paths.toLocaleString()} />
          <KV k={`C(|V|, 2) host pairs`} v={d.combinatorics.pairs} />
          <KV k="orderings of best path" v={d.combinatorics.orderings} />
        </DMCard>
        <DMCard i={3} title="Logic" glyph="∧∨¬">
          {d.logic.map((r) => (
            <div key={r.rule} className="flex gap-1.5 items-start">
              <span className={cn('mono text-[10px] px-1 rounded', r.value ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-700/60 text-slate-400')}>{r.value ? 'T' : 'F'}</span>
              <span className="mono text-[10px] leading-snug text-slate-300">{r.rule}</span>
            </div>
          ))}
        </DMCard>
        <DMCard i={4} title="Relations" glyph="A→B">
          <KV k="relation |R|" v={d.relations.edges} />
          <KV k="transitive closure R⁺" v={d.relations.closure_pairs} />
          <KV k="max pairs |V|²" v={d.relations.max_pairs} />
          <div className="text-[10px] text-slate-500">Warshall's algorithm over reachability</div>
        </DMCard>
        <DMCard i={5} title="Trees" icon="network">
          <KV k="attack tree depth" v={d.trees.attack_tree_depth} /><KV k="attack tree leaves" v={d.trees.attack_tree_leaves} />
          <KV k="RF decision-tree depth" v={d.trees.rf_depth} />
          <div className="text-[10px] text-slate-500">BFS tree rooted at the attacker</div>
        </DMCard>
        <DMCard i={6} title="Probability" icon="chart-column">
          <KV k="P(best path)" v={d.probability.best_path_p} c="text-red-300" />
          <KV k="P(breach critical)" v={d.probability.breach_p} c="text-red-300" />
          <div className="text-[10px] text-slate-400 mono break-words">{(d.probability.best_path || []).join(' → ') || 'no path'}</div>
          <div className="text-[10px] text-slate-500">noisy-OR Bayesian attack graph</div>
        </DMCard>
      </div>
    </Section>
  );
}
