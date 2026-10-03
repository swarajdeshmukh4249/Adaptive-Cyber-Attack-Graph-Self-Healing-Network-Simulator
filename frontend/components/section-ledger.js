// Section 7: Logging & Audit (Blockchain)

const EVENT_BADGE = {
  GENESIS: '#94a3b8', ATTACK_DETECTED: '#ef4444', RECOVERY_COMPLETED: '#10b981', CAMPAIGN_CONTAINED: '#d4d4d4',
};

function Block3D({ b, bad, isNew }) {
  const color = EVENT_BADGE[b.event] || (b.event.startsWith('RESPONSE') ? '#d4d4d4' : '#d4d4d4');
  return (
    <div className={cn('block3d', bad && 'bad shake', isNew && 'block-new')}>
      <div className="bf front">
        <div className="flex items-center justify-between">
          <span className="mono text-[10px] text-emerald-300">#{b.index}</span>
          <span className="mono text-[9px] text-slate-400">t{b.tick}</span>
        </div>
        <div className="text-[10px] font-bold mt-1 leading-tight" style={{ color }}>{b.event.replace(/_/g, ' ')}</div>
        <div className="text-[9px] text-slate-400 truncate">{b.data.node || b.data.scenario || b.data.message || ''}</div>
        <div className="mono text-[8.5px] text-slate-500 mt-1 truncate">prev {b.prev_hash.slice(0, 10)}…</div>
        <div className={cn('mono text-[8.5px] truncate', bad ? 'text-red-300' : 'text-emerald-300')}>hash {b.hash.slice(0, 12)}…</div>
        <div className="mono text-[8.5px] text-slate-500">nonce {b.nonce}</div>
      </div>
      <div className="bf back" /><div className="bf right" /><div className="bf left" /><div className="bf top" /><div className="bf bottom" />
    </div>
  );
}

function SectionLedger({ state, actions }) {
  const ch = state.chain;
  const v = ch.verify;
  const seen = React.useRef(new Set());
  const blocks = ch.blocks;
  const fresh = blocks.filter((b) => !seen.current.has(b.hash)).map((b) => b.hash);
  React.useEffect(() => { blocks.forEach((b) => seen.current.add(b.hash)); });
  const recent = blocks.slice(-7);
  return (
    <Section id="ledger" num={7} title="Logging & Audit (Blockchain)" color="lime" icon="link"
      subtitle="Every confirmed attack and defensive response is recorded in a SHA-256 hash-chained ledger with proof-of-work, giving an immutable, tamper-evident audit trail. Try tampering with a record to see the chain break."
      right={<Pill color={v.valid ? '#10b981' : '#ef4444'} pulse>{v.valid ? 'chain verified' : 'tampering detected'}</Pill>}>
      <div className="grid xl:grid-cols-[300px_1fr] gap-4">
        <SubPanel title="Event logging" icon="clipboard-check" color="#94a3b8">
          <ul className="space-y-1.5 text-[13px]">
            {['Attack detected', 'Node isolated', 'Rule updated', 'Recovery completed', 'Timestamp & details'].map((t) => (
              <li key={t} className="flex items-center gap-2 text-slate-300"><Icon name="check" className="text-emerald-400" /> {t}</li>
            ))}
          </ul>
          <div className="mt-4 grid grid-cols-2 gap-2 text-center">
            <div className="panel-inner p-2"><div className="text-[10px] uppercase text-slate-500">blocks</div><div className="mono text-lg text-emerald-300"><CountUp value={ch.length} /></div></div>
            <div className="panel-inner p-2"><div className="text-[10px] uppercase text-slate-500">difficulty</div><div className="mono text-lg text-emerald-300">{'0'.repeat(ch.difficulty)}…</div></div>
          </div>
          <div className="mt-3 flex gap-2">
            <button onClick={actions.tamper} className="btn-cyber flex-1 rounded-lg py-2 text-[12px] font-semibold bg-red-600/80 text-white"><Icon name="skull" /> Tamper</button>
            <button onClick={actions.repair} className="btn-cyber flex-1 rounded-lg py-2 text-[12px] font-semibold bg-emerald-600/80 text-white"><Icon name="wrench" /> Re-sync</button>
          </div>
          <div className={cn('mt-3 text-[11px] mono rounded-lg p-2', v.valid ? 'text-emerald-300 bg-emerald-500/10' : 'text-red-300 bg-red-500/10 shake')}>
            {v.valid ? '✔ ' + v.reason : `✘ block #${v.broken_at}: ${v.reason}`}
          </div>
        </SubPanel>
        <SubPanel title="Blockchain (smart-contract ledger)" icon="blocks" color="#94a3b8">
          <div className="chain-scroller overflow-x-auto overflow-y-visible py-8 px-4">
            <div className="flex items-center gap-10 min-w-max">
              {recent.map((b, i) => (
                <React.Fragment key={b.index}>
                  <Block3D b={b} bad={v.broken_at != null && b.index >= v.broken_at} isNew={fresh.includes(b.hash)} />
                  {i < recent.length - 1 && <Icon name="arrow-right" className={cn('text-xl', v.broken_at != null && b.index + 1 === v.broken_at ? 'text-red-500' : 'text-emerald-400')} />}
                </React.Fragment>
              ))}
            </div>
          </div>
          <div className="grid sm:grid-cols-4 gap-2 mt-1 text-[12px] text-slate-300">
            {['Immutable records', 'Tamper-proof audit trail', 'Ensures accountability', 'Fit for financial / ATM environments'].map((t) => (
              <div key={t} className="flex items-center gap-1.5"><Icon name="lock" className="text-emerald-400" /> {t}</div>
            ))}
          </div>
        </SubPanel>
      </div>
    </Section>
  );
}
