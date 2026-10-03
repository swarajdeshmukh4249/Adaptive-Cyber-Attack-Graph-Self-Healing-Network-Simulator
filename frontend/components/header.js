const NAV = [
  ['network', 'Network'], ['attack-graph', 'Attack graph'], ['detection', 'Detection'],
  ['response', 'Self-healing'], ['ledger', 'Ledger'],
];

const PHASE_META = {
  monitor: { color: '#d4d4d4', label: 'Monitoring' },
  detect: { color: '#f59e0b', label: 'Detecting' },
  respond: { color: '#ef4444', label: 'Responding' },
  recover: { color: '#10b981', label: 'Recovering' },
};

// Opens a pipeline tab in the "Explore" carousel and scrolls to it.
function openTab(id) {
  window.dispatchEvent(new CustomEvent('open-tab', { detail: id }));
  const el = document.getElementById('explore');
  if (el) el.scrollIntoView({ behavior: 'smooth' });
}

function Header({ state, onLaunch }) {
  const [scrolled, setScrolled] = React.useState(false);
  React.useEffect(() => {
    const on = () => setScrolled(window.scrollY > 40);
    on();
    window.addEventListener('scroll', on, { passive: true });
    return () => window.removeEventListener('scroll', on);
  }, []);
  const phase = PHASE_META[state.phase] || PHASE_META.monitor;
  const active = state.campaign && state.campaign.status === 'active';
  return (
    <header className={cn('fixed top-0 inset-x-0 z-50 transition-all duration-500 text-white',
      scrolled ? 'bg-black/90 backdrop-blur-md border-b border-white/10' : 'bg-transparent')}>
      <div className="mx-auto max-w-[1440px] px-6 md:px-10 h-[72px] flex items-center gap-8">
        <a href="#top" className="flex items-center gap-2.5 shrink-0">
          <div className="logo3d"><div className="cube">
            {['f1', 'f2', 'f3', 'f4', 'f5', 'f6'].map((f) => <div key={f} className={'face ' + f} />)}
          </div></div>
          <span className="text-[15px] font-semibold tracking-[0.14em] uppercase">CyberHeal</span>
        </a>
        <nav className="hidden lg:flex items-center gap-7 mx-auto">
          {NAV.map(([id, label]) => (
            <button key={id} onClick={() => openTab(id)} className="text-[12px] font-medium uppercase tracking-[0.1em] text-white/80 hover:text-white transition-colors">{label}</button>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-6">
          <div className="hidden md:flex items-center gap-2 text-[12px] uppercase tracking-[0.1em] text-white/70">
            <span className="h-1.5 w-1.5 rounded-full pulse-dot" style={{ background: phase.color, color: phase.color }} />
            {phase.label} · <span className="mono normal-case tracking-normal">t{state.tick}</span>
          </div>
          <button onClick={onLaunch} disabled={active} className="btn-box btn-white !py-3 !px-5">
            {active ? 'Attack running' : 'Launch attack'}
          </button>
        </div>
      </div>
    </header>
  );
}
