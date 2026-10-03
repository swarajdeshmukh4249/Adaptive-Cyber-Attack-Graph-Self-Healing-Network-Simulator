class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, info) {
    console.error('ErrorBoundary caught an error:', error, info.componentStack);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="boot-screen p-6">
          <h1 className="headline text-3xl">Something went wrong</h1>
          <p className="mono text-sm text-neutral-400 max-w-lg text-center break-words">{String(this.state.error)}</p>
          <button onClick={() => window.location.reload()} className="btn-box btn-white">Reload</button>
        </div>
      );
    }
    return this.props.children;
  }
}

const TOAST_META = {
  attack: { color: '#ef4444', label: 'Attack' },
  detect: { color: '#f59e0b', label: 'Detected' },
  respond: { color: '#10b981', label: 'Response' },
  defense: { color: '#ffffff', label: 'Contained' },
};

// Pop-up notifications for important new security events.
function Toasts({ events }) {
  const [toasts, setToasts] = React.useState([]);
  const seen = React.useRef(null);
  React.useEffect(() => {
    const key = (e) => e.tick + '|' + e.msg;
    if (seen.current === null) { seen.current = new Set(events.map(key)); return; }
    const fresh = events.filter((e) => !seen.current.has(key(e)) && TOAST_META[e.kind]);
    events.forEach((e) => seen.current.add(key(e)));
    const important = fresh.filter((e) => e.kind !== 'respond' || /quarantined|verified clean/.test(e.msg)).slice(0, 3);
    if (!important.length) return;
    const items = important.map((e) => ({ ...e, id: Math.random().toString(36).slice(2) }));
    setToasts((t) => [...items, ...t].slice(0, 4));
    items.forEach((it) => setTimeout(() => setToasts((t) => t.filter((x) => x.id !== it.id)), 4200));
  }, [events]);
  return (
    <div className="fixed top-24 right-5 z-[60] space-y-2 w-[320px] max-w-[calc(100vw-2rem)] pointer-events-none">
      {toasts.map((t) => {
        const m = TOAST_META[t.kind];
        return (
          <div key={t.id} className="toast glass rounded-[10px] p-3.5 flex gap-3 items-start shadow-[0_20px_50px_rgba(0,0,0,.4)]">
            <span className="mt-1.5 h-2 w-2 rounded-full shrink-0" style={{ background: m.color }} />
            <div>
              <div className="eyebrow text-white/50">{m.label} · t{t.tick}</div>
              <div className="text-[13px] text-white/90 leading-snug mt-0.5">{t.msg}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function App() {
  const sim = useSimulation();
  const { state, error, actions } = sim;
  const [scenario, setScenario] = React.useState('apt');

  const breach = !!(state && state.campaign && state.campaign.status === 'breach');
  React.useEffect(() => { document.body.classList.toggle('breach-alert', breach); }, [breach]);

  if (!state) {
    return (
      <div className="boot-screen">
        <div className="boot-ring" />
        <p className="boot-text">{error ? 'Backend unreachable — run: python3 main.py' : 'Connecting to simulator'}</p>
        {error && <p className="mono text-xs text-red-400">{error}</p>}
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <Header state={state} onLaunch={() => actions.launch(scenario)} />
      <Toasts events={state.events} />
      {error && (
        <div className="fixed bottom-5 left-1/2 -translate-x-1/2 z-[70] glass rounded-[8px] px-4 py-2 text-sm text-red-300">
          <Icon name="wifi-off" /> {error}
        </div>
      )}
      <Hero sim={sim} scenario={scenario} setScenario={setScenario} />
      <StatsBand state={state} />
      <ExploreCarousel state={state} actions={actions} />
      <PlatformBand state={state} />
      <section className="band-dark">
        <div className="mx-auto max-w-[1440px] px-6 md:px-10 py-24">
          <div className="text-center mb-12">
            <h2 className="headline text-[44px] md:text-[56px] font-normal">Proof, not promises</h2>
            <p className="mt-4 text-[15px] text-white/60">Outcomes measured from the simulation, plus a Monte-Carlo test of self-healing on vs off.</p>
          </div>
          <SectionOutcomes state={state} />
        </div>
      </section>
      <Footer />
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <ErrorBoundary>
    <App />
  </ErrorBoundary>
);
