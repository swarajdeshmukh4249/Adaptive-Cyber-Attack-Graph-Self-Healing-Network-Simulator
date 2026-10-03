// REST client + simulation hook. The Python backend owns all simulation state.
const API = {
  async get(path) {
    const r = await fetch('/api/' + path, { cache: 'no-store' });
    if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
    return r.json();
  },
  async post(path, body = {}) {
    const r = await fetch('/api/' + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
    return r.json();
  },
};

const STATUS_COLORS = {
  normal: '#d4d4d4',
  compromised: '#ef4444',
  isolated: '#94a3b8',
  healing: '#10b981',
  attacker: '#ef4444',
};

const KIND_ICONS = {
  attacker: 'icon-skull', cloud: 'icon-cloud', firewall: 'icon-brick-wall-fire', switch: 'icon-network',
  server: 'icon-server', db: 'icon-database', workstation: 'icon-monitor', atm: 'icon-landmark',
  critical: 'icon-shield-alert', monitor: 'icon-radar',
};

function useSimulation() {
  const [state, setState] = React.useState(null);
  const [playing, setPlaying] = React.useState(false);
  const [speed, setSpeed] = React.useState(1);
  const [error, setError] = React.useState(null);
  const busy = React.useRef(false);

  const run = React.useCallback(async (fn) => {
    if (busy.current) return;
    busy.current = true;
    try {
      const s = await fn();
      if (s && s.tick !== undefined) setState(s);
      setError(null);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      busy.current = false;
    }
  }, []);

  React.useEffect(() => { run(() => API.get('state')); }, [run]);

  React.useEffect(() => {
    if (!playing) return;
    const id = setInterval(() => run(() => API.post('step', { n: 1 })), Math.round(1000 / speed));
    return () => clearInterval(id);
  }, [playing, speed, run]);

  const actions = React.useMemo(() => ({
    step: (n = 1) => run(() => API.post('step', { n })),
    reset: (scenario) => { setPlaying(false); run(() => API.post('reset', { scenario })); },
    launch: (scenario) => { run(() => API.post('launch', { scenario })); setPlaying(true); },
    config: (cfg) => run(() => API.post('config', cfg)),
    heal: (node) => run(() => API.post('heal', { node })),
    tamper: () => run(() => API.post('chain/tamper')),
    repair: () => run(() => API.post('chain/repair')),
  }), [run]);

  return { state, playing, setPlaying, speed, setSpeed, error, actions };
}

// Fires `cb` once whenever `value` changes (after first render).
function useOnChange(value, cb) {
  const prev = React.useRef(value);
  React.useEffect(() => {
    if (prev.current !== value) {
      cb(value, prev.current);
      prev.current = value;
    }
  }, [value]);
}

function hostLabel(state, id) {
  const h = state && state.network.hosts.find((x) => x.id === id);
  return h ? h.label : id;
}
