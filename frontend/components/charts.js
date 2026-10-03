// Lightweight SVG / canvas charts with built-in motion.

function Gauge({ value = 0, size = 120, color = '#ef4444', label }) {
  const r = size / 2 - 10;
  const c = Math.PI * r; // half circle
  const v = Math.max(0, Math.min(1, value));
  const id = React.useId ? React.useId().replace(/:/g, '') : 'g' + Math.random().toString(36).slice(2);
  return (
    <svg width={size} height={size / 2 + 18} viewBox={`0 0 ${size} ${size / 2 + 18}`}>
      <defs>
        <linearGradient id={`gg${id}`} x1="0" x2="1">
          <stop offset="0%" stopColor="#10b981" />
          <stop offset="55%" stopColor="#f59e0b" />
          <stop offset="100%" stopColor="#ef4444" />
        </linearGradient>
      </defs>
      <path d={`M 10 ${size / 2} A ${r} ${r} 0 0 1 ${size - 10} ${size / 2}`} fill="none" stroke="rgba(255,255,255,.08)" strokeWidth="10" strokeLinecap="round" />
      <path
        d={`M 10 ${size / 2} A ${r} ${r} 0 0 1 ${size - 10} ${size / 2}`}
        fill="none" stroke={`url(#gg${id})`} strokeWidth="10" strokeLinecap="round"
        strokeDasharray={c} strokeDashoffset={c * (1 - v)}
        style={{ transition: 'stroke-dashoffset .9s cubic-bezier(.2,.8,.2,1)', filter: `drop-shadow(0 0 6px ${color})` }}
      />
      <g style={{ transform: `rotate(${-90 + v * 180}deg)`, transformOrigin: `${size / 2}px ${size / 2}px`, transition: 'transform .9s cubic-bezier(.2,.8,.2,1)' }}>
        <line x1={size / 2} y1={size / 2} x2={size / 2} y2={22} stroke="#fff" strokeWidth="2.5" strokeLinecap="round" />
      </g>
      <circle cx={size / 2} cy={size / 2} r="5" fill="#fff" />
      {label && <text x={size / 2} y={size / 2 + 16} textAnchor="middle" className="mono" fontSize="11" fill="#94a3b8">{label}</text>}
    </svg>
  );
}

function LineChart({ series, height = 150, max, min = 0, xKey = 'tick', data }) {
  const w = 600;
  const h = height;
  const pad = 6;
  const pts = data || [];
  const id = React.useId ? React.useId().replace(/:/g, '') : 'l' + Math.random().toString(36).slice(2);
  if (pts.length < 2) {
    return <div className="grid place-items-center text-xs text-slate-500 mono" style={{ height }}>waiting for telemetry…</div>;
  }
  const hi = max != null ? max : Math.max(1, ...series.flatMap((s) => pts.map((p) => p[s.key] || 0)));
  const x = (i) => pad + (i / (pts.length - 1)) * (w - pad * 2);
  const y = (v) => h - pad - ((v - min) / (hi - min || 1)) * (h - pad * 2);
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="w-full" style={{ height }}>
      <defs>
        {series.map((s) => (
          <linearGradient key={s.key} id={`a${id}${s.key}`} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={s.color} stopOpacity=".45" />
            <stop offset="100%" stopColor={s.color} stopOpacity="0" />
          </linearGradient>
        ))}
      </defs>
      {[0.25, 0.5, 0.75].map((g) => (
        <line key={g} x1="0" x2={w} y1={h * g} y2={h * g} stroke="rgba(148,163,184,.08)" strokeDasharray="4 6" />
      ))}
      {series.map((s) => {
        const line = pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[s.key] || 0).toFixed(1)}`).join(' ');
        const last = pts[pts.length - 1];
        return (
          <g key={s.key}>
            {s.area !== false && <path d={`${line} L${x(pts.length - 1)},${h} L${x(0)},${h} Z`} fill={`url(#a${id}${s.key})`} />}
            <path d={line} fill="none" stroke={s.color} strokeWidth="2.2" vectorEffect="non-scaling-stroke" style={{ filter: `drop-shadow(0 0 4px ${s.color})` }} />
            <circle cx={x(pts.length - 1)} cy={y(last[s.key] || 0)} r="4" fill={s.color}>
              <animate attributeName="r" values="3;6;3" dur="1.4s" repeatCount="indefinite" />
            </circle>
          </g>
        );
      })}
    </svg>
  );
}

// Continuously scrolling oscilloscope-style waveform drawn on canvas.
function WaveCanvas({ data = [], color = '#d4d4d4', height = 90, label }) {
  const ref = React.useRef(null);
  const dataRef = React.useRef(data);
  dataRef.current = data;
  React.useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext('2d');
    let raf;
    let offset = 0;
    const draw = () => {
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      if (canvas.width !== w * dpr) { canvas.width = w * dpr; canvas.height = h * dpr; }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      const d = dataRef.current.length ? dataRef.current.slice(-120) : [0];
      const maxV = Math.max(4, ...d);
      offset += 0.6;
      const step = w / 110;
      ctx.lineWidth = 2;
      ctx.shadowBlur = 14;
      ctx.shadowColor = color;
      ctx.strokeStyle = color;
      ctx.beginPath();
      for (let i = 0; i <= 110; i++) {
        const idx = Math.floor((i + offset / step) % d.length);
        const base = d[(idx + d.length) % d.length] / maxV;
        const jitter = Math.sin((i + offset) * 0.55) * 0.35 + Math.sin((i + offset) * 1.7) * 0.15;
        const amp = base * (h * 0.42) * (0.7 + jitter);
        const yy = h / 2 + (i % 2 ? amp : -amp) * Math.sin(i * 0.9 + offset * 0.05);
        i ? ctx.lineTo(i * step, yy) : ctx.moveTo(0, yy);
      }
      ctx.stroke();
      ctx.shadowBlur = 0;
      ctx.strokeStyle = 'rgba(148,163,184,.12)';
      ctx.beginPath(); ctx.moveTo(0, h / 2); ctx.lineTo(w, h / 2); ctx.stroke();
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => cancelAnimationFrame(raf);
  }, [color]);
  return (
    <div className="relative">
      <canvas ref={ref} className="w-full" style={{ height }} />
      {label && <div className="absolute bottom-1 left-0 right-0 text-center text-sm text-slate-300">{label}</div>}
    </div>
  );
}

function Donut({ value = 0, size = 64, color = '#10b981', stroke = 7, children }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90 absolute inset-0">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,.08)" strokeWidth={stroke} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - Math.max(0, Math.min(1, value)))}
          style={{ transition: 'stroke-dashoffset .9s cubic-bezier(.2,.8,.2,1), stroke .5s', filter: `drop-shadow(0 0 5px ${color})` }} />
      </svg>
      <div className="relative text-center leading-none">{children}</div>
    </div>
  );
}
