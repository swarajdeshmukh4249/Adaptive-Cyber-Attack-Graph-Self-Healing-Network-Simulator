// Shared UI building blocks: glowing 3D tilt cards, sections, counters, pills.

function Icon({ name, className = '', style }) {
  return <i className={cn(`icon-${name}`, 'inline-block leading-none', className)} style={style} aria-hidden="true" />;
}

function useReveal() {
  const ref = React.useRef(null);
  React.useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }),
      { threshold: 0.08 }
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return ref;
}

// 3D tilt that follows the pointer, with a moving specular shine.
function useTilt(max = 7) {
  const ref = React.useRef(null);
  const onMove = React.useCallback((e) => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width;
    const py = (e.clientY - r.top) / r.height;
    el.style.transform = `perspective(1100px) rotateX(${(0.5 - py) * max}deg) rotateY(${(px - 0.5) * max}deg) translateZ(0)`;
    el.style.setProperty('--mx', `${px * 100}%`);
    el.style.setProperty('--my', `${py * 100}%`);
    el.style.setProperty('--shine', '1');
  }, [max]);
  const onLeave = React.useCallback(() => {
    const el = ref.current;
    if (!el) return;
    el.style.transform = 'perspective(1100px) rotateX(0) rotateY(0)';
    el.style.setProperty('--shine', '0');
  }, []);
  return { ref, onMouseMove: onMove, onMouseLeave: onLeave };
}

function GlowCard({ children, className = '', innerClassName = '', tilt = true, maxTilt = 6, style }) {
  const t = useTilt(maxTilt);
  const handlers = tilt ? { onMouseMove: t.onMouseMove, onMouseLeave: t.onMouseLeave } : {};
  return (
    <div ref={t.ref} className={cn('tilt relative rounded-[14px] p-px', className)} style={style} {...handlers}>
      <GlowingEffect variant="mono" blur={0} borderWidth={1.5} spread={60} glow={true} disabled={false} proximity={80} inactiveZone={0.01} />
      <div className={cn('card-dark relative h-full rounded-[13px] overflow-hidden', innerClassName)}>
        <div className="tilt-shine" />
        {children}
      </div>
    </div>
  );
}

// Squarespace-style feature card: large light title, muted lede, content.
function Section({ id, num, title, subtitle, icon, children, className = '', right }) {
  return (
    <section id={id} className={cn('card-dark rounded-[12px] p-6 md:p-8 scroll-mt-28', className)}>
      <div className="flex items-start justify-between gap-4 mb-6">
        <div className="max-w-3xl">
          {num != null && <div className="text-[11px] uppercase tracking-[0.18em] text-neutral-500 mb-2">Step {String(num).padStart(2, '0')}</div>}
          <h2 className="font-display text-[28px] md:text-[34px] font-normal leading-[1.1] tracking-[-0.025em] text-white">{title}</h2>
          {subtitle && <p className="mt-3 text-[15px] leading-relaxed text-neutral-400">{subtitle}</p>}
        </div>
        {right}
      </div>
      {children}
    </section>
  );
}

function CountUp({ value, decimals = 0, duration = 700, prefix = '', suffix = '' }) {
  const [shown, setShown] = React.useState(typeof value === 'number' ? value : 0);
  const from = React.useRef(shown);
  React.useEffect(() => {
    if (typeof value !== 'number' || Number.isNaN(value)) return;
    const start = performance.now();
    const a = from.current;
    let raf;
    const tick = (now) => {
      const k = Math.min(1, (now - start) / duration);
      const e = 1 - Math.pow(1 - k, 3);
      const v = a + (value - a) * e;
      setShown(v);
      if (k < 1) raf = requestAnimationFrame(tick);
      else from.current = value;
    };
    raf = requestAnimationFrame(tick);
    return () => { cancelAnimationFrame(raf); from.current = value; };
  }, [value, duration]);
  if (value == null || Number.isNaN(value)) return <span>—</span>;
  return <span>{prefix}{shown.toFixed(decimals)}{suffix}</span>;
}

function Pill({ children, color = '#d4d4d4', className = '', pulse = false }) {
  return (
    <span
      className={cn('inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider border', className)}
      style={{ color, borderColor: color + '66', background: color + '1a' }}
    >
      {pulse && <span className="pulse-dot inline-block h-1.5 w-1.5 rounded-full" style={{ background: color, color }} />}
      {children}
    </span>
  );
}

function SubPanel({ title, icon, color: _ignored, color2 = '#94a3b8', children, className = '', right }) {
  return (
    <div className={cn('panel-inner p-4 relative', className)}>
      {title && (
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-[13px] font-medium text-neutral-300 flex items-center gap-2">
            {icon && <Icon name={icon} className="text-neutral-500" />} {title}
          </h3>
          {right}
        </div>
      )}
      {children}
    </div>
  );
}

function Bar({ value, color = '#d4d4d4', height = 6, className = '' }) {
  const pct = Math.max(0, Math.min(1, value || 0)) * 100;
  return (
    <div className={cn('w-full rounded-full bg-white/5 overflow-hidden', className)} style={{ height }}>
      <div className="h-full rounded-full bar-anim" style={{ width: pct + '%', background: `linear-gradient(90deg, ${color}99, ${color})`, boxShadow: `0 0 10px ${color}` }} />
    </div>
  );
}
