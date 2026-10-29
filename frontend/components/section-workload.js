// Section 5b: Workload failover.
// The payoff of self-healing: when a server is quarantined the *work* it was
// doing moves to a standby, and you can watch it move.

const SVC_STATUS = {
  live: { color: '#10b981', label: 'live' },
  degraded: { color: '#f59e0b', label: 'degraded' },
  failing_over: { color: '#38bdf8', label: 'switching' },
  down: { color: '#ef4444', label: 'down' },
};

function ServiceRow({ svc, hosts }) {
  const m = SVC_STATUS[svc.status] || SVC_STATUS.live;
  const hostLabel = (id) => (hosts.find((h) => h.id === id) || {}).label || id;
  return (
    <div className="glass rounded-[10px] p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[13px] text-white font-semibold truncate">{svc.label}</div>
          <div className="mono text-[10px] text-white/45 truncate">
            {svc.home ? 'home' : 'on standby'} · {hostLabel(svc.host)}
          </div>
        </div>
        <Pill color={m.color} pulse={svc.status === 'failing_over'}>{m.label}</Pill>
      </div>

      {/* primary -> standby track, with a marker showing where the work actually is */}
      <div className="mt-2.5 flex items-center gap-2">
        <div className={cn('flex-1 rounded-[6px] px-2 py-1 border text-[10px] truncate',
          svc.host === svc.primary ? 'border-emerald-400/50 text-emerald-200 bg-emerald-400/10'
                                   : 'border-white/10 text-white/35')}>
          {hostLabel(svc.primary)}
        </div>
        <Icon name="arrow-right" className={cn('h-3 w-3 shrink-0',
          svc.home ? 'text-white/20' : 'text-sky-300')} />
        <div className={cn('flex-1 rounded-[6px] px-2 py-1 border text-[10px] truncate',
          !svc.home ? 'border-sky-400/50 text-sky-200 bg-sky-400/10'
                    : 'border-white/10 text-white/35')}>
          {svc.standbys.map(hostLabel).join(', ') || '—'}
        </div>
      </div>

      {svc.status === 'failing_over' && (
        <div className="mono text-[10px] text-sky-300 mt-1.5">
          switching over — back in {svc.eta} tick{svc.eta === 1 ? '' : 's'}
        </div>
      )}
      {svc.downtime > 0 && svc.status !== 'failing_over' && (
        <div className="mono text-[10px] text-white/35 mt-1.5">
          {svc.downtime} tick{svc.downtime === 1 ? '' : 's'} of downtime so far
        </div>
      )}
    </div>
  );
}

function HostLoad({ id, info, hosts }) {
  const label = (hosts.find((h) => h.id === id) || {}).label || id;
  const pct = Math.min(info.util, 1.4) * 100;
  return (
    <div>
      <div className="flex justify-between mono text-[10px] text-white/50 mb-1">
        <span className="truncate">{label}</span>
        <span className={info.over ? 'text-amber-300' : 'text-white/40'}>
          {info.load.toFixed(2)} / {info.capacity.toFixed(2)}
        </span>
      </div>
      <Bar value={Math.min(pct, 100)} color={info.over ? '#f59e0b' : '#10b981'} />
    </div>
  );
}

function SectionWorkload({ state }) {
  const sv = state.services || { services: [], hosts: {}, availability: 100 };
  const hosts = (state.network && state.network.hosts) || [];
  const events = state.service_events || [];
  const av = sv.availability;
  const carrying = Object.entries(sv.hosts || {})
    .filter(([, v]) => v.services.length)
    .sort((a, b) => b[1].util - a[1].util);

  return (
    <Section
      id="workload"
      num="05b"
      title="Workload Failover"
      subtitle="Isolating a server protects the network but stops the work. These services move to a hot standby when their host is quarantined, and move back once it is verified clean — that is what self-healing actually buys you."
      icon="server"
      right={
        <Pill color={av >= 99 ? '#10b981' : av >= 85 ? '#f59e0b' : '#ef4444'} pulse={av < 99}>
          {av}% serving
        </Pill>
      }
    >
      <div className="grid lg:grid-cols-3 gap-4">
        <SubPanel title="Business services" icon="layers" className="lg:col-span-2">
          <div className="grid sm:grid-cols-2 gap-2.5">
            {sv.services.map((s) => <ServiceRow key={s.id} svc={s} hosts={hosts} />)}
          </div>
        </SubPanel>

        <div className="space-y-4">
          <SubPanel title="Service availability" icon="activity">
            <div className="text-center py-1">
              <div className="text-[40px] font-semibold leading-none"
                   style={{ color: av >= 99 ? '#10b981' : av >= 85 ? '#f59e0b' : '#ef4444' }}>
                <CountUp value={av} decimals={1} suffix="%" />
              </div>
              <div className="text-[11px] text-white/45 mt-1">
                business-weighted work serving now
              </div>
            </div>
            <div className="mt-2 pt-2 border-t border-white/10 flex justify-between text-[11px]">
              <span className="text-white/45">run average</span>
              <span className="text-white font-semibold">
                {sv.average_availability != null ? `${sv.average_availability}%` : '—'}
              </span>
            </div>
            <div className="flex justify-between text-[11px] mt-1">
              <span className="text-white/45">on standby hardware</span>
              <span className="text-sky-300 font-semibold">{(sv.displaced || []).length}</span>
            </div>
            <div className="flex justify-between text-[11px] mt-1">
              <span className="text-white/45">fully down</span>
              <span className={cn('font-semibold', (sv.down || []).length ? 'text-red-300' : 'text-white/60')}>
                {(sv.down || []).length}
              </span>
            </div>
            <div className="text-[10.5px] text-white/40 leading-snug mt-2">
              A switchover costs {sv.switchover} ticks offline, so this number is only 100%
              when nothing has had to move.
            </div>
          </SubPanel>

          <SubPanel title="Host load" icon="cpu">
            <div className="space-y-2">
              {carrying.length
                ? carrying.map(([id, info]) => <HostLoad key={id} id={id} info={info} hosts={hosts} />)
                : <div className="text-[12px] text-white/40 py-3 text-center">No load.</div>}
            </div>
            <div className="text-[10.5px] text-white/40 leading-snug mt-2">
              Amber means a host is carrying more work than it is rated for — it keeps
              serving, but degraded.
            </div>
          </SubPanel>
        </div>
      </div>

      <SubPanel title="Failover log" icon="list" className="mt-4">
        {events.length ? (
          <div className="space-y-1.5 max-h-[180px] overflow-y-auto pr-1">
            {events.map((e, i) => (
              <div key={i} className="flex gap-2.5 items-start">
                <span className="mono text-[10px] text-white/35 w-9 shrink-0 mt-[2px]">t{e.tick}</span>
                <span className="mt-[6px] h-1.5 w-1.5 rounded-full shrink-0"
                      style={{ background: e.kind === 'down' ? '#ef4444'
                                         : e.kind === 'failback' ? '#10b981' : '#38bdf8' }} />
                <span className="text-[12px] text-white/80 leading-snug">{e.text}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-[12px] text-white/40 py-4 text-center">
            Nothing has had to move yet. Launch an attack and watch a server get quarantined.
          </div>
        )}
      </SubPanel>
    </Section>
  );
}
