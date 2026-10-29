"""Workload layer (the self-healing payoff).

Hosts are machines; *services* are the work those machines do. When the defence
quarantines a host, the work running on it does not simply vanish -- it fails over
to a hot standby, and that is what "the network heals itself" actually means.

Failover is not free, which is the point:

* a switchover takes `SWITCHOVER` ticks during which the service is **down**;
* the receiving host has finite capacity, so absorbing extra load can push it
  into a **degraded** state where it is up but over-subscribed;
* if no healthy eligible host exists the service stays **down**.

The headline metric is therefore service availability -- the share of
business-weighted work that was actually serving over the run. It is a far more
honest measure of self-healing than counting isolated hosts.
"""
from __future__ import annotations

from typing import Dict, List, Optional

# Ticks a service spends offline while it moves between hosts.
SWITCHOVER = 2

# How much work each kind of machine can carry before it is over-subscribed.
CAPACITY = {
    "server": 1.0, "db": 1.0, "critical": 1.2,
    "workstation": 0.5, "atm": 0.5, "monitor": 0.8,
}

LIVE, FAILING, DEGRADED, DOWN = "live", "failing_over", "degraded", "down"


class Service:
    """A unit of business work that runs on some host and can move."""

    def __init__(self, sid: str, label: str, tier: float, load: float,
                 primary: str, standbys: List[str]) -> None:
        self.id = sid
        self.label = label
        self.tier = tier              # business weight: how much its downtime matters
        self.load = load              # capacity it consumes on its host
        self.primary = primary
        self.standbys = standbys
        self.host = primary
        self.status = LIVE
        self.eta = 0                  # ticks left in a switchover
        self.moves: List[dict] = []
        self.downtime = 0             # ticks spent not serving

    @property
    def serving(self) -> bool:
        return self.status in (LIVE, DEGRADED)

    @property
    def home(self) -> bool:
        return self.host == self.primary

    def to_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label, "tier": self.tier, "load": self.load,
            "primary": self.primary, "standbys": self.standbys, "host": self.host,
            "status": self.status, "eta": self.eta, "home": self.home,
            "downtime": self.downtime, "moves": self.moves[-5:],
        }


def default_services() -> List[Service]:
    return [
        Service("ledger", "Core Ledger", 1.0, 0.8, "core", ["core2"]),
        Service("swift", "SWIFT Gateway", 0.95, 0.4, "core", ["core2"]),
        Service("postgres", "Customer Database", 0.9, 0.7, "db", ["db2"]),
        Service("https", "Internet Banking", 0.8, 0.6, "web", ["web2"]),
        Service("api", "Partner API", 0.6, 0.35, "web", ["web2"]),
        Service("atm-switch", "ATM Switching", 0.85, 0.4, "atm1", ["atm2"]),
        Service("mailflow", "Corporate Mail", 0.4, 0.4, "mail", ["web2"]),
        Service("ad", "Directory / Auth", 0.9, 0.5, "admin", ["backup"]),
    ]


class ServiceLayer:
    def __init__(self, net) -> None:
        self.net = net
        self.services: Dict[str, Service] = {s.id: s for s in default_services()}
        self.events: List[dict] = []
        self.samples: List[float] = []      # availability per tick, for the run average

    switchover_ticks = SWITCHOVER

    # ------------------------------------------------------------------ helpers
    def on_host(self, host: str) -> List[Service]:
        return [s for s in self.services.values() if s.host == host and s.serving]

    def load_on(self, host: str) -> float:
        return round(sum(s.load for s in self.on_host(host)), 3)

    def capacity_of(self, host: str) -> float:
        return CAPACITY.get(self.net.hosts[host].kind, 1.0)

    def healthy(self, host: str) -> bool:
        h = self.net.hosts.get(host)
        return bool(h) and h.status == "normal"

    def _best_target(self, svc: Service, exclude: str) -> Optional[str]:
        """Pick the healthy eligible host with the most headroom."""
        options = [h for h in [svc.primary] + svc.standbys
                   if h != exclude and self.healthy(h)]
        if not options:
            return None
        return max(options, key=lambda h: self.capacity_of(h) - self.load_on(h))

    # ------------------------------------------------------------------ main step
    def step(self, tick: int) -> List[dict]:
        """Advance switchovers, trigger failover/failback, recompute health."""
        self.events = []

        for svc in self.services.values():
            # a switchover in progress
            if svc.status == FAILING:
                svc.eta -= 1
                svc.downtime += 1
                if svc.eta <= 0:
                    svc.status = LIVE
                    self.events.append({
                        "kind": "online", "service": svc.id, "host": svc.host, "tick": tick,
                        "text": f"{svc.label} is serving again from "
                                f"{self.net.hosts[svc.host].label}",
                    })
                continue

            host_ok = self.healthy(svc.host)

            # the host carrying this service has been taken off the network
            if not host_ok:
                target = self._best_target(svc, exclude=svc.host)
                if target is None:
                    if svc.status != DOWN:
                        svc.status = DOWN
                        self.events.append({
                            "kind": "down", "service": svc.id, "host": svc.host, "tick": tick,
                            "text": f"{svc.label} is DOWN - no healthy host left to take it",
                        })
                    svc.downtime += 1
                    continue
                frm = svc.host
                svc.moves.append({"tick": tick, "from": frm, "to": target})
                svc.host = target
                svc.status = FAILING
                svc.eta = SWITCHOVER
                svc.downtime += 1
                self.events.append({
                    "kind": "failover", "service": svc.id, "from": frm, "to": target, "tick": tick,
                    "text": f"{svc.label} failing over from {self.net.hosts[frm].label} "
                            f"to {self.net.hosts[target].label} "
                            f"({SWITCHOVER} tick switchover)",
                })
                continue

            # the original home is clean again -> move the work back
            if not svc.home and self.healthy(svc.primary):
                frm = svc.host
                svc.moves.append({"tick": tick, "from": frm, "to": svc.primary})
                svc.host = svc.primary
                svc.status = FAILING
                svc.eta = SWITCHOVER
                svc.downtime += 1
                self.events.append({
                    "kind": "failback", "service": svc.id, "from": frm, "to": svc.primary,
                    "tick": tick,
                    "text": f"{svc.label} failing back to "
                            f"{self.net.hosts[svc.primary].label} now that it is verified clean",
                })
                continue

            svc.status = LIVE

        # over-subscription: a host carrying more than it can handle is degraded
        for host in {s.host for s in self.services.values()}:
            if self.load_on(host) > self.capacity_of(host):
                for s in self.on_host(host):
                    if s.status == LIVE:
                        s.status = DEGRADED

        self.samples.append(self.availability())
        return self.events

    # ------------------------------------------------------------------ metrics
    def availability(self) -> float:
        """Business-weighted share of work currently serving (degraded counts as half)."""
        total = sum(s.tier for s in self.services.values()) or 1.0
        up = 0.0
        for s in self.services.values():
            if s.status == LIVE:
                up += s.tier
            elif s.status == DEGRADED:
                up += s.tier * 0.5
        return round(100 * up / total, 1)

    def average_availability(self) -> Optional[float]:
        if not self.samples:
            return None
        return round(sum(self.samples) / len(self.samples), 2)

    def to_dict(self) -> dict:
        hosts = {}
        for h in self.net.hosts.values():
            if h.infra or h.kind == "attacker":
                continue
            cap = self.capacity_of(h.id)
            load = self.load_on(h.id)
            hosts[h.id] = {
                "load": load, "capacity": cap,
                "util": round(load / cap, 3) if cap else 0.0,
                "over": load > cap,
                "services": [s.id for s in self.on_host(h.id)],
            }
        return {
            "services": [s.to_dict() for s in self.services.values()],
            "hosts": hosts,
            "availability": self.availability(),
            "average_availability": self.average_availability(),
            "switchover": SWITCHOVER,
            "displaced": [s.id for s in self.services.values() if not s.home],
            "down": [s.id for s in self.services.values() if not s.serving],
        }
