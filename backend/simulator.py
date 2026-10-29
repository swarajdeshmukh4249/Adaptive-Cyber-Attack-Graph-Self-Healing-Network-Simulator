"""Orchestrator: ties the network, attack graph, traffic, ML and self-healing loop together.

The adversary is an abstract probabilistic agent that moves along attack-graph edges;
the focus of the simulator is the defensive side (detect -> predict -> respond -> recover).
"""
from __future__ import annotations

import math
import random
from collections import deque
from typing import Dict, List, Optional, Set

from .attack_graph import AttackGraph
from .blockchain import AuditChain
from .ml import ModelSuite
from .network import Network
from .services import ServiceLayer
from .traffic import BENIGN_PAIRS, FEATURE_GROUPS, FEATURES, build_training_set, make_flow

SCENARIOS = {
    "apt": {"name": "APT kill chain", "entry": ["mail"], "stealth": 0.45, "mode": "target", "target": "core"},
    "web": {"name": "Web exploit to database", "entry": ["web"], "stealth": 0.25, "mode": "target", "target": "core"},
    "insider": {"name": "Insider threat", "entry": ["user2"], "stealth": 0.6, "mode": "target", "target": "core", "preowned": True},
    "worm": {"name": "Ransomware worm", "entry": ["web", "mail"], "stealth": 0.1, "mode": "spread", "target": "core"},
}

KILL_CHAIN = [
    "Reconnaissance", "Initial Access", "Privilege Escalation", "Lateral Movement",
    "Access Database", "Compromise Admin Server", "Reach Critical System",
]

ACTIONS = {
    "isolate": "Isolate compromised node",
    "block_ip": "Block malicious IP/traffic",
    "firewall": "Update firewall rules",
    "reroute": "Reconfigure network paths",
    "restore": "Restore from clean backup",
    "restart": "Restart affected services",
    "patch": "Apply virtual patch (predicted target)",
    "failover": "Shift workload to a standby server",
}

# Compromising either core banking node is a critical breach.
CRITICAL_NODES = {"core", "core2"}

ZONES = ["external", "perimeter", "dmz", "internal", "atm", "secure", "critical", "mgmt"]

# One simulation tick is 30 seconds of wall-clock time, so MTTD / MTTR can be
# quoted in real units instead of dimensionless "ticks".
TICK_SECONDS = 30

# Ticks between an alert being raised and the automated response firing: a SOC
# does not act instantly, and giving response a cost is what makes the
# healing-on / healing-off comparison meaningful.
RESPONSE_LATENCY = 2

# Zones an attacker can only enter from a host where it holds admin privilege,
# which is what makes the "Privilege Escalation" kill-chain stage real rather
# than decorative.
PRIV_GATED_ZONES = {"secure", "critical"}
PRIV_LABELS = {0: "none", 1: "user", 2: "admin"}

# Anomaly score at which the SOC opens an incident. The detector does NOT get to
# look at ground truth, so crossing this line on a healthy host produces a real
# false-positive isolation with a real availability cost.
ALERT_THRESHOLD = 0.6


class Simulator:
    def __init__(self, seed: int = 7, train: bool = True, models: Optional[ModelSuite] = None) -> None:
        self.seed = seed
        self.models = models or ModelSuite()
        self.auto_heal = True
        self.scenario = "apt"
        self.reset(seed, retrain=train and not self.models.trained)

    # ================================================================== setup
    def reset(self, seed: Optional[int] = None, retrain: bool = False, scenario: Optional[str] = None) -> None:
        self.rng = random.Random(seed if seed is not None else self.seed)
        if scenario in SCENARIOS:
            self.scenario = scenario
        self.net = Network()
        self.svc = ServiceLayer(self.net)
        self.ag = AttackGraph(self.net)
        self.chain = AuditChain()
        self.tick = 0
        self.compromised: Set[str] = {"attacker"}
        self.campaign: Optional[dict] = None
        self.incidents: Dict[str, dict] = {}
        self.anomaly: Dict[str, float] = {h: 0.0 for h in self.net.hosts}
        self.events: deque = deque(maxlen=60)
        self.actions_log: deque = deque(maxlen=40)
        self.history: deque = deque(maxlen=150)
        self.before_after: Optional[dict] = None
        self.phase = "monitor"
        self.last_flows: List[dict] = []
        self.wave = {"normal": deque(maxlen=160), "attack": deque(maxlen=160)}
        self.stats = {
            "detections": 0, "false_positives": 0, "true_alerts": 0, "flows_total": 0,
            "flows_flagged": 0, "flows_attack": 0, "flows_caught": 0, "attacks_blocked": 0,
            "predictions": 0, "predictions_correct": 0, "mttd": [], "mttr": [], "breaches": 0,
            "campaigns": 0, "contained": 0, "healed": 0,
            "fp_isolations": 0, "tp_isolations": 0, "disruption": 0.0,
            "missed": 0, "escalations": 0, "attacker_retreats": 0,
        }
        self.prediction: List[dict] = []
        self._pending_prediction: Optional[str] = None
        self.narrative: List[dict] = []
        self.decisions: deque = deque(maxlen=40)
        self.svc_events: deque = deque(maxlen=30)
        self.drift = getattr(self, "drift", 0.0)
        self.latency = getattr(self, "latency", RESPONSE_LATENCY)
        self.threshold = getattr(self, "threshold", ALERT_THRESHOLD)
        for h in self.net.hosts.values():
            h.priv = 2 if h.kind == "attacker" else 0
        self._refresh_graph_ctx()
        if retrain or not self.models.trained:
            self._train()
        self.paths_baseline = self.ag.count_simple_paths()
        self._log("system", f"Simulation reset - {len(self.net.hosts)} hosts, {len(self.ag.edges)} attack edges")

    def _refresh_graph_ctx(self) -> None:
        cen = self.net.betweenness()
        maxdeg = max(len(v) for v in self.net.adjacency().values()) or 1
        self.graph_ctx = {
            "degree": {h: self.net.degree(h) / maxdeg for h in self.net.hosts},
            "centrality": cen,
            "hops": {h: min(self.net.hop_distance(h, "core"), 6) / 6 for h in self.net.hosts},
        }

    def _graph_info(self) -> dict:
        feats = {}
        for h in self.net.hosts.values():
            zone = [1.0 if h.zone == z else 0.0 for z in ZONES]
            feats[h.id] = zone + [h.criticality, self.graph_ctx["degree"][h.id], self.graph_ctx["centrality"][h.id] * 3]
        return {"nodes": list(self.net.hosts), "adjacency": self.net.adjacency(), "node_feats": feats}

    def _train(self) -> None:
        rng = random.Random(1234)
        pairs = [(e["source"], e["target"]) for e in self.ag.edges.values()]
        data = build_training_set(rng, self.graph_ctx, pairs, n=1400)
        self.models.train(data, self._graph_info())

    # ================================================================== controls
    def set_config(self, auto_heal: Optional[bool] = None, model: Optional[str] = None,
                   latency: Optional[int] = None, threshold: Optional[float] = None,
                   drift: Optional[float] = None) -> None:
        if auto_heal is not None:
            self.auto_heal = bool(auto_heal)
            self._log("config", f"Auto self-healing {'enabled' if self.auto_heal else 'disabled'}")
        if latency is not None:
            self.latency = max(0, min(int(latency), 10))
            self._log("config", f"SOC response latency -> {self.latency} tick(s)")
        if threshold is not None:
            self.threshold = max(0.2, min(float(threshold), 0.95))
            self._log("config", f"Alert threshold -> {self.threshold:.2f}")
        if drift is not None:
            self.drift = max(0.0, min(float(drift), 1.0))
            self._log("config", f"Concept drift -> {self.drift:.2f} "
                                f"(traffic has moved away from what the models were trained on)")
        if model:
            self.models.by_name(model)
            self.models.active = model
            self._log("config", f"Active detection model -> {model}")

    def launch(self, scenario: Optional[str] = None) -> None:
        sc = scenario if scenario in SCENARIOS else self.scenario
        self.scenario = sc
        cfg = SCENARIOS[sc]
        self.campaign = {
            "scenario": sc, "name": cfg["name"], "stage": 0, "recon": 3, "cooldown": 0,
            "started": self.tick, "stealth": cfg["stealth"], "mode": cfg["mode"],
            "target": cfg["target"], "status": "active", "moves": [], "stalled": 0,
            # --- adaptive state: the adversary reacts to being noticed
            "heat": 0.0,       # perceived defensive pressure, 0..1
            "posture": "probing",   # probing | advancing | dormant | evading
            "burnt": {},       # edge -> consecutive failures, deprioritised afterwards
            "lost": [],        # footholds the defence has taken away
        }
        self.stats["campaigns"] += 1
        atk = self.net.hosts["attacker"]
        if atk.ip in self.net.blocked_ips:
            # the adversary rotates to fresh infrastructure after being blocked
            last = int(atk.ip.rsplit(".", 1)[1])
            atk.ip = f"198.51.100.{last % 250 + 1}"
            self.ag.rebuild()
            self._log("attack", f"Adversary rotated infrastructure to {atk.ip}")
        if cfg.get("preowned"):
            for n in cfg["entry"]:
                self._compromise(n, "attacker", "Valid Accounts")
            self.campaign["recon"] = 0
        self._log("attack", f"Threat campaign started: {cfg['name']}")

    # ================================================================== main loop
    def step(self, n: int = 1) -> None:
        for _ in range(max(1, min(n, 200))):
            self._step_once()

    def _step_once(self) -> None:
        self.tick += 1
        phase = "monitor"
        attack_flows = self._adversary_tick()
        flows = self._benign_traffic() + attack_flows
        self.rng.shuffle(flows)
        probs = self.models.predict(flows)
        for f, p in zip(flows, probs):
            f["score"] = round(p, 3)
            f["flagged"] = p >= 0.5
        self.last_flows = flows
        self._update_wave(flows)
        if self._detect(flows):
            phase = "detect"
        self._predict()
        if self.auto_heal and self._respond():
            phase = "respond"
        if self._recover():
            phase = "recover"
        self._workload_tick()
        self.phase = phase
        self._narrate(flows)
        self._record_history()

    # ------------------------------------------------------------------ adversary model
    def _active_footholds(self) -> Set[str]:
        return {n for n in self.compromised if self.net.hosts[n].status in ("compromised", "attacker")}

    def _heat_level(self) -> float:
        """How much defensive attention the adversary believes it has attracted."""
        if not self.campaign:
            return 0.0
        return self.campaign["heat"]

    def _update_heat(self) -> None:
        """Heat rises with open incidents and recent defensive actions, and decays."""
        c = self.campaign
        if not c:
            return
        # Only *current* evidence of attention counts. Losses and actions age out,
        # otherwise heat ratchets up and the adversary stays dormant forever.
        # The adversary cannot see a SIEM alert -- it only notices the defence when
        # something it relies on is taken away: a foothold lost, an IP blocked, a
        # link cut. Heat is therefore driven by observable actions, not by incidents.
        pressure = 0.0
        pressure += 0.34 * sum(1 for l in c["lost"] if self.tick - l["tick"] <= 6)
        pressure += 0.10 * sum(1 for a in self.actions_log if self.tick - a["tick"] <= 3)
        pressure = min(pressure, 1.0)
        # exponential decay toward the live pressure
        c["heat"] = round(min(1.0, 0.65 * c["heat"] + 0.35 * pressure), 3)

    def _effective_stealth(self) -> float:
        """A pressured adversary slows down and blends in harder."""
        c = self.campaign
        base = c["stealth"] if c else 0.3
        return min(0.95, base + 0.45 * self._heat_level())

    def _decide(self, kind: str, choice: str, why: str, detail: Optional[dict] = None) -> None:
        """Record a decision with the numbers behind it, so the run can be read back."""
        self.decisions.appendleft({
            "tick": self.tick, "side": kind, "choice": choice, "why": why,
            "detail": detail or {},
        })

    def _priv_ok(self, u: str, v: str) -> bool:
        """Entering a protected zone needs admin privilege on the source host."""
        return not (self.net.hosts[v].zone in PRIV_GATED_ZONES and self.net.hosts[u].priv < 2)

    def _try_escalate(self) -> bool:
        """Spend a tick escalating on a foothold that only has user-level access."""
        c = self.campaign
        cands = [n for n in self._active_footholds()
                 if n != "attacker" and self.net.hosts[n].priv == 1]
        if not cands:
            return False
        # escalate where it unlocks the most protected ground
        def unlocks(n):
            return sum(1 for (u, v) in self.ag.edges
                       if u == n and self.net.hosts[v].zone in PRIV_GATED_ZONES)
        n = max(cands, key=unlocks)
        gain = unlocks(n)
        if gain == 0:
            return False
        h = self.net.hosts[n]
        if self.rng.random() < 0.55:
            h.priv = 2
            self.stats["escalations"] += 1
            c["stage"] = max(c["stage"], 2)
            self._log("attack", f"Privilege escalated to admin on {h.label}")
            self._decide("attacker", f"escalate on {h.label}",
                         f"user-level access could not reach {gain} protected host(s); escalation succeeded",
                         {"node": n, "unlocks": gain, "priv": "admin"})
        else:
            self._decide("attacker", f"escalation failed on {h.label}",
                         "exploit attempt did not win admin rights this tick",
                         {"node": n, "unlocks": gain})
        return True

    def _adversary_tick(self) -> List[dict]:
        c = self.campaign
        flows: List[dict] = []
        for n in self._active_footholds():
            if n != "attacker":
                flows.append(self._flow("c2", n, "internet"))
        if not c or c["status"] != "active":
            return flows

        # notice footholds the defence has taken away since last tick
        for n in list(self.compromised):
            if n != "attacker" and self.net.hosts[n].status not in ("compromised", "attacker"):
                if not any(l["node"] == n for l in c["lost"]):
                    c["lost"].append({"node": n, "tick": self.tick})
                    self._decide("attacker", f"lost foothold {self.net.hosts[n].label}",
                                 "host was isolated or rebuilt by the defence; falling back",
                                 {"node": n})
        self._update_heat()
        heat = c["heat"]

        if c["recon"] > 0:
            c["recon"] -= 1
            c["posture"] = "probing"
            for dst in ("web", "mail"):
                flows.append(self._flow("scan", "attacker", dst))
            self._decide("attacker", "reconnaissance",
                         f"mapping externally reachable services before committing ({c['recon']} tick(s) left)")
            return flows

        # --- go quiet when the defence is clearly active -----------------
        if heat >= 0.6 and self.rng.random() < 0.5:
            c["posture"] = "dormant"
            c["cooldown"] = max(c["cooldown"], 2)
            self.stats["attacker_retreats"] += 1
            self._decide("attacker", "go dormant",
                         f"detection pressure {heat:.2f} is high; pausing and raising stealth to "
                         f"{self._effective_stealth():.2f} rather than risk another alert",
                         {"heat": heat, "stealth": round(self._effective_stealth(), 3)})
            return flows

        if c["cooldown"] > 0:
            c["cooldown"] -= 1
            return flows

        sources = self._active_footholds()
        all_cand = [
            (u, v) for (u, v) in self.ag.edges
            if u in sources and v not in self.compromised and self.net.hosts[v].status == "normal"
        ]
        gated = [e for e in all_cand if not self._priv_ok(*e)]
        candidates = [e for e in all_cand if self._priv_ok(*e)]

        # everything reachable needs admin we do not have -> escalate instead
        if not candidates and gated:
            if self._try_escalate():
                c["cooldown"] = 1
                return flows

        if not candidates:
            c["stalled"] += 1
            c["posture"] = "stalled"
            if c["stalled"] >= 4:
                c["status"] = "contained"
                self.stats["contained"] += 1
                self._log("defense", "Campaign contained: no remaining attack paths")
                self._decide("attacker", "abandon campaign",
                             "no reachable, unpatched target remains from any surviving foothold",
                             {"footholds": sorted(sources)})
                self.chain.add("CAMPAIGN_CONTAINED", {"scenario": c["name"]}, self.tick)
            return flows
        c["stalled"] = 0
        c["posture"] = "advancing"

        # sometimes escalate first even when a move is available, if it opens more ground
        if heat < 0.5 and self.rng.random() < 0.3 and self._try_escalate():
            c["cooldown"] = 1
            return flows

        def score(e):
            """Edge appeal = success odds, discounted by how often it has already failed."""
            return self.ag.edges[e]["p"] * (0.55 ** c["burnt"].get(e, 0))

        if sources == {"attacker"}:
            entry = [e for e in candidates if e[1] in SCENARIOS[c["scenario"]]["entry"]]
            pool = entry or candidates
            if c["mode"] == "spread":
                attempts = [self.rng.choice(pool)]
                why = "worm picks any reachable entry point at random"
            else:
                attempts = [max(pool, key=score)]
                why = (f"highest-odds way in: p={self.ag.edges[attempts[0]]['p']:.2f} "
                       f"of {len(pool)} candidate entry point(s)")
        elif c["mode"] == "spread":
            k = 1 if heat >= 0.45 else min(3, len(candidates))
            attempts = self.rng.sample(candidates, k)
            why = (f"worm fans out to {k} host(s) at once"
                   if k > 1 else f"pressure {heat:.2f}: spreading one host at a time to stay quiet")
        else:
            path = self.ag.most_probable_path(sources, c["target"])
            step = (path[0], path[1]) if len(path) >= 2 else None
            if step and step in candidates and c["burnt"].get(step, 0) < 2:
                attempts = [step]
                why = (f"next hop on the most probable route to "
                       f"{self.net.hosts[c['target']].label} ({' -> '.join(path)})")
            else:
                attempts = [max(candidates, key=score)]
                u, v = attempts[0]
                burnt = c["burnt"].get(attempts[0], 0)
                why = ("preferred route is blocked or burnt, so taking the best remaining edge "
                       f"p={self.ag.edges[attempts[0]]['p']:.2f}"
                       + (f" (after {burnt} failed attempt(s) elsewhere)" if burnt else ""))

        stealth = self._effective_stealth()
        for u, v in attempts:
            kind = "ransomware" if c["mode"] == "spread" else ("exploit" if u == "attacker" else "lateral")
            flows.append(self._flow(kind, u, v))
            if self.rng.random() < 0.3:
                flows.append(self._flow("bruteforce", u, v))
            p = self.ag.edges[(u, v)]["p"]
            hit = self.rng.random() < p
            self._decide(
                "attacker", f"{self.net.hosts[u].label} -> {self.net.hosts[v].label}",
                why,
                {"p": round(p, 3), "stealth": round(stealth, 3), "heat": round(heat, 3),
                 "technique": self.ag.edges[(u, v)]["technique"], "result": "success" if hit else "failed"},
            )
            if hit:
                c["burnt"].pop((u, v), None)
                self._compromise(v, u, self.ag.edges[(u, v)]["technique"])
                if self.net.hosts[v].kind == "db":
                    flows.append(self._flow("exfil", v, "internet"))
            else:
                c["burnt"][(u, v)] = c["burnt"].get((u, v), 0) + 1
                self.stats["attacks_blocked"] += 1
        c["cooldown"] = 2 if heat >= 0.45 else 1
        return flows

    def _compromise(self, node: str, frm: str, technique: str) -> None:
        h = self.net.hosts[node]
        self._score_prediction(node)
        self.compromised.add(node)
        h.status = "compromised"
        h.compromised_at = self.tick  # type: ignore[attr-defined]
        # Most exploits land with user-level access; a workstation or a service
        # exploited directly occasionally yields admin straight away.
        h.priv = 2 if (h.kind in ("workstation", "atm") and self.rng.random() < 0.35) else 1
        if self.campaign:
            self.campaign["moves"].append({"tick": self.tick, "from": frm, "to": node, "technique": technique})
            self.campaign["stage"] = max(self.campaign["stage"], self._stage_for(node))
        self._log("attack", f"{h.label} compromised via {technique} (from {self.net.hosts[frm].label})")
        if node in CRITICAL_NODES:
            self.stats["breaches"] += 1
            self._log("attack", "CRITICAL SYSTEM BREACHED")
            if self.campaign:
                self.campaign["status"] = "breach"

    def _stage_for(self, node: str) -> int:
        h = self.net.hosts[node]
        if node in CRITICAL_NODES:
            return 6
        if node == "admin":
            return 5
        if h.kind == "db":
            return 4
        if h.zone == "dmz":
            return 1 if len(self.compromised) <= 2 else 2
        return 3

    # ------------------------------------------------------------------ traffic
    def _flow(self, kind: str, src: str, dst: str) -> dict:
        stealth = self._effective_stealth() if self.campaign else 0.3
        return make_flow(self.rng, kind, src, dst,
                         min(0.95, stealth * self.rng.random() * 1.4), self.graph_ctx, drift=self.drift)

    def _benign_traffic(self) -> List[dict]:
        flows = []
        for _ in range(self.rng.randint(22, 32)):
            src, dst, kind = self.rng.choice(BENIGN_PAIRS)
            if self.net.hosts[src].status == "isolated" or self.net.hosts[dst].status == "isolated":
                continue
            flows.append(make_flow(self.rng, kind, src, dst, 0.0, self.graph_ctx, drift=self.drift))
        return flows

    def _update_wave(self, flows: List[dict]) -> None:
        nb = sum(f["bytes"] for f in flows if not f["label"])
        ab = sum(f["bytes"] for f in flows if f["label"])
        for k in range(6):
            ph = (self.tick * 6 + k) * 0.9
            self.wave["normal"].append(round(math.log1p(nb) * (0.55 + 0.45 * math.sin(ph)) * (0.8 + 0.4 * self.rng.random()), 3))
            self.wave["attack"].append(round(math.log1p(ab) * (0.5 + 0.5 * math.sin(ph * 1.7)) * (0.6 + 0.8 * self.rng.random()), 3))
        att = [f for f in flows if f["label"]]
        self.stats["flows_total"] += len(flows)
        self.stats["flows_attack"] += len(att)
        self.stats["flows_flagged"] += sum(1 for f in flows if f["flagged"])
        self.stats["flows_caught"] += sum(1 for f in att if f["flagged"])

    # ------------------------------------------------------------------ detection
    def _detect(self, flows: List[dict]) -> List[str]:
        node_score: Dict[str, float] = {}
        for f in flows:
            if not f["flagged"]:
                continue
            if not f["label"]:
                self.stats["false_positives"] += 1
            # evidence is attributed to inside hosts; inbound perimeter probes raise no host alert
            ends = (f["src"],) if self.net.hosts[f["src"]].zone != "external" else ()
            if self.net.hosts[f["src"]].zone != "external" and f["dst"] != "internet":
                ends += (f["dst"],)
            for n in ends:
                h = self.net.hosts[n]
                if h.infra or h.kind in ("attacker", "monitor"):
                    continue
                node_score[n] = max(node_score.get(n, 0.0), f["score"])
        new = []
        for n in self.anomaly:
            # temporal smoothing: an alert needs sustained evidence over several ticks
            self.anomaly[n] = round(0.7 * self.anomaly[n] + 0.3 * node_score.get(n, 0.0), 3)
            h = self.net.hosts[n]
            if self.anomaly[n] < self.threshold or n in self.incidents:
                continue
            if h.status not in ("normal", "compromised"):
                continue  # already isolated or being rebuilt
            # The SOC acts on the anomaly score ALONE -- it cannot see whether the
            # host is truly compromised. A wrong call here isolates a healthy host
            # and costs real availability, exactly as it would in production.
            truly = h.status == "compromised"
            inc = {
                "node": n, "detected": self.tick, "stage": "triage", "actions": [],
                "true_positive": truly, "score": self.anomaly[n],
                "acts_at": self.tick + self.latency,
                # re-imaging a workstation is quicker than rebuilding a server
                "rebuild": self.rng.randint(2, 5) + (1 if h.criticality >= 0.8 else 0),
            }
            evidence = max((f for f in flows if f["flagged"] and n in (f["src"], f["dst"])),
                           key=lambda f: f["score"], default=None)
            if evidence is not None:
                inc["evidence"] = self.models.explain(evidence, top=3)
                inc["evidence"].update({"kind": evidence["kind"], "src": evidence["src"],
                                        "dst": evidence["dst"]})
            self.incidents[n] = inc
            self.stats["detections"] += 1
            if truly:
                self.stats["true_alerts"] += 1
                self.stats["mttd"].append(self.tick - getattr(h, "compromised_at", self.tick))
            self._log("detect",
                      f"Alert raised on {h.label} (anomaly {self.anomaly[n]:.2f}, {self.models.active})")
            top = ""
            if inc.get("evidence", {}).get("contributions"):
                c0 = inc["evidence"]["contributions"][0]
                top = (f"; strongest evidence was {c0['feature']}={c0['value']} "
                       f"vs typical {c0['typical']}")
            self._decide("defence", f"raise incident on {h.label}",
                         f"smoothed anomaly {self.anomaly[n]:.2f} crossed the {self.threshold:.2f} "
                         f"alert threshold{top}",
                         {"node": n, "score": self.anomaly[n],
                          "responds_in": self.latency})
            self.chain.add("ATTACK_DETECTED",
                           {"node": n, "score": self.anomaly[n], "model": self.models.active}, self.tick)
            new.append(n)
        # a compromised host nobody has flagged is a miss, counted once
        for n, h in self.net.hosts.items():
            if h.status == "compromised" and n not in self.incidents and \
                    self.tick - getattr(h, "compromised_at", self.tick) == 5:
                self.stats["missed"] += 1
        return new

    # ------------------------------------------------------------------ prediction
    def _predict(self) -> None:
        sources = self._active_footholds()
        target = self.campaign["target"] if self.campaign else "core"
        hops_to = self.graph_ctx["hops"]
        path = self.ag.most_probable_path(sources, target) if self.campaign else []
        on_path = path[1] if len(path) >= 2 else None
        best: Dict[str, float] = {}
        for (u, v), e in self.ag.edges.items():
            if u not in sources or v in self.compromised or self.net.hosts[v].status != "normal":
                continue
            h = self.net.hosts[v]
            s = e["p"] * (0.35 + 0.4 * h.criticality + 0.25 * (1 - hops_to.get(v, 1)))
            if v == on_path:
                s *= 1.6
            best[v] = max(best.get(v, 0.0), s)
        tot = sum(best.values()) or 1.0
        self.prediction = sorted(
            [{"node": v, "prob": round(s / tot, 3)} for v, s in best.items()], key=lambda d: -d["prob"]
        )[:4]
        if self.prediction and self.campaign and self.campaign["status"] == "active" and self.campaign["recon"] == 0:
            self._pending_prediction = self.prediction[0]["node"]

    def _score_prediction(self, actual: str) -> None:
        if self._pending_prediction is None:
            return
        self.stats["predictions"] += 1
        if self._pending_prediction == actual:
            self.stats["predictions_correct"] += 1
        self._pending_prediction = None

    def risk_scores(self) -> Dict[str, float]:
        prob = self.ag.compromise_probability(self._active_footholds())
        out = {}
        for n, p in prob.items():
            h = self.net.hosts[n]
            if h.kind == "attacker":
                continue
            out[n] = 1.0 if h.status == "compromised" else round(p * (0.4 + 0.6 * h.criticality), 3)
        return out

    # ------------------------------------------------------------------ response (self-healing)
    def _act(self, inc: dict, action: str, detail: str) -> None:
        rec = {"tick": self.tick, "node": inc["node"], "action": action, "label": ACTIONS[action], "detail": detail}
        inc["actions"].append(action)
        self.actions_log.appendleft(rec)
        self._log("respond", f"{ACTIONS[action]}: {detail}")
        self.chain.add("RESPONSE_" + action.upper(), {"node": inc["node"], "detail": detail}, self.tick)

    def _respond(self) -> bool:
        acted = False
        for n, inc in list(self.incidents.items()):
            if inc["stage"] != "triage":
                continue
            # SOC approval delay: the response is not instantaneous
            if self.tick < inc["acts_at"]:
                continue
            h = self.net.hosts[n]

            if not inc["true_positive"]:
                # --- false positive: a healthy host gets pulled off the network.
                h.status = "isolated"
                inc["stage"] = "false_positive"
                inc["responded"] = self.tick
                self.stats["fp_isolations"] += 1
                self._act(inc, "isolate",
                          f"{h.label} quarantined on a false alarm (anomaly {inc['score']:.2f})")
                self._log("respond", f"FALSE POSITIVE: {h.label} isolated although it was clean")
                self._decide("defence", f"isolate {h.label} (false positive)",
                             "the detector could not tell this benign activity from an attack; "
                             "a healthy host is now offline and the cost is counted against availability",
                             {"node": n, "score": inc["score"],
                              "criticality": h.criticality})
                self.chain.add("FALSE_POSITIVE_ISOLATION",
                               {"node": n, "score": inc["score"]}, self.tick)
                acted = True
                continue

            # --- true positive: contain, cut paths, patch ahead of the attacker
            before_paths = self.ag.count_simple_paths()
            before_edges = [e for e in self.ag.edges.values() if n in (e["source"], e["target"])]
            preds = [p["node"] for p in self.prediction]
            h.status = "isolated"
            h.priv = 0
            self._act(inc, "isolate", f"{h.label} quarantined from the network")
            self._decide("defence", f"isolate {h.label}",
                         f"confirmed compromise; isolating removes "
                         f"{len(before_edges)} attack edge(s) from the graph",
                         {"node": n, "edges_removed": len(before_edges),
                          "latency_ticks": self.tick - inc["detected"]})
            atk = self.net.hosts["attacker"]
            if atk.ip not in self.net.blocked_ips:
                self.net.blocked_ips.add(atk.ip)
                self._act(inc, "block_ip", f"Blocked {atk.ip} at the perimeter")
            for p in preds[:1]:
                rule = self.net.add_rule("deny", n, p, f"contain lateral movement from {n}", self.tick)
                self._act(inc, "firewall", f"Rule #{rule.id}: deny {n} -> {p}")
                ph = self.net.hosts[p]
                vulns = ph.open_vulns()
                if vulns:
                    vulns[0].patched = True
                    self._act(inc, "patch", f"Virtual patch {vulns[0].cve} on predicted target {ph.label}")
                    self._decide("defence", f"pre-emptively patch {ph.label}",
                                 f"prediction put {ph.label} next on the attacker's route, so the "
                                 f"vulnerability is closed before it is reached",
                                 {"node": p, "cve": vulns[0].cve})
            for a, b in list(self.net.links):
                other = b if a == n else a if b == n else None
                if other and not self.net.hosts[other].infra and not self.net.is_cut(a, b):
                    self.net.cut_link(a, b)
                    self._act(inc, "reroute", f"Back-end link {a} <-> {b} disabled, traffic rerouted")
            self.ag.rebuild()
            self.stats["tp_isolations"] += 1
            self.before_after = {
                "node": n, "label": h.label, "tick": self.tick,
                "before": {"paths": before_paths, "edges": before_edges},
                "after": {"paths": self.ag.count_simple_paths(),
                          "edges": [e for e in self.ag.edges.values() if n in (e["source"], e["target"])]},
            }
            inc["stage"] = "responded"
            inc["responded"] = self.tick
            acted = True
        return acted

    def _recover(self) -> bool:
        acted = False
        for n, inc in list(self.incidents.items()):
            h = self.net.hosts[n]

            # every tick a healthy host sits isolated is lost availability
            if inc["stage"] == "false_positive":
                self.stats["disruption"] += round(h.criticality + 0.2, 3)
                if self.tick - inc["responded"] >= 3:
                    h.status = "normal"
                    self.anomaly[n] = 0.0
                    self.net.cut_links = {l for l in self.net.cut_links if n not in l}
                    self.net.invalidate()
                    self._act(inc, "restart", f"{h.label} cleared by analyst review and returned to service")
                    self._decide("defence", f"release {h.label}",
                                 "manual triage found no compromise; the host was offline for "
                                 f"{self.tick - inc['responded']} tick(s) for nothing",
                                 {"node": n, "downtime_ticks": self.tick - inc["responded"]})
                    self.ag.rebuild()
                    del self.incidents[n]
                    acted = True
                continue

            if inc["stage"] == "responded" and self.tick - inc["responded"] >= 1:
                h.status = "healing"
                inc["stage"] = "restoring"
                self._act(inc, "restore", f"{h.label} re-imaged from last clean backup")
                acted = True
            elif inc["stage"] == "restoring" and self.tick - inc["responded"] >= inc.get("rebuild", 3):
                for v in h.vulns:
                    v.patched = True
                h.status = "normal"
                h.priv = 0
                self.compromised.discard(n)
                self.anomaly[n] = 0.0
                self.net.cut_links = {l for l in self.net.cut_links if n not in l}
                self.net.invalidate()
                self._act(inc, "restart", f"{h.label} services restarted and verified clean")
                self.ag.rebuild()
                self.stats["mttr"].append(self.tick - inc["detected"])
                self.stats["healed"] += 1
                self.chain.add("RECOVERY_COMPLETED", {"node": n, "mttr": self.tick - inc["detected"]}, self.tick)
                del self.incidents[n]
                acted = True
        return acted

    def manual_heal(self, node: str) -> bool:
        h = self.net.hosts.get(node)
        if not h or h.status != "compromised" or node in self.incidents:
            return False
        self.incidents[node] = {
            "node": node, "detected": self.tick, "stage": "triage", "actions": [],
            "true_positive": True, "score": self.anomaly.get(node, 1.0),
            "acts_at": self.tick,  # an analyst acting by hand skips the approval wait
        }
        self._log("respond", f"Manual response triggered for {h.label}")
        self._respond()
        return True

    # ------------------------------------------------------------------ workload
    def _workload_tick(self) -> None:
        """Move business services off quarantined hosts and back when they are clean."""
        for ev in self.svc.step(self.tick):
            if ev["kind"] == "failover":
                self._log("respond", ev["text"])
                self.actions_log.appendleft({
                    "tick": self.tick, "node": ev["to"], "action": "failover",
                    "label": ACTIONS["failover"], "detail": ev["text"],
                })
                svc = self.svc.services[ev["service"]]
                self._decide("defence", f"move {svc.label} to {self.net.hosts[ev['to']].label}",
                             f"{self.net.hosts[ev['from']].label} was quarantined, so the workload "
                             f"shifts to its standby; the service is offline for "
                             f"{self.svc.switchover_ticks} tick(s) during the switchover",
                             {"service": svc.id, "from": ev["from"], "to": ev["to"],
                              "tier": svc.tier})
                self.chain.add("WORKLOAD_FAILOVER",
                               {"service": ev["service"], "from": ev["from"], "to": ev["to"]},
                               self.tick)
            elif ev["kind"] == "failback":
                self._log("defense", ev["text"])
                self.chain.add("WORKLOAD_FAILBACK",
                               {"service": ev["service"], "to": ev["to"]}, self.tick)
            elif ev["kind"] == "down":
                self._log("attack", ev["text"])
                self.chain.add("SERVICE_DOWN", {"service": ev["service"]}, self.tick)
            self.svc_events = getattr(self, "svc_events", deque(maxlen=30))
            self.svc_events.appendleft({"tick": self.tick, **ev})

    # ------------------------------------------------------------------ narration
    def clock(self, ticks: Optional[int] = None) -> str:
        """Render ticks as real elapsed time, so metrics are not dimensionless."""
        t = self.tick if ticks is None else ticks
        sec = t * TICK_SECONDS
        if sec < 60:
            return f"{sec}s"
        if sec < 3600:
            return f"{sec // 60}m {sec % 60:02d}s"
        return f"{sec // 3600}h {(sec % 3600) // 60:02d}m"

    def _narrate(self, flows: List[dict]) -> None:
        """A plain-English account of this tick: what happened, and why.

        This is what turns the 3D view from a light show into something a reader
        can follow -- every sentence is generated from the same numbers the
        engine acted on, never hard-coded.
        """
        lines: List[dict] = []
        c = self.campaign
        att = sum(1 for f in flows if f["label"])
        flagged = sum(1 for f in flows if f["flagged"])
        caught = sum(1 for f in flows if f["label"] and f["flagged"])
        missed = att - caught
        fp = sum(1 for f in flows if f["flagged"] and not f["label"])

        lines.append({"kind": "traffic", "text":
                      f"{len(flows)} flows this tick; {att} were hostile, the detector flagged "
                      f"{flagged}. It caught {caught} of the {att} attacks"
                      + (f" and missed {missed}" if missed else "")
                      + (f", and wrongly flagged {fp} benign flow(s)" if fp else "") + "."})

        if c and c["status"] == "active":
            if c["recon"] > 0:
                lines.append({"kind": "attack", "text":
                              "The adversary is still scanning from outside and has not "
                              "committed to an entry point yet."})
            elif c["posture"] == "dormant":
                lines.append({"kind": "attack", "text":
                              f"The adversary has gone quiet: it noticed the defence "
                              f"(pressure {c['heat']:.2f}) and is waiting rather than risk "
                              f"another alert. Its traffic is now {self._effective_stealth():.0%} "
                              f"blended into normal activity."})
            elif c["posture"] == "stalled":
                lines.append({"kind": "attack", "text":
                              "The adversary has no reachable unpatched target left from any "
                              "foothold it still controls."})
            else:
                mv = [d for d in self.decisions if d["tick"] == self.tick and d["side"] == "attacker"]
                for d in mv[:2]:
                    res = d["detail"].get("result")
                    lines.append({"kind": "attack", "text":
                                  f"{d['choice']} - {d['why']}."
                                  + (f" The exploit {res}." if res else "")})

        for d in self.decisions:
            if d["tick"] != self.tick or d["side"] != "defence":
                continue
            txt = d["choice"]
            lines.append({"kind": "defence", "text": f"{txt[:1].upper()}{txt[1:]} - {d['why']}."})

        for ev in list(getattr(self, "svc_events", []))[:4]:
            if ev["tick"] == self.tick:
                lines.append({"kind": "workload", "text": ev["text"] + "."})
        av = self.svc.availability()
        displaced = [self.svc.services[i].label for i in self.svc.to_dict()["displaced"]]
        if displaced or av < 100:
            lines.append({"kind": "workload", "text":
                          f"{av:.0f}% of business work is serving right now"
                          + (f"; {', '.join(displaced)} currently running on standby hardware."
                             if displaced else ".")})

        held = [n for n in self._active_footholds() if n != "attacker"]
        if held:
            labels = ", ".join(self.net.hosts[n].label for n in sorted(held))
            privs = ", ".join(f"{self.net.hosts[n].label}={PRIV_LABELS[self.net.hosts[n].priv]}"
                              for n in sorted(held))
            lines.append({"kind": "state", "text":
                          f"The adversary currently holds {len(held)} host(s): {labels} "
                          f"(access level: {privs})."})
        self.narrative = lines

    # ------------------------------------------------------------------ bookkeeping
    def _log(self, kind: str, msg: str) -> None:
        self.events.appendleft({"tick": self.tick, "kind": kind, "msg": msg})

    def health(self) -> float:
        hosts = [h for h in self.net.hosts.values() if h.kind != "attacker"]
        w = {"normal": 1.0, "healing": 0.6, "isolated": 0.4, "compromised": 0.0}
        tot = sum(h.criticality + 0.2 for h in hosts)
        return round(100 * sum((h.criticality + 0.2) * w.get(h.status, 1) for h in hosts) / tot, 1)

    def _record_history(self) -> None:
        risk = self.risk_scores()
        open_risk = [v for k, v in risk.items() if self.net.hosts[k].status != "compromised"]
        self.history.append({
            "tick": self.tick,
            "health": self.health(),
            "compromised": len(self.compromised) - 1,
            "risk": round(max(open_risk or [0]), 3),
            "alerts": sum(1 for f in self.last_flows if f["flagged"]),
            "attack_flows": sum(1 for f in self.last_flows if f["label"]),
            "paths": self.ag.count_simple_paths(cap=5000),
            "availability": self.svc.availability(),
        })

    # ================================================================== snapshot
    def dm_concepts(self, risk: Dict[str, float]) -> dict:
        V = set(self.ag.out)
        C = self.compromised - {"attacker"}
        I = {h.id for h in self.net.hosts.values() if h.status == "isolated"}
        R = self.ag.reachable_from(self._active_footholds()) - {"attacker"}
        crit = {h.id for h in self.net.hosts.values() if h.criticality >= 0.85}
        best = self.ag.most_probable_path(self._active_footholds())
        depth, leaves = self.ag.bfs_tree_depth()
        nV = len(V)
        sus = next((f for f in self.last_flows if f["flagged"]), None)
        rules = [
            {"rule": "anomaly(x) ≥ 0.55 ∧ compromised(x) → isolate(x)",
             "value": any(self.anomaly[n] >= 0.55 for n in C)},
            {"rule": "failed_auth > 5 ∨ port_entropy > 2 → suspicious(flow)",
             "value": bool(sus and (sus["x"][7] > 5 or sus["x"][5] > 2))},
            {"rule": "isolated(x) → ¬reachable(attacker, x)", "value": all(n not in R for n in I)},
            {"rule": "patched(v) → ¬∃u edge(u, v)",
             "value": all(self.net.hosts[v].open_vulns() for (_, v) in self.ag.edges)},
        ]
        breach_p = 1.0 - math.prod(1 - risk.get(c, 0) for c in crit if c in risk)
        hops = max(len(best) - 1, 0)
        return {
            "graphs": {"V": len(self.net.hosts), "E": len(self.net.links) - len(self.net.cut_links),
                       "attack_edges": len(self.ag.edges),
                       "avg_degree": round(2 * len(self.net.links) / len(self.net.hosts), 2)},
            "sets": {"V": nV, "C": sorted(C), "N": nV - len(C) - 1, "I": sorted(I), "R": len(R),
                     "R_cap_critical": sorted(R & crit)},
            "combinatorics": {"paths": self.ag.count_simple_paths(), "baseline_paths": self.paths_baseline,
                              "pairs": math.comb(nV, 2), "orderings": math.factorial(hops)},
            "logic": rules,
            "relations": {"closure_pairs": self.ag.transitive_closure_size(), "max_pairs": nV * nV,
                          "edges": len(self.ag.edges)},
            "trees": {"attack_tree_depth": depth, "attack_tree_leaves": leaves,
                      "rf_depth": self.models.to_dict()["rf_avg_depth"]},
            "probability": {"best_path": best,
                            "best_path_p": round(self.ag.path_probability(best), 4) if len(best) > 1 else 0,
                            "breach_p": round(breach_p, 3)},
        }

    def outcomes(self) -> dict:
        s = self.stats
        avg = lambda xs: round(sum(xs) / len(xs), 2) if xs else None
        mttd, mttr = avg(s["mttd"]), avg(s["mttr"])
        alerts = s["tp_isolations"] + s["fp_isolations"]
        return {
            "detection_rate": round(s["flows_caught"] / s["flows_attack"], 3) if s["flows_attack"] else None,
            "prediction_accuracy": round(s["predictions_correct"] / s["predictions"], 3) if s["predictions"] else None,
            "mttd": mttd, "mttr": mttr,
            "mttd_human": self.clock(round(mttd)) if mttd is not None else None,
            "mttr_human": self.clock(round(mttr)) if mttr is not None else None,
            "tick_seconds": TICK_SECONDS,
            "elapsed": self.clock(),
            "healed": s["healed"], "breaches": s["breaches"], "campaigns": s["campaigns"],
            "contained": s["contained"], "false_positives": s["false_positives"],
            "attacks_blocked": s["attacks_blocked"], "chain_valid": self.chain.verify()["valid"],
            # --- the cost side: automated response is not free
            "fp_isolations": s["fp_isolations"], "tp_isolations": s["tp_isolations"],
            "precision_of_response": round(s["tp_isolations"] / alerts, 3) if alerts else None,
            "availability_cost": round(s["disruption"], 2),
            "service_availability": self.svc.availability(),
            "avg_service_availability": self.svc.average_availability(),
            "services_displaced": len(self.svc.to_dict()["displaced"]),
            "services_down": len(self.svc.to_dict()["down"]),
            "missed_compromises": s["missed"],
            "escalations": s["escalations"],
            "attacker_retreats": s["attacker_retreats"],
        }

    def snapshot(self) -> dict:
        risk = self.risk_scores()
        flows = self.last_flows
        sample = max(flows, key=lambda f: f.get("score", 0)) if flows else None
        means = {}
        if flows:
            for i, name in enumerate(FEATURES):
                means[name] = round(sum(f["x"][i] for f in flows) / len(flows), 3)
        open_nodes = [(k, v) for k, v in risk.items() if self.net.hosts[k].status == "normal"]
        top = max(open_nodes, key=lambda kv: kv[1], default=(None, 0))
        detected = next((self.net.hosts[n].label for n in self.incidents), None)
        c = self.campaign
        return {
            "tick": self.tick,
            "phase": self.phase,
            "auto_heal": self.auto_heal,
            "scenario": self.scenario,
            "scenarios": {k: v["name"] for k, v in SCENARIOS.items()},
            "campaign": None if not c else {
                "name": c["name"], "status": c["status"], "stage": c["stage"],
                "stage_name": KILL_CHAIN[c["stage"]], "recon": c["recon"], "moves": c["moves"][-10:],
                "heat": c["heat"], "posture": c["posture"],
                "stealth": round(self._effective_stealth(), 3),
                "lost": [l["node"] for l in c["lost"]],
            },
            "services": self.svc.to_dict(),
            "service_events": list(getattr(self, "svc_events", []))[:12],
            "narrative": self.narrative,
            "decisions": list(self.decisions)[:18],
            "clock": self.clock(),
            "tick_seconds": TICK_SECONDS,
            "config": {"latency": self.latency, "threshold": self.threshold,
                       "drift": self.drift, "auto_heal": self.auto_heal},
            "privileges": {h.id: PRIV_LABELS[h.priv] for h in self.net.hosts.values() if h.priv},
            "kill_chain": KILL_CHAIN,
            "network": self.net.to_dict(),
            "attack_graph": self.ag.to_dict(),
            "compromised": sorted(self.compromised - {"attacker"}),
            "anomaly": self.anomaly,
            "risk": risk,
            "prediction": self.prediction,
            "best_path": self.ag.most_probable_path(self._active_footholds()),
            "output": {
                "detected": detected,
                "predicted": self.net.hosts[self.prediction[0]["node"]].label if self.prediction else None,
                "risk_node": self.net.hosts[top[0]].label if top[0] else None,
                "risk_score": top[1],
            },
            "incidents": list(self.incidents.values()),
            "actions": list(self.actions_log)[:16],
            "actions_catalog": ACTIONS,
            "before_after": self.before_after,
            "traffic": {
                "wave": {"normal": list(self.wave["normal"]), "attack": list(self.wave["attack"])},
                "flows": [{k: f[k] for k in ("src", "dst", "kind", "protocol", "bytes", "label", "score", "flagged")}
                          for f in flows[:14]],
                "n": len(flows), "flagged": sum(1 for f in flows if f["flagged"]),
                "attack": sum(1 for f in flows if f["label"]),
                "feature_means": means,
                "sample": sample and {"x": sample["x"], "score": sample["score"], "kind": sample["kind"],
                                      "src": sample["src"], "dst": sample["dst"]},
            },
            "features": {"names": FEATURES, "groups": FEATURE_GROUPS},
            "ml": self.models.to_dict(),
            "events": list(self.events)[:30],
            "history": list(self.history),
            "chain": self.chain.to_dict(),
            "dm": self.dm_concepts(risk),
            "outcomes": self.outcomes(),
            "stats": {k: v for k, v in self.stats.items() if not isinstance(v, list)},
            "health": self.health(),
        }


def _summarise(xs: List[float]) -> dict:
    """Mean with a 95% confidence interval -- a bare mean is not evidence."""
    n = len(xs)
    if not n:
        return {"mean": None, "sd": None, "ci95": None, "n": 0}
    mean = sum(xs) / n
    if n < 2:
        return {"mean": round(mean, 3), "sd": 0.0, "ci95": 0.0, "n": n}
    var = sum((x - mean) ** 2 for x in xs) / (n - 1)
    sd = math.sqrt(var)
    ci = 1.96 * sd / math.sqrt(n)          # normal approximation
    return {"mean": round(mean, 3), "sd": round(sd, 3), "ci95": round(ci, 3), "n": n,
            "lo": round(max(0.0, mean - ci), 3), "hi": round(mean + ci, 3)}


def run_experiment(models: ModelSuite, runs: int = 12, ticks: int = 45) -> dict:
    """Monte-Carlo comparison of self-healing on vs off.

    Every figure is reported as a mean with a 95% confidence interval, and the
    cost of self-healing (false-positive isolations and lost availability) is
    reported next to the benefit, so the comparison is honest in both directions.
    """
    out: dict = {}
    per_scenario: Dict[str, dict] = {}
    names = list(SCENARIOS)
    for heal in (False, True):
        breach, comp, mttr, mttd, fp, disrupt, avail = [], [], [], [], [], [], []
        by_sc: Dict[str, List[float]] = {k: [] for k in names}
        for r in range(runs):
            sc = names[r % len(names)]
            sim = Simulator(seed=1000 + r, models=models)
            sim.auto_heal = heal
            sim.launch(sc)
            sim.step(ticks)
            st = sim.stats
            b = 1.0 if st["breaches"] else 0.0
            breach.append(b)
            by_sc[sc].append(b)
            comp.append(float(len(sim.compromised) - 1))
            mttr += [float(x) for x in st["mttr"]]
            mttd += [float(x) for x in st["mttd"]]
            fp.append(float(st["fp_isolations"]))
            disrupt.append(float(st["disruption"]))
            a = sim.svc.average_availability()
            if a is not None:
                avail.append(float(a))
        key = "with_healing" if heal else "without_healing"
        out[key] = {
            "breach_rate": _summarise(breach),
            "avg_compromised": _summarise(comp),
            "mttr": _summarise(mttr),
            "mttd": _summarise(mttd),
            "false_positive_isolations": _summarise(fp),
            "availability_cost": _summarise(disrupt),
            "service_availability": _summarise(avail),
        }
        per_scenario[key] = {k: _summarise(v) for k, v in by_sc.items()}

    a = out["without_healing"]["breach_rate"]["mean"]
    b = out["with_healing"]["breach_rate"]["mean"]
    out["per_scenario"] = per_scenario
    out["scenario_names"] = {k: v["name"] for k, v in SCENARIOS.items()}
    out["reduction"] = round((a - b) / a, 3) if a else None
    out["significant"] = bool(
        out["without_healing"]["breach_rate"].get("lo", 0)
        > out["with_healing"]["breach_rate"].get("hi", 1)
    )
    av_off = out["without_healing"]["service_availability"]
    av_on = out["with_healing"]["service_availability"]
    out["availability_significant"] = bool(
        av_off.get("mean") is not None and av_on.get("mean") is not None
        and av_on.get("lo", 0) > av_off.get("hi", 100)
    )
    out["runs"] = runs
    out["ticks"] = ticks
    out["tick_seconds"] = TICK_SECONDS
    out["interpretation"] = (
        f"Self-healing changed the breach rate from "
        f"{a:.0%} to {b:.0%} over {runs} campaigns of {ticks} ticks "
        f"({ticks * TICK_SECONDS // 60} simulated minutes each). "
        + ("The 95% breach-rate intervals do not overlap, so that difference is "
           "statistically meaningful. "
           if out["significant"] else
           "The 95% breach-rate intervals overlap, so more runs are needed before claiming "
           "an effect on that particular measure. ")
        + f"The cost was {out['with_healing']['false_positive_isolations']['mean']:.2f} "
          f"false-positive isolation(s) per campaign. "
        + (f"Business services stayed available "
           f"{out['with_healing']['service_availability']['mean']:.1f}% of the time with "
           f"self-healing versus "
           f"{out['without_healing']['service_availability']['mean']:.1f}% without"
           + (" -- and those intervals do NOT overlap, so service availability is the "
              "measure that most clearly shows self-healing working."
              if out["availability_significant"] else ".")
           if out['with_healing']['service_availability']['mean'] is not None else "")
    )
    return out
