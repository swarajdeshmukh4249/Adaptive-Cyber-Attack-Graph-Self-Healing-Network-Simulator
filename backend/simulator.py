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
}

ZONES = ["external", "perimeter", "dmz", "internal", "atm", "secure", "critical", "mgmt"]


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
        }
        self.prediction: List[dict] = []
        self._pending_prediction: Optional[str] = None
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
    def set_config(self, auto_heal: Optional[bool] = None, model: Optional[str] = None) -> None:
        if auto_heal is not None:
            self.auto_heal = bool(auto_heal)
            self._log("config", f"Auto self-healing {'enabled' if self.auto_heal else 'disabled'}")
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
        self.phase = phase
        self._record_history()

    # ------------------------------------------------------------------ adversary model
    def _active_footholds(self) -> Set[str]:
        return {n for n in self.compromised if self.net.hosts[n].status in ("compromised", "attacker")}

    def _adversary_tick(self) -> List[dict]:
        c = self.campaign
        flows: List[dict] = []
        for n in self._active_footholds():
            if n != "attacker":
                flows.append(self._flow("c2", n, "internet"))
        if not c or c["status"] != "active":
            return flows
        if c["recon"] > 0:
            c["recon"] -= 1
            for dst in ("web", "mail"):
                flows.append(self._flow("scan", "attacker", dst))
            return flows
        if c["cooldown"] > 0:
            c["cooldown"] -= 1
            return flows

        sources = self._active_footholds()
        candidates = [
            (u, v) for (u, v) in self.ag.edges
            if u in sources and v not in self.compromised and self.net.hosts[v].status == "normal"
        ]
        if not candidates:
            c["stalled"] += 1
            if c["stalled"] >= 4:
                c["status"] = "contained"
                self.stats["contained"] += 1
                self._log("defense", "Campaign contained: no remaining attack paths")
                self.chain.add("CAMPAIGN_CONTAINED", {"scenario": c["name"]}, self.tick)
            return flows
        c["stalled"] = 0

        if sources == {"attacker"}:
            entry = [e for e in candidates if e[1] in SCENARIOS[c["scenario"]]["entry"]]
            candidates = entry or candidates
            attempts = [self.rng.choice(candidates)] if c["mode"] == "spread" else \
                [max(candidates, key=lambda e: self.ag.edges[e]["p"])]
        elif c["mode"] == "spread":
            attempts = self.rng.sample(candidates, min(3, len(candidates)))
        else:
            path = self.ag.most_probable_path(sources, c["target"])
            if len(path) >= 2:
                attempts = [(path[0], path[1])]
            else:
                attempts = [max(candidates, key=lambda e: self.ag.edges[e]["p"])]

        for u, v in attempts:
            kind = "ransomware" if c["mode"] == "spread" else ("exploit" if u == "attacker" else "lateral")
            flows.append(self._flow(kind, u, v))
            if self.rng.random() < 0.3:
                flows.append(self._flow("bruteforce", u, v))
            if self.rng.random() < self.ag.edges[(u, v)]["p"]:
                self._compromise(v, u, self.ag.edges[(u, v)]["technique"])
                if self.net.hosts[v].kind == "db":
                    flows.append(self._flow("exfil", v, "internet"))
            else:
                self.stats["attacks_blocked"] += 1
        c["cooldown"] = 1
        return flows

    def _compromise(self, node: str, frm: str, technique: str) -> None:
        h = self.net.hosts[node]
        self._score_prediction(node)
        self.compromised.add(node)
        h.status = "compromised"
        h.compromised_at = self.tick  # type: ignore[attr-defined]
        if self.campaign:
            self.campaign["moves"].append({"tick": self.tick, "from": frm, "to": node, "technique": technique})
            self.campaign["stage"] = max(self.campaign["stage"], self._stage_for(node))
        self._log("attack", f"{h.label} compromised via {technique} (from {self.net.hosts[frm].label})")
        if node == "core":
            self.stats["breaches"] += 1
            self._log("attack", "CRITICAL SYSTEM BREACHED")
            if self.campaign:
                self.campaign["status"] = "breach"

    def _stage_for(self, node: str) -> int:
        h = self.net.hosts[node]
        if node == "core":
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
        stealth = self.campaign["stealth"] if self.campaign else 0.3
        return make_flow(self.rng, kind, src, dst, min(0.95, stealth * self.rng.random() * 1.4), self.graph_ctx)

    def _benign_traffic(self) -> List[dict]:
        flows = []
        for _ in range(self.rng.randint(22, 32)):
            src, dst, kind = self.rng.choice(BENIGN_PAIRS)
            if self.net.hosts[src].status == "isolated" or self.net.hosts[dst].status == "isolated":
                continue
            flows.append(make_flow(self.rng, kind, src, dst, 0.0, self.graph_ctx))
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
            if self.anomaly[n] < 0.6 or n in self.incidents or h.status != "compromised":
                continue
            # SOC forensic triage confirms the compromise before automated response
            self.incidents[n] = {"node": n, "detected": self.tick, "stage": "detected", "actions": []}
            self.stats["detections"] += 1
            self.stats["true_alerts"] += 1
            self.stats["mttd"].append(self.tick - getattr(h, "compromised_at", self.tick))
            self._log("detect", f"Attack detected on {h.label} (anomaly {self.anomaly[n]:.2f}, {self.models.active})")
            self.chain.add("ATTACK_DETECTED", {"node": n, "score": self.anomaly[n], "model": self.models.active}, self.tick)
            new.append(n)
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
            if inc["stage"] != "detected":
                continue
            h = self.net.hosts[n]
            before_paths = self.ag.count_simple_paths()
            before_edges = [e for e in self.ag.edges.values() if n in (e["source"], e["target"])]
            preds = [p["node"] for p in self.prediction]
            h.status = "isolated"
            self._act(inc, "isolate", f"{h.label} quarantined from the network")
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
            for a, b in list(self.net.links):
                other = b if a == n else a if b == n else None
                if other and not self.net.hosts[other].infra and not self.net.is_cut(a, b):
                    self.net.cut_link(a, b)
                    self._act(inc, "reroute", f"Back-end link {a} <-> {b} disabled, traffic rerouted")
            self.ag.rebuild()
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
            if inc["stage"] == "responded" and self.tick - inc["responded"] >= 1:
                h.status = "healing"
                inc["stage"] = "restoring"
                self._act(inc, "restore", f"{h.label} re-imaged from last clean backup")
                acted = True
            elif inc["stage"] == "restoring" and self.tick - inc["responded"] >= 3:
                for v in h.vulns:
                    v.patched = True
                h.status = "normal"
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
        self.incidents[node] = {"node": node, "detected": self.tick, "stage": "detected", "actions": []}
        self._log("respond", f"Manual response triggered for {h.label}")
        self._respond()
        return True

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
        return {
            "detection_rate": round(s["flows_caught"] / s["flows_attack"], 3) if s["flows_attack"] else None,
            "prediction_accuracy": round(s["predictions_correct"] / s["predictions"], 3) if s["predictions"] else None,
            "mttd": avg(s["mttd"]), "mttr": avg(s["mttr"]),
            "healed": s["healed"], "breaches": s["breaches"], "campaigns": s["campaigns"],
            "contained": s["contained"], "false_positives": s["false_positives"],
            "attacks_blocked": s["attacks_blocked"], "chain_valid": self.chain.verify()["valid"],
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
            },
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


def run_experiment(models: ModelSuite, runs: int = 12, ticks: int = 45) -> dict:
    """Monte-Carlo comparison: breach rate with and without self-healing."""
    out = {}
    for heal in (False, True):
        breaches, compromised, mttr = 0, 0, []
        for r in range(runs):
            sim = Simulator(seed=1000 + r, models=models)
            sim.auto_heal = heal
            sim.launch(list(SCENARIOS)[r % len(SCENARIOS)])
            sim.step(ticks)
            breaches += 1 if sim.stats["breaches"] else 0
            compromised += len(sim.compromised) - 1
            mttr += sim.stats["mttr"]
        out["with_healing" if heal else "without_healing"] = {
            "breach_rate": round(breaches / runs, 3),
            "avg_compromised": round(compromised / runs, 2),
            "avg_mttr": round(sum(mttr) / len(mttr), 2) if mttr else None,
        }
    out["runs"] = runs
    out["ticks"] = ticks
    return out
