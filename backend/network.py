"""Virtual network: hosts, physical links, zones and firewall policy.

Models a small financial / ATM network (Section 1 of the design).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class Vulnerability:
    cve: str
    name: str
    technique: str          # MITRE ATT&CK style technique label
    exploitability: float   # probability a single attempt succeeds (0..1)
    patched: bool = False

    def to_dict(self) -> dict:
        return {
            "cve": self.cve,
            "name": self.name,
            "technique": self.technique,
            "exploitability": self.exploitability,
            "patched": self.patched,
        }


@dataclass
class Host:
    id: str
    label: str
    kind: str               # cloud, firewall, switch, server, db, workstation, atm, critical, attacker, monitor
    zone: str               # external, perimeter, dmz, internal, atm, secure, critical, mgmt
    ip: str
    criticality: float
    services: List[str]
    vulns: List[Vulnerability]
    pos: Tuple[float, float, float]
    status: str = "normal"  # normal | compromised | isolated | healing | attacker
    infra: bool = False      # forwarding device (traffic passes through, never a target)
    priv: int = 0            # attacker's privilege here: 0 none, 1 user, 2 admin/root
    standby_for: Optional[str] = None   # this host is the hot standby of another host

    def open_vulns(self) -> List[Vulnerability]:
        return [v for v in self.vulns if not v.patched]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "kind": self.kind,
            "zone": self.zone,
            "ip": self.ip,
            "criticality": self.criticality,
            "services": self.services,
            "vulns": [v.to_dict() for v in self.vulns],
            "pos": list(self.pos),
            "status": self.status,
            "infra": self.infra,
            "priv": self.priv,
            "standby_for": self.standby_for,
        }


# Zone-to-zone flows the default firewall policy permits (directional).
DEFAULT_ZONE_POLICY: Set[Tuple[str, str]] = {
    ("external", "dmz"),
    ("dmz", "internal"),     # mail delivery to workstations (phishing vector)
    ("internal", "internal"),
    ("internal", "dmz"),
    ("internal", "secure"),
    ("atm", "secure"),
    ("secure", "secure"),
    ("secure", "critical"),
    ("secure", "atm"),
    ("mgmt", "internal"),
    ("mgmt", "secure"),
    ("mgmt", "dmz"),
}


@dataclass
class FirewallRule:
    id: int
    action: str       # deny | allow
    src: str          # host id, zone name, ip or "*"
    dst: str
    reason: str
    tick: int

    def matches(self, src: Host, dst: Host) -> bool:
        return self.src in ("*", src.id, src.zone, src.ip) and self.dst in ("*", dst.id, dst.zone)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "action": self.action,
            "src": self.src,
            "dst": self.dst,
            "reason": self.reason,
            "tick": self.tick,
        }


def _v(cve, name, technique, p):
    return Vulnerability(cve, name, technique, p)


def build_default_hosts() -> Dict[str, Host]:
    hosts = [
        Host("attacker", "Threat Actor", "attacker", "external", "198.51.100.66", 0.0, ["c2"], [], (-9.0, 4.0, 0.0), status="attacker"),
        Host("internet", "Internet", "cloud", "external", "203.0.113.1", 0.1, ["bgp"], [], (-6.0, 3.0, 0.0), infra=True),
        Host("firewall", "Firewall", "firewall", "perimeter", "10.0.0.1", 0.6, ["ngfw", "ids"], [], (-3.0, 2.5, 0.0), infra=True),
        Host("switch", "Core Switch", "switch", "perimeter", "10.0.0.2", 0.5, ["vlan"], [], (0.0, 2.0, 0.0), infra=True),
        Host("web", "Web Server", "server", "dmz", "10.0.1.10", 0.55, ["https", "api"], [
            _v("CVE-2021-41773", "Apache path traversal RCE", "Exploit Public-Facing App", 0.72),
        ], (-3.0, 0.0, -3.0)),
        Host("web2", "Web Server #2", "server", "dmz", "10.0.1.11", 0.55, ["https-standby"], [
            _v("CVE-2021-41773", "Apache path traversal RCE", "Exploit Public-Facing App", 0.72),
        ], (-4.5, 0.6, -4.6), standby_for="web"),
        Host("mail", "Mail Server", "server", "dmz", "10.0.1.20", 0.45, ["smtp", "imap"], [
            _v("CVE-2023-23397", "Outlook NTLM leak", "Phishing", 0.66),
        ], (-3.5, 0.0, 3.0)),
        Host("user1", "Finance PC", "workstation", "internal", "10.0.2.11", 0.3, ["smb", "rdp"], [
            _v("CVE-2022-30190", "Follina macro execution", "User Execution", 0.62),
        ], (-0.5, -3.0, 4.5)),
        Host("user2", "HR PC", "workstation", "internal", "10.0.2.12", 0.25, ["smb"], [
            _v("WEAK-CRED-01", "Reused local admin password", "Valid Accounts", 0.45),
        ], (1.5, -3.2, 5.0)),
        Host("user3", "Teller PC", "workstation", "internal", "10.0.2.13", 0.3, ["smb", "teller"], [
            _v("CVE-2017-0144", "EternalBlue SMBv1", "Lateral Tool Transfer", 0.55),
        ], (3.5, -3.0, 4.0)),
        Host("atm1", "ATM #1", "atm", "atm", "10.0.5.31", 0.7, ["xfs", "tls"], [
            _v("ATM-XFS-07", "XFS dispenser jackpotting", "Hardware Additions", 0.32),
        ], (5.5, -1.0, 3.0)),
        Host("atm2", "ATM #2", "atm", "atm", "10.0.5.32", 0.7, ["xfs", "tls"], [
            _v("ATM-XFS-07", "XFS dispenser jackpotting", "Hardware Additions", 0.32),
        ], (6.5, -1.0, 0.5)),
        Host("db", "Database Server", "db", "secure", "10.0.3.20", 0.85, ["postgres"], [
            _v("CVE-2019-9193", "SQL COPY FROM PROGRAM", "Privilege Escalation", 0.58),
        ], (2.0, -1.0, -3.5)),
        Host("db2", "DB Replica", "db", "secure", "10.0.3.21", 0.85, ["postgres-replica"], [
            _v("CVE-2019-9193", "SQL COPY FROM PROGRAM", "Privilege Escalation", 0.58),
        ], (2.8, -0.2, -5.2), standby_for="db"),
        Host("admin", "Admin Server", "server", "secure", "10.0.3.30", 0.9, ["ad", "ssh"], [
            _v("T1550.002", "Pass-the-Hash", "Use Alternate Auth Material", 0.6),
        ], (4.5, 0.5, -2.0)),
        Host("backup", "Backup Server", "server", "secure", "10.0.3.40", 0.65, ["rsync"], [
            _v("WEAK-CRED-02", "Default backup credentials", "Valid Accounts", 0.35),
        ], (0.5, -1.5, -6.0)),
        Host("core", "Core Banking", "critical", "critical", "10.0.9.1", 1.0, ["ledger", "swift"], [
            _v("CVE-2024-CORE", "Ledger admin RCE", "Impact: Critical System", 0.5),
        ], (6.0, -3.0, -5.0)),
        Host("core2", "Core Banking #2", "critical", "critical", "10.0.9.2", 1.0, ["ledger-standby"], [
            _v("CVE-2024-CORE", "Ledger admin RCE", "Impact: Critical System", 0.5),
        ], (7.2, -2.2, -6.8), standby_for="core"),
        Host("siem", "SIEM / Monitor", "monitor", "mgmt", "10.0.8.5", 0.4, ["siem", "ml"], [], (-1.0, 4.5, -2.0)),
    ]
    return {h.id: h for h in hosts}


DEFAULT_LINKS: List[Tuple[str, str]] = [
    ("attacker", "internet"),
    ("internet", "firewall"),
    ("firewall", "switch"),
    ("switch", "web"),
    ("switch", "web2"),
    ("switch", "mail"),
    ("switch", "user1"),
    ("switch", "user2"),
    ("switch", "user3"),
    ("switch", "atm1"),
    ("switch", "atm2"),
    ("switch", "db"),
    ("switch", "db2"),
    ("switch", "admin"),
    ("switch", "backup"),
    ("switch", "siem"),
    ("web", "db"),
    ("web2", "db"),
    ("admin", "core"),
    ("admin", "core2"),
    ("db", "core"),
    ("db2", "core2"),
    ("db", "db2"),
    ("core", "core2"),
    ("db", "backup"),
]


class Network:
    """Physical topology + firewall. Answers reachability queries for the attack graph."""

    def __init__(self) -> None:
        self.hosts: Dict[str, Host] = build_default_hosts()
        self.links: List[Tuple[str, str]] = list(DEFAULT_LINKS)
        self.zone_policy: Set[Tuple[str, str]] = set(DEFAULT_ZONE_POLICY)
        self.rules: List[FirewallRule] = []
        self.blocked_ips: Set[str] = set()
        self.cut_links: Set[Tuple[str, str]] = set()   # links removed by path reconfiguration
        self._rule_seq = 0
        self._adj_cache: Optional[Dict[str, List[str]]] = None

    # ---------------------------------------------------------------- topology
    def adjacency(self) -> Dict[str, List[str]]:
        if self._adj_cache is None:
            adj: Dict[str, List[str]] = {h: [] for h in self.hosts}
            for a, b in self.links:
                if self.is_cut(a, b):
                    continue
                adj[a].append(b)
                adj[b].append(a)
            self._adj_cache = adj
        return self._adj_cache

    def invalidate(self) -> None:
        self._adj_cache = None

    def is_cut(self, a: str, b: str) -> bool:
        return (a, b) in self.cut_links or (b, a) in self.cut_links

    def degree(self, host_id: str) -> int:
        return len(self.adjacency()[host_id])

    def physically_reachable(self, src: str, dst: str) -> bool:
        """BFS that may only transit forwarding devices (switch, firewall, internet)."""
        if src == dst:
            return True
        adj = self.adjacency()
        seen = {src}
        q = deque([src])
        while q:
            cur = q.popleft()
            for nxt in adj[cur]:
                if nxt in seen or self.hosts[nxt].status == "isolated":
                    continue
                if nxt == dst:
                    return True
                if self.hosts[nxt].infra:
                    seen.add(nxt)
                    q.append(nxt)
        return False

    def directly_linked(self, a: str, b: str) -> bool:
        return b in self.adjacency()[a]

    # ---------------------------------------------------------------- firewall
    def policy_allows(self, src: Host, dst: Host) -> bool:
        if src.ip in self.blocked_ips:
            return False
        for rule in reversed(self.rules):
            if rule.matches(src, dst):
                return rule.action == "allow"
        if src.zone == dst.zone and src.zone != "external":
            return True
        if self.directly_linked(src.id, dst.id) and not src.infra and not dst.infra:
            return True  # dedicated back-end links (web->db, admin->core)
        return (src.zone, dst.zone) in self.zone_policy

    def can_reach(self, src: str, dst: str) -> bool:
        s, d = self.hosts[src], self.hosts[dst]
        if s.status == "isolated" or d.status == "isolated":
            return False
        if d.infra or d.kind in ("monitor", "attacker"):
            return False
        if not self.policy_allows(s, d):
            return False
        return self.physically_reachable(src, dst)

    def add_rule(self, action: str, src: str, dst: str, reason: str, tick: int) -> FirewallRule:
        self._rule_seq += 1
        rule = FirewallRule(self._rule_seq, action, src, dst, reason, tick)
        self.rules.append(rule)
        return rule

    def cut_link(self, a: str, b: str) -> bool:
        if (a, b) in self.links or (b, a) in self.links:
            self.cut_links.add((a, b))
            self.invalidate()
            return True
        return False

    # ---------------------------------------------------------------- graph metrics
    def betweenness(self) -> Dict[str, float]:
        """Brandes betweenness centrality on the undirected physical graph, normalised."""
        adj = self.adjacency()
        nodes = list(self.hosts)
        cb = {v: 0.0 for v in nodes}
        for s in nodes:
            stack: List[str] = []
            pred: Dict[str, List[str]] = {w: [] for w in nodes}
            sigma = {w: 0 for w in nodes}
            sigma[s] = 1
            dist = {w: -1 for w in nodes}
            dist[s] = 0
            q = deque([s])
            while q:
                v = q.popleft()
                stack.append(v)
                for w in adj[v]:
                    if dist[w] < 0:
                        dist[w] = dist[v] + 1
                        q.append(w)
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]
                        pred[w].append(v)
            delta = {w: 0.0 for w in nodes}
            while stack:
                w = stack.pop()
                for v in pred[w]:
                    delta[v] += sigma[v] / sigma[w] * (1 + delta[w])
                if w != s:
                    cb[w] += delta[w]
        n = len(nodes)
        norm = (n - 1) * (n - 2) if n > 2 else 1
        return {v: round(c / norm, 4) for v, c in cb.items()}

    def hop_distance(self, src: str, dst: str) -> int:
        adj = self.adjacency()
        dist = {src: 0}
        q = deque([src])
        while q:
            cur = q.popleft()
            if cur == dst:
                return dist[cur]
            for nxt in adj[cur]:
                if nxt not in dist:
                    dist[nxt] = dist[cur] + 1
                    q.append(nxt)
        return 99

    def to_dict(self) -> dict:
        return {
            "hosts": [h.to_dict() for h in self.hosts.values()],
            "links": [{"source": a, "target": b, "cut": self.is_cut(a, b)} for a, b in self.links],
            "rules": [r.to_dict() for r in self.rules[-14:]],
            "blocked_ips": sorted(self.blocked_ips),
        }
