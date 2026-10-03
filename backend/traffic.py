"""Traffic simulation and feature extraction (Section 3).

Each flow becomes a 13-dimensional feature vector made of traffic features,
graph features (from the live topology) and time-based features.
"""
from __future__ import annotations

import math
import random
from typing import Dict, List, Sequence, Tuple

FEATURES = [
    "duration", "bytes_log", "packets_log", "avg_pkt_size", "protocol",
    "port_entropy", "conn_rate", "failed_auth",
    "src_degree", "dst_centrality", "hops_to_critical",
    "rate_change", "rolling_mean",
]
FEATURE_GROUPS = {
    "traffic": FEATURES[0:8],
    "graph": FEATURES[8:11],
    "time": FEATURES[11:13],
}
PROTOCOLS = ["TCP", "UDP", "ICMP", "SMB", "HTTPS"]

# (mean, std) for: duration, bytes_log, packets_log, avg_pkt_size, protocol,
#                  port_entropy, conn_rate, failed_auth, rate_change, rolling_mean
P = Tuple[float, float]
PROFILES: Dict[str, List[P]] = {
    # ---- benign
    "web":     [(1.2, .8), (9.5, 1.0), (3.5, .7), (750, 250), (4, 0), (.6, .3), (4, 2), (0, .3), (0, .3), (9.3, .8)],
    "db":      [(.4, .3), (8.5, 1.0), (3.0, .6), (420, 150), (0, 0), (.3, .2), (6, 3), (.1, .3), (0, .3), (8.4, .8)],
    "email":   [(2, 1), (10.5, 1.2), (3.8, .8), (900, 300), (4, 0), (.5, .3), (2, 1), (.1, .3), (0, .3), (10, 1)],
    "smb":     [(1.5, 1), (9.0, 1.3), (3.2, .8), (600, 250), (3, 0), (.8, .4), (3, 2), (.2, .4), (0, .4), (9, 1)],
    "backup":  [(30, 10), (15, 1.0), (8.5, .7), (1300, 150), (0, 0), (.2, .1), (1, .5), (0, .2), (.1, .3), (14, 1)],
    "atm":     [(.8, .4), (7.5, .8), (2.5, .5), (380, 120), (4, 0), (.2, .1), (1.5, .8), (0, .2), (0, .2), (7.5, .7)],
    # ---- malicious
    "scan":       [(.05, .04), (5, .8), (1.2, .4), (70, 30), (2, 0), (3.2, .6), (40, 12), (.3, .5), (2.5, .8), (5.5, 1)],
    "exploit":    [(.6, .4), (8.8, 1.0), (3.0, .7), (950, 300), (4, 0), (1.2, .5), (8, 4), (.5, .7), (1.5, .6), (8.5, 1)],
    "bruteforce": [(.2, .1), (6.5, .8), (2.0, .5), (160, 60), (0, 0), (.4, .3), (30, 10), (9, 4), (2, .7), (6.5, .8)],
    "lateral":    [(1, .7), (9.5, 1.2), (3.4, .8), (700, 250), (3, 0), (2.2, .6), (12, 5), (2, 1.5), (1.6, .7), (9, 1.2)],
    "c2":         [(60, 30), (6.8, .8), (2.8, .6), (200, 80), (4, 0), (.3, .2), (1, .5), (0, .3), (.2, .3), (6.8, .6)],
    "exfil":      [(40, 15), (16, 1.2), (9.0, .8), (1400, 100), (4, 0), (.3, .2), (1.5, .8), (0, .3), (2.2, .8), (12, 1.5)],
    "ransomware": [(3, 2), (13, 1.5), (7.0, 1.0), (1100, 250), (3, 0), (2.8, .7), (25, 8), (.5, .8), (3, .9), (12, 1.5)],
}
BENIGN = ["web", "db", "email", "smb", "backup", "atm"]
MALICIOUS = ["scan", "exploit", "bruteforce", "lateral", "c2", "exfil", "ransomware"]
# Benign profile a stealthy attack imitates.
MIMIC = {
    "scan": "web", "exploit": "web", "bruteforce": "db", "lateral": "smb",
    "c2": "web", "exfil": "backup", "ransomware": "smb",
}

# Typical benign conversations (src, dst, kind).
BENIGN_PAIRS: List[Tuple[str, str, str]] = [
    ("internet", "web", "web"), ("internet", "web", "web"), ("user1", "web", "web"),
    ("user3", "web", "web"), ("web", "db", "db"), ("admin", "db", "db"),
    ("db", "core", "db"), ("admin", "core", "db"),
    ("internet", "mail", "email"), ("mail", "user1", "email"), ("mail", "user2", "email"),
    ("mail", "user3", "email"), ("user1", "user2", "smb"), ("user2", "admin", "smb"),
    ("user3", "admin", "smb"), ("db", "backup", "backup"), ("admin", "backup", "backup"),
    ("atm1", "db", "atm"), ("atm2", "db", "atm"), ("siem", "admin", "smb"),
]


def _clip(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


def make_flow(rng: random.Random, kind: str, src: str, dst: str, stealth: float,
              graph_ctx: Dict[str, Dict[str, float]]) -> dict:
    """Sample one flow. `stealth` in [0,1] blends a malicious profile toward a benign one."""
    prof = PROFILES[kind]
    mimic = PROFILES[MIMIC[kind]] if kind in MIMIC else prof
    s = stealth if kind in MIMIC else 0.0
    vals = []
    for (m, sd), (mm, msd) in zip(prof, mimic):
        mean = m * (1 - s) + mm * s
        std = sd * (1 - s) + msd * s
        vals.append(rng.gauss(mean, std) if std > 0 else mean)
    duration, b, pk, size, proto, ent, conn, fail, rc, rm = vals
    proto_idx = max(0, min(4, int(round(proto))))
    deg = graph_ctx["degree"]
    cen = graph_ctx["centrality"]
    hops = graph_ctx["hops"]
    x = [
        round(_clip(duration, 0.0, 200.0), 3),
        round(_clip(b, 2.0, 20.0), 3),
        round(_clip(pk, 0.0, 12.0), 3),
        round(_clip(size, 40.0, 1500.0), 1),
        float(proto_idx),
        round(_clip(ent, 0.0, 5.0), 3),
        round(_clip(conn, 0.0, 120.0), 2),
        round(_clip(fail, 0.0, 30.0), 2),
        round(deg.get(src, 0.1), 3),
        round(cen.get(dst, 0.0), 4),
        round(hops.get(dst, 1.0), 3),
        round(rc, 3),
        round(_clip(rm, 2.0, 20.0), 3),
    ]
    return {
        "src": src,
        "dst": dst,
        "kind": kind,
        "label": 1 if kind in MALICIOUS else 0,
        "protocol": PROTOCOLS[proto_idx],
        "bytes": int(math.exp(x[1])),
        "x": x,
    }


def build_training_set(rng: random.Random, graph_ctx, attack_pairs: Sequence[Tuple[str, str]],
                       n: int = 1600, attack_ratio: float = 0.4) -> List[dict]:
    """Labelled dataset: benign conversations + attacks of every kind at varying stealth."""
    data = []
    n_attack = int(n * attack_ratio)
    for _ in range(n - n_attack):
        src, dst, kind = rng.choice(BENIGN_PAIRS)
        data.append(make_flow(rng, kind, src, dst, 0.0, graph_ctx))
    for _ in range(n_attack):
        kind = rng.choice(MALICIOUS)
        src, dst = rng.choice(attack_pairs)
        stealth = rng.random() ** 1.6 * 0.85
        data.append(make_flow(rng, kind, src, dst, stealth, graph_ctx))
    rng.shuffle(data)
    return data
