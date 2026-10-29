"""Traffic simulation and feature extraction (Section 3).

Each flow becomes a 13-dimensional feature vector made of traffic features,
graph features (from the live topology) and time-based features.

Realism notes
-------------
Benign and malicious profiles deliberately OVERLAP. Three benign activities --
`admin_scan`, `backup_burst` and `patch_push` -- are almost indistinguishable from
`scan`, `exfil` and `lateral` on the eight traffic features alone. The only thing
that separates them is *who is talking to whom*, so a classifier is forced to use
the graph features (src_degree, dst_centrality, hops_to_critical) to do well.
That is the whole thesis of the project, and it is why the detector scores a
believable ~85% instead of a suspicious ~99%.

Training labels also carry a small amount of noise (`LABEL_NOISE`), the way a real
SOC dataset does, and `drift` lets profile means move after training so the models
can be shown degrading under concept drift.
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

# Fraction of training labels that are wrong, as in a hand-triaged SOC dataset.
LABEL_NOISE = 0.03

# (mean, std) for: duration, bytes_log, packets_log, avg_pkt_size, protocol,
#                  port_entropy, conn_rate, failed_auth, rate_change, rolling_mean
P = Tuple[float, float]
PROFILES: Dict[str, List[P]] = {
    # ---- ordinary benign
    "web":     [(1.2, .9), (9.5, 1.3), (3.5, .9), (750, 300), (4, 0), (.6, .45), (4, 2.5), (0, .4), (0, .45), (9.3, 1.1)],
    "db":      [(.4, .35), (8.5, 1.2), (3.0, .8), (420, 190), (0, 0), (.3, .3), (6, 3.5), (.1, .4), (0, .4), (8.4, 1.0)],
    "email":   [(2, 1.2), (10.5, 1.4), (3.8, 1.0), (900, 350), (4, 0), (.5, .4), (2, 1.3), (.1, .4), (0, .4), (10, 1.2)],
    "smb":     [(1.5, 1.1), (9.0, 1.4), (3.2, .9), (600, 290), (3, 0), (.8, .5), (3, 2.3), (.2, .5), (0, .5), (9, 1.2)],
    "backup":  [(30, 12), (15, 1.2), (8.5, .9), (1300, 180), (0, 0), (.2, .15), (1, .6), (0, .25), (.1, .4), (14, 1.2)],
    "atm":     [(.8, .5), (7.5, 1.0), (2.5, .7), (380, 150), (4, 0), (.2, .15), (1.5, 1.0), (0, .25), (0, .3), (7.5, .9)],

    # ---- benign, but looks exactly like an attack on traffic features alone.
    # These are what stop the detector from being trivially perfect.
    "admin_scan":   [(.08, .05), (5.4, 1.0), (1.4, .5), (90, 45), (2, 0), (2.8, .7), (34, 13), (.4, .6), (2.1, .9), (5.8, 1.2)],
    "backup_burst": [(38, 16), (15.4, 1.3), (8.8, .9), (1380, 130), (0, 0), (.3, .25), (1.4, .8), (0, .3), (1.9, .9), (13.2, 1.6)],
    "patch_push":   [(1.1, .8), (9.6, 1.3), (3.5, .9), (720, 280), (3, 0), (1.9, .7), (11, 5), (1.4, 1.4), (1.4, .8), (9.2, 1.3)],

    # ---- malicious
    "scan":       [(.06, .05), (5.2, 1.0), (1.3, .5), (80, 40), (2, 0), (3.0, .7), (38, 14), (.35, .6), (2.4, .9), (5.6, 1.2)],
    "exploit":    [(.7, .5), (8.9, 1.2), (3.1, .9), (930, 330), (4, 0), (1.1, .6), (7.5, 4.5), (.5, .8), (1.4, .7), (8.6, 1.2)],
    "bruteforce": [(.22, .14), (6.6, 1.0), (2.1, .6), (170, 75), (0, 0), (.5, .4), (28, 11), (8, 4.5), (1.9, .8), (6.6, 1.0)],
    "lateral":    [(1.05, .8), (9.5, 1.3), (3.4, .9), (710, 280), (3, 0), (2.0, .7), (11.5, 5.5), (1.8, 1.6), (1.5, .8), (9.1, 1.3)],
    "c2":         [(58, 32), (6.9, 1.0), (2.8, .7), (210, 95), (4, 0), (.35, .25), (1.1, .6), (0, .35), (.25, .4), (6.9, .9)],
    "exfil":      [(39, 16), (15.7, 1.3), (8.9, .9), (1390, 120), (4, 0), (.32, .25), (1.5, .9), (0, .35), (2.1, .9), (12.6, 1.6)],
    "ransomware": [(3, 2.2), (13, 1.7), (7.0, 1.2), (1100, 280), (3, 0), (2.6, .8), (24, 9), (.5, .9), (2.8, 1.0), (12, 1.7)],
}

CONFUSABLE = ["admin_scan", "backup_burst", "patch_push"]
BENIGN = ["web", "db", "email", "smb", "backup", "atm"] + CONFUSABLE
MALICIOUS = ["scan", "exploit", "bruteforce", "lateral", "c2", "exfil", "ransomware"]

# The benign activity each attack is statistically nearest to. A stealthy attack
# blends toward it; the detector has to tell the pair apart from context.
MIMIC = {
    "scan": "admin_scan", "exploit": "web", "bruteforce": "db", "lateral": "patch_push",
    "c2": "web", "exfil": "backup_burst", "ransomware": "smb",
}
# Human-readable reason each attack class is hard to spot.
CONFUSION_NOTE = {
    "scan": "looks like an IT asset-discovery sweep",
    "exfil": "looks like the nightly backup window",
    "lateral": "looks like an admin patch rollout",
    "bruteforce": "looks like an application retrying a database login",
    "c2": "looks like a long-lived HTTPS session",
    "exploit": "looks like ordinary web traffic",
    "ransomware": "looks like bulk SMB file access",
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
    # --- the confusable ones: benign, but attack-shaped
    ("siem", "user1", "admin_scan"), ("siem", "user2", "admin_scan"),
    ("siem", "atm1", "admin_scan"), ("siem", "web", "admin_scan"),
    ("db", "backup", "backup_burst"), ("core", "backup", "backup_burst"),
    ("admin", "user1", "patch_push"), ("admin", "user2", "patch_push"),
    ("admin", "user3", "patch_push"),
]


def _clip(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


def make_flow(rng: random.Random, kind: str, src: str, dst: str, stealth: float,
              graph_ctx: Dict[str, Dict[str, float]], drift: float = 0.0) -> dict:
    """Sample one flow.

    `stealth` in [0,1] blends a malicious profile toward the benign activity it
    imitates. `drift` in [0,1] shifts every mean slightly, simulating the network
    changing after the models were trained (concept drift).
    """
    prof = PROFILES[kind]
    mimic = PROFILES[MIMIC[kind]] if kind in MIMIC else prof
    s = stealth if kind in MIMIC else 0.0
    vals = []
    for (m, sd), (mm, msd) in zip(prof, mimic):
        mean = m * (1 - s) + mm * s
        std = sd * (1 - s) + msd * s
        if drift:
            mean *= 1.0 + drift * 0.25
            std *= 1.0 + drift * 0.5
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
                       n: int = 1600, attack_ratio: float = 0.4,
                       label_noise: float = LABEL_NOISE) -> List[dict]:
    """Labelled dataset: benign conversations + attacks of every kind at varying stealth.

    A `label_noise` fraction of labels is deliberately flipped so the models cannot
    reach an unrealistic ceiling, mirroring analyst mislabelling in real data.
    """
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
    for d in data:
        if rng.random() < label_noise:
            d["label"] = 1 - d["label"]
            d["noisy_label"] = True
    rng.shuffle(data)
    return data
