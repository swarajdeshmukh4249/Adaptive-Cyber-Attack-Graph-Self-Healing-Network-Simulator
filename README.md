# Adaptive Cyber Attack Graph & Self-Healing Network Simulator

Models attacker behaviour on a cyber attack graph, detects and predicts attack progression with
machine learning, and automatically applies defensive actions so the network heals itself.

## Run

```bash
python3 main.py            # dashboard at http://127.0.0.1:8000
python3 main.py --port 9000 --open
python3 main.py --headless # terminal experiment: self-healing on vs off
```

No dependencies: the engine is pure Python standard library (3.9+). The dashboard loads React,
Tailwind and Three.js from CDNs, so the browser needs internet access.

## Why the numbers are believable

A simulator can always be tuned to produce a flattering result. These are the choices
that stop it, and they are the first things worth checking:

| Risk | What the engine does about it |
|---|---|
| Detector grading its own homework | Three *benign* activities (`admin_scan`, `backup_burst`, `patch_push`) are statistically almost identical to `scan`, `exfil` and `lateral` on the eight traffic features. Only the graph features separate them, so the detector has to earn its score. Training labels also carry 3% noise. Result: a realistic ~85%, not a suspicious ~99%. |
| Detector peeking at ground truth | `_detect()` raises an incident on the smoothed anomaly score **alone**. It cannot see whether a host is really compromised, so it isolates healthy hosts sometimes — and that costs real availability. |
| Passive attacker | The adversary tracks detection pressure (`heat`). When the defence takes a foothold away or blocks traffic it goes dormant, blends harder into normal traffic, burns failed edges and reroutes. It also has to escalate privilege before entering the `secure` and `critical` zones. |
| Free defence | Response is gated by a SOC approval delay, and false-positive isolations are counted against an availability budget. Benefit and cost are reported side by side. |
| Means without error bars | Every Monte-Carlo figure is a mean with a 95% confidence interval, plus an explicit significance check and a per-scenario breakdown. |
| Dimensionless ticks | 1 tick = 30 seconds, so MTTD and MTTR are quoted in real time. |

Because of this the headline result is a defensible **~60-100% breach rate without
self-healing versus ~0-10% with it**, with non-overlapping confidence intervals and a
stated cost of roughly 0.5 false-positive isolations per campaign — rather than a
too-clean 100% to 0%.

## Workload failover: what self-healing actually buys you

Isolating a compromised server protects the network but stops the work it was doing.
`backend/services.py` adds the missing half: eight business services (Core Ledger,
SWIFT Gateway, Customer Database, Internet Banking, Partner API, ATM Switching,
Corporate Mail, Directory/Auth) run on hosts and **move to a hot standby when their
host is quarantined**, then move back once it is rebuilt and verified clean.

Three standby machines exist for this: **Web Server #2**, **DB Replica** and
**Core Banking #2**.

Failover is deliberately not free:

* a switchover takes 2 ticks during which the service is genuinely **down**;
* every host has a finite capacity, so a standby absorbing several services becomes
  over-subscribed and its services go **degraded** (serving, but at half credit);
* if no healthy eligible host remains, the service is simply **down**.

That gives the project its clearest headline number — **service availability**, the
business-weighted share of work actually serving:

| | without self-healing | with self-healing |
|---|---|---|
| service availability | 72.3% ± 6.4% | **95.6% ± 0.7%** |
| hosts compromised | 8.67 ± 1.57 | 0.00 |

Those intervals do not overlap. A typical run reads:

```
t4  Corporate Mail failing over from Mail Server to Web Server #2 (2 tick switchover)
t6  Internet Banking + Partner API failing over from Web Server to Web Server #2
t8  all three serving again from Web Server #2   (85.9% - Web #2 is over-subscribed)
t14 failing back now that the originals are verified clean
t16 100% serving
```

## The two topology views

The hero panel has a **2D / 3D toggle**, and **2D is the default** because it is the
one you can actually read.

* **2D (`frontend/components/network2d.js`)** – zones are fixed left-to-right columns
  (external → perimeter → DMZ → internal → ATM → secure → critical), so an attack
  working inward is literally movement across the screen. Positions are deterministic,
  so there is no occlusion, no colliding labels, and the same picture every time you
  screenshot it. Live traffic is drawn as dots travelling along the links (grey benign,
  amber flagged, red hostile), the most-probable attack path is highlighted with the
  predicted next target ringed, and **service chips slide between servers when a
  workload fails over**.
* **3D (`frontend/components/network3d.js`)** – the original Three.js scene, kept as the
  visual hook. Orbit it, but read the 2D one.

## Reading a run

Open the **Read this run** panel (first tab of the pipeline carousel). It shows:

* **What is happening** — a plain-English narration of the current tick, generated from
  the same numbers the engine acted on.
* **Inside the adversary** — its posture, detection pressure and how hard it is currently
  blending into normal traffic.
* **Why the detector fired** — occlusion attribution: each feature is replaced by its
  training median and the score movement is measured, so you see the real evidence
  behind a verdict rather than a black box. Works identically for all four models.
* **Decision trace** — every attacker and defender choice with the numbers behind it.

## How to use the dashboard

1. Pick a scenario (APT kill chain, Web exploit, Insider threat, Ransomware worm) and press **Launch attack**.
2. Watch the 3D topology: red = compromised, gray cage = isolated, green ring = healing, amber reticle = predicted next target.
3. Toggle **Self-healing** off to see the attacker reach the critical system, and back on to see it contained.
4. Click a model in section 4 to switch the live detector; click **Tamper** in section 7 to break the audit chain.
5. **Run experiment** (Outcomes) runs a Monte-Carlo comparison of breach rates with and without self-healing.

## Architecture

| Design section | Implementation |
|---|---|
| 1. Network simulation | `backend/network.py` – hosts, zones, links, firewall policy, betweenness centrality |
| 2. Attack graph | `backend/attack_graph.py` – directed reachability × vulnerability graph, Dijkstra most-probable path, path enumeration, Bayesian (noisy-OR) risk |
| 3. Traffic & features | `backend/traffic.py` – deliberately overlapping benign/malicious flow profiles, 13 traffic/graph/time features, label noise, concept drift |
| 4. Detection & prediction | `backend/ml.py` – SVM, Random Forest, XGBoost-style boosting, GNN, all from scratch, plus model-agnostic occlusion explanations |
| 5–6. Self-healing loop | `backend/simulator.py` – adaptive adversary, honest detection, response latency and cost, detect → isolate / block / firewall / reroute / patch → restore → verify |
| 5b. Workload failover | `backend/services.py` – business services with hot standbys, switchover delay, host capacity and degradation, service-availability metric |
| 7. Audit log | `backend/blockchain.py` – SHA-256 hash chain with proof-of-work, verify / tamper / re-sync |
| Dashboard | `frontend/` – React + Tailwind, 2D SVG topology (default) with the Three.js scene behind a toggle |

API: `GET /api/state`, `POST /api/{step,reset,launch,config,heal,chain/tamper,chain/repair,experiment}`.

`POST /api/config` accepts `auto_heal`, `model`, and three realism knobs: `latency`
(SOC approval delay in ticks), `threshold` (anomaly score needed to open an incident)
and `drift` (how far traffic has moved since the models were trained). Raising `drift`
is the quickest way to show the detector degrading on data it was not trained for.
