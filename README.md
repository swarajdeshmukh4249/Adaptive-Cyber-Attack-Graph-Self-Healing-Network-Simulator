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
| 3. Traffic & features | `backend/traffic.py` – benign/malicious flow profiles, 13 traffic/graph/time features |
| 4. Detection & prediction | `backend/ml.py` – SVM, Random Forest, XGBoost-style boosting, GNN, all from scratch |
| 5–6. Self-healing loop | `backend/simulator.py` – detect → isolate / block / firewall / reroute / patch → restore → verify |
| 7. Audit log | `backend/blockchain.py` – SHA-256 hash chain with proof-of-work, verify / tamper / re-sync |
| Dashboard | `frontend/` – React + Tailwind + Three.js, reusing the GlowingEffect component |

API: `GET /api/state`, `POST /api/{step,reset,launch,config,heal,chain/tamper,chain/repair,experiment}`.
