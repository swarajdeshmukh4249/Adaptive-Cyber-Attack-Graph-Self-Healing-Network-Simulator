"""Adaptive Cyber Attack Graph & Self-Healing Network Simulator.

Usage:
    python3 main.py                 # start the dashboard on http://127.0.0.1:8000
    python3 main.py --port 9000
    python3 main.py --headless      # run a self-healing on/off experiment in the terminal
"""
import argparse
import webbrowser

from backend.server import serve
from backend.simulator import Simulator, run_experiment


def headless(runs: int, ticks: int) -> None:
    sim = Simulator()
    print("Model comparison:")
    for r in sim.models.to_dict()["results"]:
        print(f"  {r['name']:<22} acc={r['accuracy']:.3f} f1={r['f1']:.3f} auc={r['auc']:.3f} train={r['train_ms']}ms")
    print(f"\nMonte-Carlo experiment ({runs} campaigns x {ticks} ticks)...")
    res = run_experiment(sim.models, runs=runs, ticks=ticks)
    for k in ("without_healing", "with_healing"):
        print(f"  {k:<16} {res[k]}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--runs", type=int, default=12)
    ap.add_argument("--ticks", type=int, default=45)
    args = ap.parse_args()
    if args.headless:
        headless(args.runs, args.ticks)
    else:
        if args.open:
            webbrowser.open(f"http://{args.host}:{args.port}")
        serve(args.host, args.port)
