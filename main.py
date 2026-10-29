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
    print("Detection models (trained on deliberately overlapping traffic):")
    for r in sim.models.to_dict()["results"]:
        print(f"  {r['name']:<22} acc={r['accuracy']:.3f} f1={r['f1']:.3f} "
              f"auc={r['auc']:.3f} train={r['train_ms']}ms")

    print(f"\nMonte-Carlo experiment ({runs} campaigns x {ticks} ticks, "
          f"self-healing off vs on)...")
    res = run_experiment(sim.models, runs=runs, ticks=ticks)
    rows = [
        ("breach rate", "breach_rate", "{:.1%}"),
        ("hosts compromised", "avg_compromised", "{:.2f}"),
        ("mean time to detect", "mttd", "{:.2f} ticks"),
        ("mean time to recover", "mttr", "{:.2f} ticks"),
        ("false-positive isolations", "false_positive_isolations", "{:.2f}"),
        ("availability cost", "availability_cost", "{:.2f}"),
        ("service availability", "service_availability", "{:.1f}%"),
    ]
    print(f"\n  {'metric':<28}{'without healing':>24}{'with healing':>24}")
    print("  " + "-" * 76)
    for label, key, fmt in rows:
        cells = []
        for side in ("without_healing", "with_healing"):
            v = res[side][key]
            if v["mean"] is None:
                cells.append("n/a")
            else:
                cells.append(fmt.format(v["mean"]) + f" +/-{v['ci95']:.2f}")
        print(f"  {label:<28}{cells[0]:>24}{cells[1]:>24}")
    print("\n  " + res["interpretation"])
    print("\n  Per-scenario breach rate (with healing):")
    for k, v in res["per_scenario"]["with_healing"].items():
        name = res["scenario_names"][k]
        if v["mean"] is not None:
            print(f"    {name:<26} {v['mean']:.0%} (n={v['n']})")


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
