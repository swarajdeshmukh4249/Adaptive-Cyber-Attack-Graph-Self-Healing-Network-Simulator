"""Zero-dependency HTTP server: serves the dashboard and a small JSON API."""
from __future__ import annotations

import json
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .simulator import Simulator, run_experiment

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"

_lock = threading.Lock()
_sim: Simulator = None  # type: ignore[assignment]
_experiment: dict = {"status": "idle", "result": None}


def _run_experiment(runs: int, ticks: int) -> None:
    try:
        _experiment["result"] = run_experiment(_sim.models, runs=runs, ticks=ticks)
        _experiment["status"] = "done"
    except Exception as exc:  # surfaced to the UI
        _experiment.update(status="error", error=str(exc))


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberSim/1.0"

    def log_message(self, fmt, *args):  # keep the console quiet
        pass

    # ---------------------------------------------------------------- helpers
    def _json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return {}

    # ---------------------------------------------------------------- routes
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/state":
            with _lock:
                return self._json(_sim.snapshot())
        if path == "/api/experiment":
            return self._json(_experiment)
        self._static(path)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        data = self._body()
        with _lock:
            if path == "/api/step":
                _sim.step(int(data.get("n", 1)))
            elif path == "/api/reset":
                _sim.reset(seed=data.get("seed"), scenario=data.get("scenario"))
            elif path == "/api/launch":
                _sim.launch(data.get("scenario"))
            elif path == "/api/config":
                try:
                    _sim.set_config(auto_heal=data.get("auto_heal"), model=data.get("model"))
                except KeyError:
                    return self._json({"error": "unknown model"}, 400)
            elif path == "/api/heal":
                _sim.manual_heal(str(data.get("node", "")))
            elif path == "/api/chain/tamper":
                _sim.chain.tamper(data.get("index"))
            elif path == "/api/chain/repair":
                _sim.chain.repair()
            elif path == "/api/experiment":
                if _experiment["status"] != "running":
                    _experiment.update(status="running", result=None)
                    runs = max(2, min(int(data.get("runs", 12)), 40))
                    ticks = max(10, min(int(data.get("ticks", 45)), 120))
                    threading.Thread(target=_run_experiment, args=(runs, ticks), daemon=True).start()
                return self._json(_experiment)
            else:
                return self._json({"error": "not found"}, 404)
            return self._json(_sim.snapshot())

    def _static(self, path: str) -> None:
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        target = (FRONTEND / rel).resolve()
        if FRONTEND not in target.parents or not target.is_file():
            self.send_error(404)
            return
        body = target.read_bytes()
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if target.suffix == ".js":
            ctype = "text/javascript"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    global _sim
    print("Training detection models (SVM, Random Forest, XGBoost-style, GNN)...")
    _sim = Simulator()
    for r in _sim.models.to_dict()["results"]:
        print(f"  {r['name']:<22} acc={r['accuracy']:.3f}  f1={r['f1']:.3f}  auc={r['auc']:.3f}")
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"\n  Dashboard ready ->  http://{host}:{port}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        httpd.server_close()
