"""Attack detection models (Section 4), implemented from scratch in pure Python.

* Linear SVM            - hinge loss + L2, SGD
* Random Forest         - bagged CART trees on histogram (quantile) splits
* XGBoost-style GBM     - second-order gradient boosting of shallow trees
* Graph Neural Network  - SGC-style 2-hop propagated node embeddings + MLP head
"""
from __future__ import annotations

import bisect
import math
import random
import time
from typing import Dict, List, Optional, Sequence

from .traffic import FEATURE_GROUPS, FEATURES

Vec = List[float]


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class Scaler:
    def fit(self, X: Sequence[Vec]) -> "Scaler":
        n, d = len(X), len(X[0])
        self.mu = [sum(r[j] for r in X) / n for j in range(d)]
        self.sd = [
            math.sqrt(sum((r[j] - self.mu[j]) ** 2 for r in X) / n) or 1.0 for j in range(d)
        ]
        return self

    def transform(self, X: Sequence[Vec]) -> List[Vec]:
        return [[(v - m) / s for v, m, s in zip(r, self.mu, self.sd)] for r in X]


# ===================================================================== histogram binning
class Binner:
    """Quantile thresholds per feature, so trees split on bins (LightGBM style)."""

    def __init__(self, n_bins: int = 24) -> None:
        self.n_bins = n_bins

    def fit(self, X: Sequence[Vec]) -> "Binner":
        d = len(X[0])
        self.thresholds: List[List[float]] = []
        for j in range(d):
            col = sorted(r[j] for r in X)
            qs = sorted({col[int(len(col) * k / self.n_bins)] for k in range(1, self.n_bins)})
            self.thresholds.append(qs)
        return self

    def transform(self, X: Sequence[Vec]) -> List[List[int]]:
        return [[bisect.bisect_left(t, v) for v, t in zip(r, self.thresholds)] for r in X]


class _Node:
    __slots__ = ("feat", "thr", "left", "right", "value")

    def __init__(self, value: float) -> None:
        self.feat = -1
        self.thr = 0.0
        self.left: Optional[_Node] = None
        self.right: Optional[_Node] = None
        self.value = value


def _tree_predict(node: _Node, x: Vec) -> float:
    while node.feat >= 0:
        node = node.left if x[node.feat] <= node.thr else node.right
    return node.value


def _tree_depth(node: _Node) -> int:
    if node.feat < 0:
        return 0
    return 1 + max(_tree_depth(node.left), _tree_depth(node.right))


def _tree_leaves(node: _Node) -> int:
    if node.feat < 0:
        return 1
    return _tree_leaves(node.left) + _tree_leaves(node.right)


class HistTree:
    """CART tree over binned features. mode='gini' (classification) or 'newton' (boosting)."""

    def __init__(self, binner: Binner, max_depth: int, min_leaf: int, mode: str,
                 mtry: Optional[int] = None, lam: float = 1.0, rng: Optional[random.Random] = None):
        self.binner = binner
        self.max_depth = max_depth
        self.min_leaf = min_leaf
        self.mode = mode
        self.mtry = mtry
        self.lam = lam
        self.rng = rng or random.Random(0)
        self.importance: Dict[int, float] = {}

    def fit(self, B: List[List[int]], idx: List[int], a: List[float], b: List[float]) -> "HistTree":
        """gini: a = labels (0/1), b unused.  newton: a = gradients, b = hessians."""
        self.root = self._grow(B, idx, a, b, 0)
        return self

    def _leaf_value(self, idx, a, b) -> float:
        if self.mode == "gini":
            return sum(a[i] for i in idx) / len(idx)
        g = sum(a[i] for i in idx)
        h = sum(b[i] for i in idx)
        return -g / (h + self.lam)

    def _grow(self, B, idx, a, b, depth) -> _Node:
        node = _Node(self._leaf_value(idx, a, b))
        n = len(idx)
        if depth >= self.max_depth or n < 2 * self.min_leaf:
            return node
        if self.mode == "gini":
            pos = sum(a[i] for i in idx)
            if pos == 0 or pos == n:
                return node
        d = len(B[0])
        feats = list(range(d))
        if self.mtry:
            feats = self.rng.sample(feats, self.mtry)

        best_gain, best_f, best_k = 1e-9, -1, -1
        if self.mode == "gini":
            parent = n - (pos * pos + (n - pos) * (n - pos)) / n  # n * gini
            for f in feats:
                nb = len(self.binner.thresholds[f]) + 1
                cnt = [0] * nb
                cp = [0.0] * nb
                for i in idx:
                    k = B[i][f]
                    cnt[k] += 1
                    cp[k] += a[i]
                ln = lp = 0.0
                for k in range(nb - 1):
                    ln += cnt[k]
                    lp += cp[k]
                    rn = n - ln
                    if ln < self.min_leaf or rn < self.min_leaf:
                        continue
                    rp = pos - lp
                    child = (ln - (lp * lp + (ln - lp) ** 2) / ln) + (rn - (rp * rp + (rn - rp) ** 2) / rn)
                    gain = parent - child
                    if gain > best_gain:
                        best_gain, best_f, best_k = gain, f, k
        else:
            G = sum(a[i] for i in idx)
            H = sum(b[i] for i in idx)
            parent = G * G / (H + self.lam)
            for f in feats:
                nb = len(self.binner.thresholds[f]) + 1
                cnt = [0] * nb
                sg = [0.0] * nb
                sh = [0.0] * nb
                for i in idx:
                    k = B[i][f]
                    cnt[k] += 1
                    sg[k] += a[i]
                    sh[k] += b[i]
                ln = 0
                lg = lh = 0.0
                for k in range(nb - 1):
                    ln += cnt[k]
                    lg += sg[k]
                    lh += sh[k]
                    if ln < self.min_leaf or n - ln < self.min_leaf:
                        continue
                    rg, rh = G - lg, H - lh
                    gain = lg * lg / (lh + self.lam) + rg * rg / (rh + self.lam) - parent
                    if gain > best_gain:
                        best_gain, best_f, best_k = gain, f, k
        if best_f < 0:
            return node
        self.importance[best_f] = self.importance.get(best_f, 0.0) + best_gain
        left = [i for i in idx if B[i][best_f] <= best_k]
        right = [i for i in idx if B[i][best_f] > best_k]
        node.feat = best_f
        node.thr = self.binner.thresholds[best_f][best_k]
        node.left = self._grow(B, left, a, b, depth + 1)
        node.right = self._grow(B, right, a, b, depth + 1)
        return node

    def predict(self, x: Vec) -> float:
        return _tree_predict(self.root, x)


# ===================================================================== models
class LinearSVM:
    name = "SVM"
    family = "Linear SVM (hinge loss, SGD)"

    def __init__(self, epochs: int = 18, lam: float = 1e-3, seed: int = 1) -> None:
        self.epochs, self.lam, self.rng = epochs, lam, random.Random(seed)

    def fit(self, X: List[Vec], y: List[int], **_):
        self.scaler = Scaler().fit(X)
        Z = self.scaler.transform(X)
        d = len(Z[0])
        w = [0.0] * d
        bias = 0.0
        order = list(range(len(Z)))
        t = 0
        for _ in range(self.epochs):
            self.rng.shuffle(order)
            for i in order:
                t += 1
                eta = 1.0 / (self.lam * (t + 200))
                yi = 1.0 if y[i] else -1.0
                zi = Z[i]
                margin = yi * (sum(wj * xj for wj, xj in zip(w, zi)) + bias)
                decay = 1 - eta * self.lam
                if margin < 1:
                    w = [wj * decay + eta * yi * xj for wj, xj in zip(w, zi)]
                    bias += eta * yi * 0.1
                else:
                    w = [wj * decay for wj in w]
        self.w, self.b = w, bias
        return self

    def predict_proba(self, X: List[Vec], **_) -> List[float]:
        Z = self.scaler.transform(X)
        return [sigmoid(2.0 * (sum(wj * xj for wj, xj in zip(self.w, z)) + self.b)) for z in Z]


class RandomForest:
    name = "Random Forest"
    family = "Bagged CART trees (Gini)"

    def __init__(self, n_trees: int = 21, max_depth: int = 8, seed: int = 2) -> None:
        self.n_trees, self.max_depth, self.rng = n_trees, max_depth, random.Random(seed)

    def fit(self, X: List[Vec], y: List[int], **_):
        self.binner = Binner().fit(X)
        B = self.binner.transform(X)
        n = len(X)
        mtry = max(2, int(math.sqrt(len(X[0])) + 0.5))
        self.trees = []
        a = [float(v) for v in y]
        for _ in range(self.n_trees):
            idx = [self.rng.randrange(n) for _ in range(n)]
            tree = HistTree(self.binner, self.max_depth, 3, "gini", mtry=mtry, rng=self.rng).fit(B, idx, a, a)
            self.trees.append(tree)
        imp = [0.0] * len(X[0])
        for t in self.trees:
            for f, g in t.importance.items():
                imp[f] += g
        tot = sum(imp) or 1.0
        self.importance = [v / tot for v in imp]
        self.avg_depth = sum(_tree_depth(t.root) for t in self.trees) / len(self.trees)
        self.avg_leaves = sum(_tree_leaves(t.root) for t in self.trees) / len(self.trees)
        return self

    def predict_proba(self, X: List[Vec], **_) -> List[float]:
        k = len(self.trees)
        return [sum(t.predict(x) for t in self.trees) / k for x in X]


class GradientBoosting:
    name = "XGBoost"
    family = "2nd-order gradient boosting (XGBoost-style)"

    def __init__(self, rounds: int = 45, depth: int = 3, eta: float = 0.3, seed: int = 3) -> None:
        self.rounds, self.depth, self.eta, self.rng = rounds, depth, eta, random.Random(seed)

    def fit(self, X: List[Vec], y: List[int], **_):
        self.binner = Binner().fit(X)
        B = self.binner.transform(X)
        n = len(X)
        prior = min(max(sum(y) / n, 1e-3), 1 - 1e-3)
        self.base = math.log(prior / (1 - prior))
        F = [self.base] * n
        idx = list(range(n))
        self.trees = []
        for _ in range(self.rounds):
            p = [sigmoid(f) for f in F]
            g = [pi - yi for pi, yi in zip(p, y)]
            h = [max(pi * (1 - pi), 1e-6) for pi in p]
            tree = HistTree(self.binner, self.depth, 5, "newton", lam=1.0, rng=self.rng).fit(B, idx, g, h)
            self.trees.append(tree)
            F = [f + self.eta * tree.predict(x) for f, x in zip(F, X)]
        return self

    def predict_proba(self, X: List[Vec], **_) -> List[float]:
        return [sigmoid(self.base + self.eta * sum(t.predict(x) for t in self.trees)) for x in X]


class GraphNeuralNet:
    name = "Graph Neural Network"
    family = "SGC 2-hop message passing + MLP"

    def __init__(self, hidden: int = 8, epochs: int = 10, lr: float = 0.05, seed: int = 4) -> None:
        self.hidden, self.epochs, self.lr, self.rng = hidden, epochs, lr, random.Random(seed)

    def set_graph(self, node_ids: List[str], adjacency: Dict[str, List[str]], node_feats: Dict[str, Vec]) -> None:
        """Propagate node features twice with the symmetric normalised adjacency (A+I)."""
        deg = {n: len(adjacency[n]) + 1 for n in node_ids}
        H = {n: list(node_feats[n]) for n in node_ids}
        for _ in range(2):
            new = {}
            for n in node_ids:
                acc = [v / deg[n] for v in H[n]]
                for m in adjacency[n]:
                    c = 1.0 / math.sqrt(deg[n] * deg[m])
                    acc = [a + c * v for a, v in zip(acc, H[m])]
                new[n] = acc
            H = new
        self.emb = H
        self.emb_dim = len(next(iter(H.values())))

    def _inputs(self, Z: List[Vec], src: List[str], dst: List[str]) -> List[Vec]:
        zero = [0.0] * self.emb_dim
        return [z + self.emb.get(s, zero) + self.emb.get(t, zero) for z, s, t in zip(Z, src, dst)]

    def fit(self, X: List[Vec], y: List[int], src=None, dst=None, **_):
        self.scaler = Scaler().fit(X)
        I = self._inputs(self.scaler.transform(X), src, dst)
        d, h = len(I[0]), self.hidden
        r = self.rng
        self.W1 = [[r.gauss(0, 1 / math.sqrt(d)) for _ in range(d)] for _ in range(h)]
        self.b1 = [0.0] * h
        self.w2 = [r.gauss(0, 1 / math.sqrt(h)) for _ in range(h)]
        self.b2 = 0.0
        order = list(range(len(I)))
        for ep in range(self.epochs):
            r.shuffle(order)
            lr = self.lr / (1 + 0.3 * ep)
            for i in order:
                x = I[i]
                pre = [sum(wk * xk for wk, xk in zip(row, x)) + b for row, b in zip(self.W1, self.b1)]
                act = [p if p > 0 else 0.0 for p in pre]
                out = sigmoid(sum(a * w for a, w in zip(act, self.w2)) + self.b2)
                err = out - y[i]
                for j in range(h):
                    if pre[j] > 0:
                        gj = err * self.w2[j] * lr
                        row = self.W1[j]
                        self.W1[j] = [wk - gj * xk for wk, xk in zip(row, x)]
                        self.b1[j] -= gj
                    self.w2[j] -= lr * err * act[j]
                self.b2 -= lr * err
        return self

    def predict_proba(self, X: List[Vec], src=None, dst=None, **_) -> List[float]:
        I = self._inputs(self.scaler.transform(X), src, dst)
        res = []
        for x in I:
            act = [max(0.0, sum(wk * xk for wk, xk in zip(row, x)) + b) for row, b in zip(self.W1, self.b1)]
            res.append(sigmoid(sum(a * w for a, w in zip(act, self.w2)) + self.b2))
        return res


# ===================================================================== suite
def _metrics(y: List[int], p: List[float]) -> dict:
    tp = sum(1 for a, b in zip(y, p) if a == 1 and b >= 0.5)
    tn = sum(1 for a, b in zip(y, p) if a == 0 and b < 0.5)
    fp = sum(1 for a, b in zip(y, p) if a == 0 and b >= 0.5)
    fn = sum(1 for a, b in zip(y, p) if a == 1 and b < 0.5)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    # ROC-AUC via the rank statistic
    pos = [b for a, b in zip(y, p) if a == 1]
    neg_sorted = sorted(b for a, b in zip(y, p) if a == 0)
    auc = 0.0
    if pos and neg_sorted:
        for s in pos:
            lo = bisect.bisect_left(neg_sorted, s)
            hi = bisect.bisect_right(neg_sorted, s)
            auc += lo + 0.5 * (hi - lo)
        auc /= len(pos) * len(neg_sorted)
    return {
        "accuracy": round((tp + tn) / len(y), 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "auc": round(auc, 4),
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
    }


class ModelSuite:
    def __init__(self) -> None:
        self.models = [LinearSVM(), RandomForest(), GradientBoosting(), GraphNeuralNet()]
        self.results: Dict[str, dict] = {}
        self.active = "Random Forest"
        self.trained = False

    def by_name(self, name: str):
        for m in self.models:
            if m.name == name:
                return m
        raise KeyError(name)

    def train(self, data: List[dict], graph_info: dict) -> None:
        split = int(len(data) * 0.75)
        train, test = data[:split], data[split:]
        Xtr = [d["x"] for d in train]
        ytr = [d["label"] for d in train]
        Xte = [d["x"] for d in test]
        yte = [d["label"] for d in test]
        kw_tr = {"src": [d["src"] for d in train], "dst": [d["dst"] for d in train]}
        kw_te = {"src": [d["src"] for d in test], "dst": [d["dst"] for d in test]}
        for m in self.models:
            if isinstance(m, GraphNeuralNet):
                m.set_graph(graph_info["nodes"], graph_info["adjacency"], graph_info["node_feats"])
            t0 = time.perf_counter()
            m.fit(Xtr, ytr, **kw_tr)
            t1 = time.perf_counter()
            p = m.predict_proba(Xte, **kw_te)
            t2 = time.perf_counter()
            res = _metrics(yte, p)
            res.update({
                "name": m.name,
                "family": m.family,
                "train_ms": round((t1 - t0) * 1000, 1),
                "infer_us": round((t2 - t1) / max(len(Xte), 1) * 1e6, 1),
            })
            self.results[m.name] = res
        self.active = max(self.results.values(), key=lambda r: (r["f1"], r["auc"]))["name"]
        self.n_train, self.n_test = len(train), len(test)
        # Per-feature median of the training set: the "uninformative" value used as
        # the reference point when attributing a score to individual features.
        self.baseline = [
            sorted(col)[len(col) // 2]
            for col in ([row[i] for row in Xtr] for i in range(len(FEATURES)))
        ]
        self.trained = True

    def predict(self, flows: List[dict], model: Optional[str] = None) -> List[float]:
        if not flows:
            return []
        m = self.by_name(model or self.active)
        return m.predict_proba([f["x"] for f in flows], src=[f["src"] for f in flows], dst=[f["dst"] for f in flows])

    def explain(self, flow: dict, model: Optional[str] = None, top: int = 3) -> dict:
        """Why did this flow get this score?

        Occlusion attribution: replace one feature at a time with its training
        median and measure how far the score moves. A large positive drop means
        that feature was the evidence pushing the flow toward "malicious".
        Model-agnostic, so it works identically for the SVM, forest, boosting
        and GNN -- which is the point: the explanation is of the decision, not
        of one particular algorithm.
        """
        name = model or self.active
        m = self.by_name(name)
        base = getattr(self, "baseline", None)
        x = flow["x"]
        kw = {"src": [flow["src"]], "dst": [flow["dst"]]}
        full = m.predict_proba([x], **kw)[0]
        if not base:
            return {"model": name, "score": round(full, 3), "contributions": []}
        variants = []
        for i in range(len(FEATURES)):
            xi = list(x)
            xi[i] = base[i]
            variants.append(xi)
        occluded = m.predict_proba(
            variants, src=[flow["src"]] * len(variants), dst=[flow["dst"]] * len(variants)
        )
        contrib = []
        for i, name_f in enumerate(FEATURES):
            delta = full - occluded[i]
            contrib.append({
                "feature": name_f,
                "group": next(g for g, fs in FEATURE_GROUPS.items() if name_f in fs),
                "value": x[i],
                "typical": round(base[i], 3),
                "contribution": round(delta, 4),
                "direction": "raises" if delta > 0 else "lowers",
            })
        contrib.sort(key=lambda d: -abs(d["contribution"]))
        return {
            "model": name,
            "score": round(full, 3),
            "verdict": "malicious" if full >= 0.5 else "benign",
            "contributions": contrib[:top],
            "all": contrib,
        }

    def to_dict(self) -> dict:
        rf = self.by_name("Random Forest")
        imp = getattr(rf, "importance", [0.0] * len(FEATURES))
        return {
            "active": self.active,
            "results": [self.results[m.name] for m in self.models if m.name in self.results],
            "feature_importance": sorted(
                [{"feature": f, "value": round(v, 4)} for f, v in zip(FEATURES, imp)],
                key=lambda d: -d["value"],
            ),
            "n_train": getattr(self, "n_train", 0),
            "n_test": getattr(self, "n_test", 0),
            "rf_avg_depth": round(getattr(rf, "avg_depth", 0.0), 2),
            "rf_avg_leaves": round(getattr(rf, "avg_leaves", 0.0), 1),
            "rf_trees": len(getattr(rf, "trees", [])),
        }
