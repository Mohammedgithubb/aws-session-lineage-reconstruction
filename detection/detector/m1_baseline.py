"""M1 Behaviour baseline: rarity score + Isolation Forest + session drift."""
import math
from collections import defaultdict, deque
import numpy as np

WEIGHTS = {"net": 2.0, "uaf": 2.0, "region": 1.0}
LABEL = {"net": "network", "uaf": "tool", "region": "Region"}

class Baseline:
    name = "M1"

    def __init__(self, cfg):
        self.warmup = cfg["warmup_events"]
        self.counts = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        self.N = defaultdict(int)
        self.R_hist = defaultdict(lambda: deque(maxlen=2000))
        self.fp = defaultdict(set)                       # session fingerprints
        self.recent = defaultdict(lambda: deque(maxlen=200))   # (t, source, error) per identity
        self.iforest = None
        self.train_X = []

    # Part A: rarity
    def rarity(self, ev):
        u, R, parts = ev["identity"], 0.0, []
        for f, w in WEIGHTS.items():
            vals = self.counts[u][f]
            K = max(len(vals), 1)
            p = (vals.get(ev[f], 0) + 1) / (self.N[u] + K)        # Laplace smoothing, alpha = 1
            bits = -math.log2(p)
            R += w * bits
            if self.N[u] >= self.warmup:
                if vals.get(ev[f], 0) == 0:
                    parts.append(f"{LABEL[f]} {ev[f]} never seen for {u}")
                elif p < 0.1:
                    parts.append(f"{LABEL[f]} {ev[f]} is rare for {u} ({vals[ev[f]]} of {self.N[u]} events)")
        return R, parts

    def _vector(self, ev, R):
        u, t = ev["identity"], ev["t"]
        rec = self.recent[u]
        last60 = sum(1 for x in rec if t - x[0] <= 60) + 1
        services = len({x[1] for x in rec if t - x[0] <= 600} | {ev["source"]})
        last20 = list(rec)[-19:] + [(t, ev["source"], ev["error"])]
        err = sum(1 for x in last20 if x[2]) / len(last20)
        h = (t % 86400) / 3600.0
        return [math.sin(2 * math.pi * h / 24), math.cos(2 * math.pi * h / 24), last60, services, err, R]

    def learn(self, ev, R=None):
        u = ev["identity"]
        if R is None:
            R, _ = self.rarity(ev)
        if self.N[u] >= self.warmup:
            self.R_hist[u].append(R)
            if len(self.train_X) < 20000:
                self.train_X.append(self._vector(ev, R))
        for f in WEIGHTS:
            self.counts[u][f][ev[f]] += 1
        self.N[u] += 1
        self.recent[u].append((ev["t"], ev["source"], ev["error"]))
        if ev["key"]:
            self.fp[ev["key"]].add((ev["net"], ev["uaf"]))

    def finalize(self):
        """Fit Isolation Forest on the normal-period vectors (needs scikit-learn)."""
        if len(self.train_X) >= 64:
            from sklearn.ensemble import IsolationForest
            self.iforest = IsolationForest(n_estimators=100, max_samples=min(256, len(self.train_X)), random_state=7)
            self.iforest.fit(np.array(self.train_X))

    def score(self, ev):
        u = ev["identity"]
        R, reasons = self.rarity(ev)
        z_r = 0.0
        if self.N[u] >= self.warmup:
            hist = self.R_hist[u]
            r99 = max(float(np.percentile(hist, 99)), 1.0) if len(hist) >= 20 else 6.0
            z_r = min(R / r99, 1.0)
        s_prime = 0.0
        if self.iforest is not None and self.N[u] >= self.warmup:
            s = float(-self.iforest.score_samples(np.array([self._vector(ev, R)]))[0])
            s_prime = max(0.0, (s - 0.5) / 0.5)
            if s_prime > 0.3:
                reasons.append(f"Isolation Forest score {s:.2f} (unusual activity pattern)")
        D = 0
        k = ev["key"] or ""
        fp = self.fp.get(k) if k.startswith("ASIA") else None     # drift is checked for temporary sessions
        if fp and (ev["net"], ev["uaf"]) not in fp:
            D = 1
            reasons.append(f"same key now used from {ev['net']} with {ev['uaf']} (session drift)")
        z = max(z_r, s_prime, 0.8 * D)
        return {"z": z, "R": round(R, 2), "reasons": reasons if z > 0.2 else []}, R
