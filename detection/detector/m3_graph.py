"""M3 Streaming graph anomaly: MIDAS-R with Count-Min Sketch, new-edge and chain-depth checks."""
import hashlib, math
from collections import defaultdict
import numpy as np

class CMS:
    """Count-Min Sketch: d rows x w columns of counters."""
    def __init__(self, d=4, w=1024):
        self.d, self.w = d, w
        self.t = np.zeros((d, w))
    def _idx(self, item):
        h = hashlib.blake2b(item.encode(), digest_size=16).digest()
        return [int.from_bytes(h[i * 4:(i + 1) * 4], "little") % self.w for i in range(self.d)]
    def add(self, item, n=1.0):
        for i, j in enumerate(self._idx(item)):
            self.t[i, j] += n
    def get(self, item):
        return min(self.t[i, j] for i, j in enumerate(self._idx(item)))
    def scale(self, f):
        self.t *= f

def chi2(a, s, t):
    if s <= 0 or t <= 1:
        return 0.0
    return (a - s / t) ** 2 * t * t / (s * (t - 1))

class Graph:
    name = "M3"

    def __init__(self, cfg, gamma=0.5):
        self.tick_s = cfg["tick_seconds"]
        self.priv = set(cfg["privileged"])
        self.gamma = gamma
        self.cur, self.tot = CMS(), CMS()
        self.t0, self.tick = None, 0
        self.baseline = set()
        self.scores = []
        self.tau = 20.0
        self.depth, self.root = {}, {}
        self.usual_depth = defaultdict(int)

    def edges(self, ev):
        out = []
        if ev["assumed_role"]:
            out.append((ev["identity"], ev["assumed_role"].split("/")[-1]))
        for r in ev["resources"]:
            if r.startswith("arn:aws:s3:::"):
                out.append((ev["identity"], "s3:" + r[len("arn:aws:s3:::"):].split("/")[0]))
        return list(dict.fromkeys(out))       # an object and its bucket give the same edge once

    def _advance(self, t):
        tk = int(t // self.tick_s)
        if self.t0 is None:
            self.t0 = tk
        tk = tk - self.t0 + 1
        if tk > self.tick:
            self.cur.scale(self.gamma ** (tk - self.tick))
            self.tick = tk

    def _update_depth(self, ev):
        k = ev["key"]
        if k and k not in self.depth:
            self.depth[k] = 0
            self.root[k] = ev["identity"]
        if ev["issued_key"]:
            d = self.depth.get(k, 0) + 1 if k else 1
            self.depth[ev["issued_key"]] = d
            self.root[ev["issued_key"]] = self.root.get(k, ev["identity"])

    def _midas(self, a, b):
        e, ka, kb = f"e|{a}|{b}", f"n|{a}", f"n|{b}"
        for x in (e, ka, kb):
            self.cur.add(x); self.tot.add(x)
        t = self.tick
        return max(chi2(self.cur.get(e), self.tot.get(e), t), chi2(self.cur.get(ka), self.tot.get(ka), t), chi2(self.cur.get(kb), self.tot.get(kb), t))

    def learn(self, ev):
        self._advance(ev["t"])
        self._update_depth(ev)
        for a, b in self.edges(ev):
            s = self._midas(a, b)
            if self.tick > 60 and (a, b) in self.baseline:   # tau describes known edges, after the first hour
                self.scores.append(s)
            self.baseline.add((a, b))
        if ev["key"] in self.depth:
            r = self.root[ev["key"]]
            self.usual_depth[r] = max(self.usual_depth[r], self.depth[ev["key"]])

    def finalize(self):
        if len(self.scores) >= 50:
            self.tau = max(float(np.percentile(self.scores, 99.9)), 5.0)

    def score(self, ev):
        self._advance(ev["t"])
        self._update_depth(ev)
        z, reasons = 0.0, []
        for a, b in self.edges(ev):
            s = self._midas(a, b)
            # 0 at the normal 99.9th percentile (tau), 1 at ten times tau, on a log scale
            zm = min(max((math.log1p(s) - math.log1p(self.tau)) / (math.log1p(10 * self.tau) - math.log1p(self.tau)), 0.0), 1.0)
            novel = (a, b) not in self.baseline
            priv = b in self.priv or b.startswith("s3:") and any(p in b for p in self.priv)
            zz = max(zm, 0.7 * novel * priv)
            if zm > 0.3:
                reasons.append(f"link {a} -> {b} arriving much faster than usual (MIDAS {s:.0f})")
            if novel and priv:
                reasons.append(f"never-seen link {a} -> {b} (privileged)")
            elif novel:
                reasons.append(f"never-seen link {a} -> {b}")
            z = max(z, zz)
        k = ev["key"]
        if k in self.depth:
            r = self.root[k]
            if self.depth[k] > self.usual_depth.get(r, 0) and self.depth[k] >= 2:
                z = max(z, 0.3)
                reasons.append(f"role chain depth {self.depth[k]} from {r} (usual {self.usual_depth.get(r, 0)})")
        return {"z": z, "reasons": reasons if z > 0.2 else []}
