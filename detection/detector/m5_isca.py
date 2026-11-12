"""M5 ISCA-DS: session ledger and checks for records hidden while logging stays on.
S1 orphan session is live here. S2 (Event History vs delivered trail, Wald test) and
S3 (digest chain) run as periodic jobs in m5_jobs.py."""
import math

class Ledger:
    name = "M5"

    def __init__(self, cfg):
        self.delta = cfg["delta_seconds"]
        self.issued = {}          # key -> time of issuing record
        self.window_start = None  # start of the log window we can see
        self.flagged = set()

    def observe(self, ev):
        if self.window_start is None and ev["t"]:
            self.window_start = ev["t"]
        if ev["issued_key"]:
            self.issued[ev["issued_key"]] = ev["t"]

    def score(self, ev, now=None):
        k = ev["key"]
        if not k or not k.startswith("ASIA") or ev["service_event"] or not ev["created"]:
            return {"S1": 0, "m_S": 0.0, "reasons": []}
        now = now or ev["t"]
        if k in self.issued:
            return {"S1": 0, "m_S": 0.0, "reasons": []}
        if self.window_start <= ev["created"] <= now - self.delta:
            self.flagged.add(k)
            age = (now - ev["created"]) / 60
            return {"S1": 1, "m_S": 0.7, "reasons": [f"orphan session: key in use, created {age:.0f} min ago, but its AssumeRole record never arrived"]}
        return {"S1": 0, "m_S": 0.0, "reasons": []}

class SPRT:
    """S2: Wald sequential test per identity on 'Event History record missing from trail'."""
    def __init__(self, p0=0.001, p1=0.2, alpha=0.01, beta=0.05):
        self.up = math.log((1 - beta) / alpha)
        self.low = math.log(beta / (1 - alpha))
        self.inc = math.log(p1 / p0)
        self.dec = math.log((1 - p1) / (1 - p0))
        self.L, self.n, self.miss = {}, {}, {}

    def add(self, u, missing):
        L = self.L.get(u, 0.0) + (self.inc if missing else self.dec)
        self.n[u] = self.n.get(u, 0) + 1
        self.miss[u] = self.miss.get(u, 0) + int(missing)
        if L <= self.low:
            L = 0.0                   # decided Normal: restart the test
        self.L[u] = L
        return "suppressed" if L >= self.up else "watching"

    def coverage(self, u):
        n = self.n.get(u, 0)
        return 1 - self.miss.get(u, 0) / n if n else 1.0
