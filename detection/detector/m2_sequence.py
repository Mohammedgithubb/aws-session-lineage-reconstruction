"""M2 API sequence: Markov next-call model, top-5 rule, Poisson error-burst test."""
import math
from collections import defaultdict, deque, Counter
from scipy.stats import poisson

ALPHA, WINDOW, TOP_G = 0.1, 10, 5

class Sequence:
    name = "M2"

    def __init__(self, cfg):
        self.warmup = cfg["warmup_events"]
        self.c3 = defaultdict(Counter)       # (a, b) -> Counter(next)
        self.c2 = defaultdict(Counter)       # a -> Counter(next)
        self.c1 = Counter()
        self.V = set()
        self.last = defaultdict(lambda: deque(maxlen=2))       # session -> last two tokens
        self.win = defaultdict(lambda: deque(maxlen=WINDOW))   # session -> surprises
        self.n_id = defaultdict(int)
        # Welford for window surprise on normal data
        self.w_n, self.w_mean, self.w_m2 = 0, 0.0, 0.0
        # error rate per identity
        self.err_times = defaultdict(lambda: deque(maxlen=500))
        self.err_learned = defaultdict(int)
        self.span = {}

    def prob(self, ctx, tok):
        V = max(len(self.V), 1)
        if len(ctx) == 2 and sum(self.c3[tuple(ctx)].values()) > 0:
            c = self.c3[tuple(ctx)]
            return (c[tok] + ALPHA) / (sum(c.values()) + ALPHA * V), c
        if len(ctx) >= 1 and sum(self.c2[ctx[-1]].values()) > 0:
            c = self.c2[ctx[-1]]
            return (c[tok] + ALPHA) / (sum(c.values()) + ALPHA * V), None
        N = sum(self.c1.values())
        return (self.c1[tok] + ALPHA) / (N + ALPHA * V), None

    def learn(self, ev):
        k, tok, u = ev["key"] or ev["identity"], ev["token"], ev["identity"]
        ctx = list(self.last[k])
        p, _ = self.prob(ctx, tok)
        self.win[k].append(-math.log2(p))
        if len(self.win[k]) >= 3:
            s = sum(self.win[k]) / len(self.win[k])
            self.w_n += 1
            d = s - self.w_mean
            self.w_mean += d / self.w_n
            self.w_m2 += d * (s - self.w_mean)
        if len(ctx) == 2:
            self.c3[tuple(ctx)][tok] += 1
        if ctx:
            self.c2[ctx[-1]][tok] += 1
        self.c1[tok] += 1
        self.V.add(tok)
        self.last[k].append(tok)
        self.n_id[u] += 1
        a, b = self.span.get(u, (ev["t"], ev["t"]))
        self.span[u] = (min(a, ev["t"]), max(b, ev["t"]))
        if ev["error"]:
            self.err_learned[u] += 1
            self.err_times[u].append(ev["t"])

    def lam(self, u):
        a, b = self.span.get(u, (0, 0))
        windows = max((b - a) / 300.0, 1.0)
        return max(self.err_learned[u] / windows, 0.1)

    def score(self, ev):
        k, tok, u = ev["key"] or ev["identity"], ev["token"], ev["identity"]
        ctx = list(self.last[k])
        p, c = self.prob(ctx, tok)
        reasons = []
        surprises = list(self.win[k]) + [-math.log2(p)]
        surprises = surprises[-WINDOW:]
        S = sum(surprises) / len(surprises)
        z_seq = 0.0
        sigma = math.sqrt(self.w_m2 / (self.w_n - 1)) if self.w_n > 1 else 0.0
        if self.n_id[u] >= self.warmup and sigma > 0 and len(surprises) >= 3:
            z_seq = min(max((S - self.w_mean) / (3 * sigma), 0.0), 1.0)
            if z_seq > 0.3:
                reasons.append(f"unusual call order (surprise {S:.1f} bits vs normal {self.w_mean:.1f})")
        miss = 0
        if c is not None:
            top = [t for t, _ in c.most_common(TOP_G)]
            if tok not in top:
                miss = 1
                reasons.append(f"{tok} not in top-{TOP_G} expected next calls")
        z_err = 0.0
        if ev["error"]:
            x = sum(1 for t in self.err_times[u] if ev["t"] - t <= 300) + 1
            pb = float(poisson.sf(x - 1, self.lam(u)))
            z_err = min(-math.log10(max(pb, 1e-300)) / 6.0, 1.0)
            if z_err > 0.3:
                reasons.append(f"{x} errors in 5 min (normal about {self.lam(u):.1f}), chance {pb:.1e}")
        z = max(z_seq, z_err, 0.5 * miss)
        return {"z": z, "z_seq": round(z_seq, 3), "z_err": round(z_err, 3), "miss": miss, "reasons": reasons if z > 0.2 else []}

    def after_score(self, ev):
        """Keep session context moving even when we do not learn from the event."""
        k = ev["key"] or ev["identity"]
        p, _ = self.prob(list(self.last[k]), ev["token"])
        self.win[k].append(-math.log2(p))
        self.last[k].append(ev["token"])
        if ev["error"]:
            self.err_times[ev["identity"]].append(ev["t"])
