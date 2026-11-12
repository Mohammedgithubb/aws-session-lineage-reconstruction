"""Detection engine: runs M1-M5 on each event, keeps per-session evidence, fuses, acts."""
import pickle, threading, time
from collections import deque
from .config import DATA
from .m1_baseline import Baseline
from .m2_sequence import Sequence
from .m3_graph import Graph
from .m4_honeytoken import Honeytoken
from .m5_isca import Ledger
from .fusion import combine, state_of
from .actions import Actions
from .store import Store

BASELINE_FILE = DATA / "baseline.pkl"
METHODS = ["M1", "M2", "M3", "M4", "M5"]

class Engine:
    def __init__(self, cfg, mode="detect", live=True, store=None):
        self.cfg, self.mode, self.live = cfg, mode, live
        self.lock = threading.RLock()
        self.m1, self.m2, self.m3 = Baseline(cfg), Sequence(cfg), Graph(cfg)
        self.m4, self.m5 = Honeytoken(cfg), Ledger(cfg)
        self.store = store or Store()
        self.actions = Actions(cfg, live)
        self.sessions = {}
        self.recent = deque(maxlen=60)
        self.n_events = 0
        self.n_learned = 0
        self.s2_done, self.s2_verdicts = set(), {}
        self.jobs = None
        self.started = time.time()

    # ---------- baseline persistence ----------
    def save_baseline(self):
        with self.lock:
            m1, m2, m3 = self.m1, self.m2, self.m3
            blob = {"m1": (dict_deep(m1.counts), dict(m1.N), {k: list(v) for k, v in m1.R_hist.items()}, m1.train_X, m1.iforest),
                    "m2": (dict(m2.c3), dict(m2.c2), m2.c1, m2.V, dict(m2.n_id), (m2.w_n, m2.w_mean, m2.w_m2), dict(m2.err_learned), m2.span),
                    "m3": (m3.baseline, m3.scores, m3.tau, dict(m3.usual_depth)),
                    "n_learned": self.n_learned}
            BASELINE_FILE.write_bytes(pickle.dumps(blob))

    def load_baseline(self):
        if not BASELINE_FILE.exists():
            return False
        b = pickle.loads(BASELINE_FILE.read_bytes())
        c, N, R, X, iforest = b["m1"]
        for u, fs in c.items():
            for f, vals in fs.items():
                for v, n in vals.items():
                    self.m1.counts[u][f][v] = n
        self.m1.N.update(N)
        for u, h in R.items():
            self.m1.R_hist[u].extend(h)
        self.m1.train_X, self.m1.iforest = X, iforest
        c3, c2, c1, V, n_id, w, errl, span = b["m2"]
        for k, v in c3.items(): self.m2.c3[k].update(v)
        for k, v in c2.items(): self.m2.c2[k].update(v)
        self.m2.c1.update(c1); self.m2.V |= V; self.m2.n_id.update(n_id)
        self.m2.w_n, self.m2.w_mean, self.m2.w_m2 = w
        self.m2.err_learned.update(errl); self.m2.span.update(span)
        self.m3.baseline, self.m3.scores, self.m3.tau, ud = b["m3"]
        self.m3.usual_depth.update(ud)
        self.n_learned = b.get("n_learned", 0)
        return True

    def finalize_learning(self):
        self.m1.finalize(); self.m3.finalize()

    # ---------- per-event processing ----------
    def _session(self, ev):
        k = ev["key"]
        s = self.sessions.get(k)
        if s is None:
            s = self.sessions[k] = {"key": k, "identity": ev["identity"], "issuer": ev["issuer"] or ev["arn"],
                                    "first": ev["t"], "last": ev["t"], "n": 0, "net": ev["net"], "uaf": ev["uaf"],
                                    "mass": {m: 0.0 for m in METHODS}, "z": {m: 0.0 for m in METHODS},
                                    "reasons": {m: [] for m in METHODS}, "bel": 0.0, "level": 0, "state": "Normal",
                                    "history": [], "sealed": None, "response": None, "m_S": 0.0, "methods_fired": []}
        return s

    def process(self, ev):
        if not ev["t"]:
            return
        with self.lock:
            self.n_events += 1
            self.store.add_event(ev)
            self.recent.appendleft({k: ev[k] for k in ("time", "identity", "token", "net", "uaf", "error", "key")})
            self.m5.observe(ev)
            if ev["service_event"] or not ev["key"]:
                return
            if self.mode == "learn":
                R, _ = self.m1.rarity(ev)
                self.m1.learn(ev, R); self.m2.learn(ev); self.m3.learn(ev)
                self.n_learned += 1
                return
            s = self._session(ev)
            s["last"], s["n"] = ev["t"], s["n"] + 1
            r1, R = self.m1.score(ev)
            r2 = self.m2.score(ev)
            r3 = self.m3.score(ev)
            r4 = self.m4.score(ev)
            r5 = self.m5.score(ev)
            cm = self.cfg["cmax"]
            new = {"M1": (r1["z"], cm * r1["z"], r1["reasons"]), "M2": (r2["z"], cm * r2["z"], r2["reasons"]),
                   "M3": (r3["z"], cm * r3["z"], r3["reasons"]), "M4": (r4["trip"], r4["m"], r4["reasons"])}
            if r5["m_S"] > 0:
                s["m_S"] = max(s["m_S"], r5["m_S"])
            new["M5"] = (s["m_S"], 0.5 * s["m_S"], r5["reasons"])
            for m, (z, mass, reasons) in new.items():
                if mass > s["mass"][m]:
                    s["mass"][m], s["z"][m] = round(mass, 4), round(z, 3)
                    s["reasons"][m] = reasons or s["reasons"][m]
            self._fuse(s, ev["t"], trip=r4["trip"] == 1)
            # learn only from sessions that still look normal
            if s["level"] < 2:
                self.m1.learn(ev, R); self.m2.learn(ev); self.m3.learn(ev)
            else:
                self.m2.after_score(ev)
                if s["sealed"]:
                    self.actions.seal(s["key"], [ev], f"event-{ev['id']}")

    def _fuse(self, s, t, trip=False, note=None):
        bel = combine(s["mass"], self.cfg["reliability"])
        level, name = state_of(bel, self.cfg["thresholds"], trip or s["mass"]["M4"] > 0)
        s["bel"] = round(bel, 4)
        s["methods_fired"] = [m for m in METHODS if s["mass"][m] >= 0.1]
        s["history"].append((t, s["bel"]))
        if level > s["level"]:
            s["level"], s["state"] = level, name
            alert = {"t": t, "seen": time.time() if self.live else t, "key": s["key"], "identity": s["identity"], "state": name, "bel": s["bel"],
                     "methods": s["methods_fired"], "why": [r for m in METHODS for r in s["reasons"][m]][:6]}
            if level >= 2 and not s["sealed"]:
                s["sealed"] = self.actions.seal(s["key"], self.store.session_events(s["key"]), "initial")
                alert["sealed"] = s["sealed"]
            if level >= 3 and not s["response"]:
                s["response"] = self.actions.respond(s["issuer"])
                alert["response"] = s["response"]
            self.store.add_alert(alert)

    # ---------- signals from periodic M5 jobs ----------
    def raise_suppression(self, identity, m_s, reason, records=None):
        with self.lock:
            for s in self.sessions.values():
                if s["identity"] == identity and s["m_S"] < m_s:
                    s["m_S"] = m_s
                    s["mass"]["M5"] = max(s["mass"]["M5"], 0.5 * m_s)
                    s["reasons"]["M5"] = s["reasons"]["M5"] + [reason]
                    self._fuse(s, time.time())

    def raise_chainbreak(self, lines):
        with self.lock:
            for s in self.sessions.values():
                if time.time() - s["last"] < 6 * 3600 and s["m_S"] < 0.8:
                    s["m_S"] = 0.8
                    s["mass"]["M5"] = max(s["mass"]["M5"], 0.4)
                    s["reasons"]["M5"] = s["reasons"]["M5"] + ["S3: digest chain check failed: " + lines[0][:120]]
                    self._fuse(s, time.time())

    # ---------- views for the dashboard ----------
    def summary(self):
        with self.lock:
            ss = sorted(self.sessions.values(), key=lambda s: (-s["level"], -s["bel"], -s["last"]))
            counts = {n: sum(1 for s in self.sessions.values() if s["state"] == n) for n in ("Normal", "Watch", "Suspicious", "Compromised")}
            return {"mode": self.mode, "live": self.live, "events": self.n_events, "learned": self.n_learned,
                    "sessions": len(self.sessions), "counts": counts, "uptime": int(time.time() - self.started),
                    "jobs": self.jobs.status if self.jobs else None,
                    "top": [slim(s) for s in ss[:40]], "alerts": list(reversed(self.store.alerts()))[:50],
                    "recent": list(self.recent)[:25]}

    def session(self, key):
        with self.lock:
            s = self.sessions.get(key)
            if not s:
                return None
            d = dict(s)
            d["events"] = self.store.session_events(key)
            return d

def slim(s):
    return {k: s[k] for k in ("key", "identity", "state", "level", "bel", "first", "last", "n", "methods_fired", "net", "uaf")}

def dict_deep(d):
    return {k: dict_deep(v) if isinstance(v, dict) else v for k, v in d.items()}
