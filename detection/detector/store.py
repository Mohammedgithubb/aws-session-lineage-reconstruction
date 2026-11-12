"""SQLite store for events and alerts (one file: data/detector.db)."""
import json, sqlite3, threading
from .config import DATA

class Store:
    def __init__(self, path=None):
        self.db = sqlite3.connect(path or DATA / "detector.db", check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, t REAL, key TEXT, identity TEXT, token TEXT, json TEXT);
            CREATE TABLE IF NOT EXISTS alerts(t REAL, key TEXT, identity TEXT, state TEXT, bel REAL, json TEXT);
            CREATE INDEX IF NOT EXISTS ev_key ON events(key);""")

    def reset(self):
        with self.lock:
            self.db.executescript("DELETE FROM events; DELETE FROM alerts;")
            self.db.commit()

    def add_event(self, ev):
        with self.lock:
            self.db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?)", (ev["id"], ev["t"], ev["key"], ev["identity"], ev["token"], json.dumps(ev)))
            self.db.commit()

    def add_alert(self, a):
        with self.lock:
            self.db.execute("INSERT INTO alerts VALUES(?,?,?,?,?,?)", (a["t"], a["key"], a["identity"], a["state"], a["bel"], json.dumps(a)))
            self.db.commit()

    def session_events(self, key, limit=500):
        with self.lock:
            rows = self.db.execute("SELECT json FROM events WHERE key=? ORDER BY t LIMIT ?", (key, limit)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def alerts(self):
        with self.lock:
            rows = self.db.execute("SELECT json FROM alerts ORDER BY t").fetchall()
        return [json.loads(r[0]) for r in rows]
