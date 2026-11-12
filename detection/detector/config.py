"""Settings. Values come from config.json (written by `python -m detector setup`)
and can be overridden with environment variables."""
import json, os, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)
CONFIG_FILE = ROOT / "config.json"

DEFAULTS = {
    "region": "us-east-1",
    "queue_url": "",
    "trail_bucket": "",
    "test_bucket": "",
    "evidence_bucket": "",
    "decoy_key_ids": [],
    "decoy_arns": [],
    "privileged": ["pw25-Role-C"],
    # method settings (start values from the methods document)
    "warmup_events": 30,          # events an identity needs before M1/M2 score it
    "delta_seconds": 900,         # S1 delivery allowance (15 min); lower for demos
    "tick_seconds": 60,           # MIDAS tick
    "reliability": {"M1": 0.80, "M2": 0.85, "M3": 0.85, "M4": 1.00, "M5": 0.90},
    "cmax": 0.6,
    "thresholds": {"watch": 0.30, "suspicious": 0.60, "compromised": 0.90},
    "seal": True,                 # copy evidence to the Object Lock bucket at Suspicious
    "respond": False,             # revoke role sessions at Compromised (off by default)
}

def load():
    cfg = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        cfg.update(json.loads(CONFIG_FILE.read_text()))
    for k in ("queue_url", "region", "trail_bucket", "test_bucket", "evidence_bucket"):
        if os.environ.get("PW25_" + k.upper()):
            cfg[k] = os.environ["PW25_" + k.upper()]
    if os.environ.get("PW25_DELTA_SECONDS"):
        cfg["delta_seconds"] = int(os.environ["PW25_DELTA_SECONDS"])
    if os.environ.get("PW25_RESPOND") == "1":
        cfg["respond"] = True
    return cfg
