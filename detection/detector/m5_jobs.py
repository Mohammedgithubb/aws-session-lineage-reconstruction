"""M5 periodic jobs for live mode.
S2: compare Event History (LookupEvents) with the delivered trail in S3, per identity, Wald test.
S3: run AWS's digest-chain validation (`aws cloudtrail validate-logs`) every hour."""
import gzip, json, shutil, subprocess, threading, time, datetime as dt
import boto3
from .m5_isca import SPRT

class Jobs:
    def __init__(self, engine, cfg):
        self.e, self.cfg = engine, cfg
        self.sprt = SPRT()
        self.seen_trail, self.checked = set(), set()
        self.status = {"S2": "not started", "S3": "not started", "coverage": {}, "global_coverage": 1.0}
        self.s3 = boto3.client("s3", region_name=cfg["region"])
        self.ct = boto3.client("cloudtrail", region_name=cfg["region"])
        self.account = boto3.client("sts", region_name=cfg["region"]).get_caller_identity()["Account"]

    def start(self):
        threading.Thread(target=self._loop_s2, daemon=True).start()
        threading.Thread(target=self._loop_s3, daemon=True).start()

    # ----- S2 -----
    def _read_trail(self, since):
        prefix = f"AWSLogs/{self.account}/CloudTrail/{self.cfg['region']}/"
        days = {since.strftime("%Y/%m/%d"), dt.datetime.now(dt.timezone.utc).strftime("%Y/%m/%d")}
        for d in days:
            pages = self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.cfg["trail_bucket"], Prefix=prefix + d)
            for page in pages:
                for o in page.get("Contents", []):
                    if o["Key"] in self.checked:
                        continue
                    body = self.s3.get_object(Bucket=self.cfg["trail_bucket"], Key=o["Key"])["Body"].read()
                    for r in json.loads(gzip.decompress(body)).get("Records", []):
                        self.seen_trail.add(r.get("eventID"))
                    self.checked.add(o["Key"])

    def s2_once(self):
        now = dt.datetime.now(dt.timezone.utc)
        end = now - dt.timedelta(seconds=self.cfg["delta_seconds"])
        start = end - dt.timedelta(minutes=30)
        self._read_trail(start)
        per_id, missing_ids = {}, {}
        for page in self.ct.get_paginator("lookup_events").paginate(StartTime=start, EndTime=end):
            for ev in page["Events"]:
                if ev["EventId"] in self.e.s2_done:
                    continue
                self.e.s2_done.add(ev["EventId"])
                r = json.loads(ev["CloudTrailEvent"])
                ui = r.get("userIdentity") or {}
                if ui.get("type") == "AWSService":
                    continue
                u = ((ui.get("sessionContext") or {}).get("sessionIssuer") or {}).get("userName") or ui.get("userName") or ui.get("type")
                miss = ev["EventId"] not in self.seen_trail
                verdict = self.sprt.add(u, miss)
                per_id.setdefault(u, [0, 0])
                per_id[u][0] += 1; per_id[u][1] += int(miss)
                if miss:
                    missing_ids.setdefault(u, []).append(r)
                if verdict == "suppressed":
                    self.e.s2_verdicts[u] = True
            time.sleep(0.6)   # LookupEvents allows about 2 calls per second
        tot = sum(v[0] for v in per_id.values()); mis = sum(v[1] for v in per_id.values())
        g = 1 - mis / tot if tot else 1.0
        self.status["global_coverage"] = round(g, 3)
        self.status["coverage"] = {u: round(self.sprt.coverage(u), 3) for u in self.sprt.n}
        for u, flag in list(self.e.s2_verdicts.items()):
            if flag and g >= 0.95:          # identity-selective: only this identity is losing records
                self.e.raise_suppression(u, 0.6, f"S2: Event History has records of {u} missing from the trail (coverage {self.sprt.coverage(u):.2f}, account {g:.2f})", missing_ids.get(u, []))
        self.status["S2"] = f"checked {tot} records at {now:%H:%M:%S} UTC"

    def _loop_s2(self):
        while True:
            try:
                self.s2_once()
            except Exception as ex:
                self.status["S2"] = f"error: {ex}"
            time.sleep(180)

    # ----- S3 -----
    def s3_once(self):
        if not shutil.which("aws"):
            self.status["S3"] = "AWS CLI not installed, digest check skipped"
            return
        start = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
        arn = f"arn:aws:cloudtrail:{self.cfg['region']}:{self.account}:trail/pw25-trail"
        out = subprocess.run(["aws", "cloudtrail", "validate-logs", "--trail-arn", arn, "--start-time", start, "--region", self.cfg["region"]], capture_output=True, text=True, timeout=600)
        text = out.stdout + out.stderr
        bad = [l for l in text.splitlines() if "INVALID" in l.upper() or "not found" in l.lower()]
        if bad:
            self.e.raise_chainbreak(bad[:5])
            self.status["S3"] = f"CHAIN BREAK: {len(bad)} problem(s)"
        else:
            self.status["S3"] = "digest chain valid at " + dt.datetime.now(dt.timezone.utc).strftime("%H:%M UTC")

    def _loop_s3(self):
        while True:
            try:
                self.s3_once()
            except Exception as ex:
                self.status["S3"] = f"error: {ex}"
            time.sleep(3600)
