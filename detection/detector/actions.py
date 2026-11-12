"""Live evidence sealing (S3 Object Lock) and automated response (revoke role sessions)."""
import json, datetime as dt
from .config import DATA

class Actions:
    def __init__(self, cfg, live):
        self.cfg, self.live = cfg, live
        self.s3 = self.iam = None
        if live:
            import boto3
            self.s3 = boto3.client("s3", region_name=cfg["region"])
            self.iam = boto3.client("iam")

    def seal(self, key, events, tag):
        body = json.dumps({"session": key, "sealed_at": dt.datetime.now(dt.timezone.utc).isoformat(), "events": events}, default=str)
        name = f"sealed/{key}/{tag}.json"
        if self.live and self.cfg.get("evidence_bucket") and self.cfg.get("seal"):
            until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
            self.s3.put_object(Bucket=self.cfg["evidence_bucket"], Key=name, Body=body.encode(),
                               ObjectLockMode="GOVERNANCE", ObjectLockRetainUntilDate=until)
            return f"s3://{self.cfg['evidence_bucket']}/{name} (Object Lock until {until:%Y-%m-%d %H:%M} UTC)"
        p = DATA / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
        return f"local {p.relative_to(DATA.parent)} (replay mode: no AWS write)"

    def respond(self, role_arn):
        """Same as the console's 'Revoke active sessions': deny tokens issued before now."""
        if not role_arn or ":role/" not in role_arn:
            return "no role to revoke"
        role = role_arn.split("/")[-1]
        if not (self.live and self.cfg.get("respond")):
            return f"response for {role} is switched off (set PW25_RESPOND=1 to enable)"
        now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*",
               "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}}}]}
        self.iam.put_role_policy(RoleName=role, PolicyName="AWSRevokeOlderSessions", PolicyDocument=json.dumps(doc))
        return f"revoked sessions of {role} issued before {now}"
