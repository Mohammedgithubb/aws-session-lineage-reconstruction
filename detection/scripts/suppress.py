"""Simulated log suppression in YOUR OWN sandbox: delete the delivered trail file that holds the
attacker's Role-B AssumeRole record. Logging stays ON. M5 should notice:
S2 (Event History still has the record, the trail does not) and S3 (digest chain no longer matches).
Run it about 15 minutes after attack_chain.py, so the log file has been delivered."""
import gzip, json, boto3
from common import ROOT, CFG

truth = [json.loads(l) for l in open(ROOT / "data" / "ground_truth.jsonl")]
kB = [t["key"] for t in truth if t["role"] == "pw25-Role-B"][-1]
s3 = boto3.client("s3", region_name=CFG["region"])
acct = boto3.client("sts").get_caller_identity()["Account"]
prefix = f"AWSLogs/{acct}/CloudTrail/{CFG['region']}/"
hit = None
for page in s3.get_paginator("list_objects_v2").paginate(Bucket=CFG["trail_bucket"], Prefix=prefix):
    for o in sorted(page.get("Contents", []), key=lambda o: o["LastModified"], reverse=True)[:300]:
        recs = json.loads(gzip.decompress(s3.get_object(Bucket=CFG["trail_bucket"], Key=o["Key"])["Body"].read())).get("Records", [])
        if any(((r.get("responseElements") or {}).get("credentials") or {}).get("accessKeyId") == kB for r in recs):
            hit = o["Key"]; break
    if hit: break
if not hit:
    raise SystemExit("Log file not found yet. Wait a few minutes and run again.")
s3.delete_object(Bucket=CFG["trail_bucket"], Key=hit)
with open(ROOT / "data" / "ground_truth.jsonl", "a") as f:
    f.write(json.dumps({"key": kB, "role": "pw25-Role-B", "suppressed_file": hit, "note": "trail file with Role-B issuance deleted"}) + "\n")
print("Deleted", hit)
