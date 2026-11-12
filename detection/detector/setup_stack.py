"""Read the CloudFormation outputs, write config.json and data/demo_credentials.ini,
and upload normal files plus decoy files to the test bucket."""
import json
import boto3
from .config import CONFIG_FILE, DATA

NORMAL = {"reports/jan.csv": "month,sales\njan,120\n", "reports/feb.csv": "month,sales\nfeb,135\n", "reports/mar.csv": "month,sales\nmar,150\n"}
DECOYS = {"backup/backup-credentials.csv": "PLACEHOLDER - this is a decoy file with no real data\n",
          "finance/payroll-2026.xlsx.txt": "PLACEHOLDER - decoy\n"}

def setup(stack, cfg):
    cf = boto3.client("cloudformation", region_name=cfg["region"])
    out = {o["OutputKey"]: o["OutputValue"] for o in cf.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}
    s3 = boto3.client("s3", region_name=cfg["region"])
    for k, v in {**NORMAL, **DECOYS}.items():
        s3.put_object(Bucket=out["TestBucket"], Key=k, Body=v.encode())
    conf = {"region": cfg["region"], "queue_url": out["QueueUrl"], "trail_bucket": out["TrailBucket"],
            "test_bucket": out["TestBucket"], "evidence_bucket": out["EvidenceBucket"],
            "decoy_key_ids": [out["DecoyKeyId"]],
            "decoy_arns": [f"arn:aws:s3:::{out['TestBucket']}/{k}" for k in DECOYS],
            "privileged": ["pw25-Role-C"],
            "roles": {"A": out["RoleA"], "B": out["RoleB"], "C": out["RoleC"]}}
    CONFIG_FILE.write_text(json.dumps(conf, indent=2))
    (DATA / "demo_credentials.ini").write_text(
        f"[pw25-dev-alice]\naws_access_key_id = {out['DevUserKeyId']}\naws_secret_access_key = {out['DevUserSecret']}\n\n"
        f"[pw25-decoy]\naws_access_key_id = {out['DecoyKeyId']}\naws_secret_access_key = {out['DecoySecret']}\n")
    print("Wrote config.json and data/demo_credentials.ini, uploaded", len(NORMAL), "normal and", len(DECOYS), "decoy files.")
