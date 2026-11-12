"""Empty the buckets and delete the sandbox stack (the evidence bucket stays until its 1-day lock ends)."""
import json, boto3, pathlib
CFG = json.loads((pathlib.Path(__file__).resolve().parent.parent / "config.json").read_text())
s3 = boto3.resource("s3", region_name=CFG["region"])
for b in (CFG["trail_bucket"], CFG["test_bucket"]):
    s3.Bucket(b).object_versions.delete(); s3.Bucket(b).objects.delete(); print("emptied", b)
boto3.client("cloudformation", region_name=CFG["region"]).delete_stack(StackName="pw25-sandbox")
print("Stack deletion started. Delete the evidence bucket by hand after one day.")
