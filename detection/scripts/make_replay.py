"""Make a SYNTHETIC CloudTrail replay file for testing the detector without AWS.
Days 1-3 (72 h): normal activity only (the detector learns from it).
Day 4: normal activity continues; at 04:10 UTC an attacker uses a stolen Role-A key,
walks Role-A -> Role-B -> Role-C, reads a decoy, and the AssumeRole record for Role-B is
removed (simulated log suppression). Writes data/replay_synthetic.jsonl and data/replay_truth.jsonl.
Clearly synthetic: used for testing and as a demo fallback, not as evaluation results."""
import json, random, secrets, string, sys, pathlib
from datetime import datetime, timedelta, timezone

random.seed(11)
ACCT = "111122223333"
BUCKET = f"pw25-test-data-{ACCT}"
OUT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "data")
OUT.mkdir(exist_ok=True)
DAY1 = datetime(2026, 11, 2, tzinfo=timezone.utc)

def iso(t): return t.strftime("%Y-%m-%dT%H:%M:%SZ")
def key(p="ASIA"): return p + "".join(random.choices(string.ascii_uppercase + string.digits, k=16))
def eid(): return str(__import__("uuid").UUID(int=random.getrandbits(128)))
def role_arn(r): return f"arn:aws:iam::{ACCT}:role/{r}"

def user_identity(kind, name, k, created=None):
    if kind == "user":
        return {"type": "IAMUser", "userName": name, "arn": f"arn:aws:iam::{ACCT}:user/{name}", "accountId": ACCT, "accessKeyId": k}
    return {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCT}:assumed-role/{name}/s", "accountId": ACCT, "accessKeyId": k,
            "sessionContext": {"sessionIssuer": {"type": "Role", "arn": role_arn(name), "userName": name, "accountId": ACCT},
                               "attributes": {"creationDate": iso(created), "mfaAuthenticated": "false"}}}

def rec(t, ui, src, name, ip, ua, err=None, rp=None, resp=None, res=None, read_only=True):
    r = {"eventVersion": "1.10", "userIdentity": ui, "eventTime": iso(t), "eventSource": f"{src}.amazonaws.com", "eventName": name,
         "awsRegion": "us-east-1", "sourceIPAddress": ip, "userAgent": ua, "requestParameters": rp, "responseElements": resp,
         "eventID": eid(), "readOnly": read_only, "eventType": "AwsApiCall", "recipientAccountId": ACCT}
    if err: r["errorCode"] = err; r["errorMessage"] = "denied"
    if res: r["resources"] = res
    return {"detail-type": "AWS API Call via CloudTrail", "source": "aws." + src, "detail": r}

def assume(t, caller_ui, role, ip, ua, new_key):
    return rec(t, caller_ui, "sts", "AssumeRole", ip, ua, rp={"roleArn": role_arn(role), "roleSessionName": "s"},
               resp={"credentials": {"accessKeyId": new_key, "expiration": iso(t + timedelta(hours=1))}}, read_only=True)

def s3get(t, ui, k_obj, ip, ua, err=None):
    arn = f"arn:aws:s3:::{BUCKET}/{k_obj}"
    return rec(t, ui, "s3", "GetObject", ip, ua, err=err, rp={"bucketName": BUCKET, "key": k_obj},
               res=[{"type": "AWS::S3::Object", "ARN": arn}, {"type": "AWS::S3::Bucket", "ARN": f"arn:aws:s3:::{BUCKET}"}])

def s3list(t, ui, ip, ua):
    return rec(t, ui, "s3", "ListObjects", ip, ua, rp={"bucketName": BUCKET}, res=[{"type": "AWS::S3::Bucket", "ARN": f"arn:aws:s3:::{BUCKET}"}])

ALICE_KEY = "AKIA" + "ALICEDEMO0000001"
OFFICE = ["198.51.100.%d" % i for i in (10, 11, 12)]
VPN = "192.0.2.44"
CLI, BOTO = "aws-cli/2.17.3 Python/3.11 Linux/6.5 exe/x86_64", "Boto3/1.35.10 md/Botocore#1.35.10 Python/3.11.9 Linux"
events, truth = [], []

def normal_session(t):
    ip = random.choice(OFFICE) if random.random() > 0.1 else VPN
    ua = CLI if random.random() > 0.15 else BOTO
    k = key()
    alice = user_identity("user", "pw25-dev-alice", ALICE_KEY)
    events.append(assume(t, alice, "pw25-Role-A", ip, ua, k))
    created = t
    ui = user_identity("role", "pw25-Role-A", k, created)
    tt = t + timedelta(seconds=random.randint(5, 30))
    events.append(rec(tt, ui, "s3", "ListBuckets", ip, ua))
    for _ in range(random.randint(2, 6)):
        tt += timedelta(seconds=random.randint(10, 90))
        events.append(s3list(tt, ui, ip, ua))
        tt += timedelta(seconds=random.randint(5, 40))
        f = random.choice(["reports/jan.csv", "reports/feb.csv", "reports/mar.csv", "reports/apr.csv"])
        events.append(s3get(tt, ui, f, ip, ua, err="NoSuchKey" if f.endswith("apr.csv") and random.random() < 0.5 else None))
    if random.random() < 0.08:   # rare ops task: Role-A -> Role-B to read a role
        kb = key()
        events.append(assume(tt + timedelta(seconds=20), ui, "pw25-Role-B", ip, ua, kb))
        uib = user_identity("role", "pw25-Role-B", kb, tt + timedelta(seconds=20))
        events.append(rec(tt + timedelta(seconds=40), uib, "iam", "GetRole", ip, ua, rp={"roleName": "pw25-Role-A"}))
    return k, ui, ip, ua

def normal_day(day, start_h=3.5, end_h=13.5):
    t = day + timedelta(hours=start_h)
    keys = []
    while t < day + timedelta(hours=end_h):
        keys.append((t, normal_session(t)))
        t += timedelta(minutes=random.randint(25, 55))
    return keys

LEARN_DAYS = 3
for d in range(LEARN_DAYS):
    normal_day(DAY1 + timedelta(days=d))
day2 = DAY1 + timedelta(days=LEARN_DAYS)
sessions2 = normal_day(day2, 3.5, 5.0)

# ----- attack on day 2 -----
ATT_IP, CURL = "203.0.113.7", "curl/8.4.0"
T = day2 + timedelta(hours=4, minutes=10)
stolen_t, (K, uiA, _, _) = [s for s in sessions2 if s[0] <= T][-1]   # most recent legit Role-A session key
truth.append({"key": K, "role": "pw25-Role-A", "first_call": iso(T), "note": "stolen Role-A session key (also used by the victim)"})
ui = uiA
t = T
events.append(rec(t, ui, "sts", "GetCallerIdentity", ATT_IP, CURL))
for name in ["ListRoles", "ListUsers", "ListPolicies", "ListRoles", "GetAccountAuthorizationDetails", "ListAttachedRolePolicies", "ListRoles", "ListGroups"]:
    t += timedelta(seconds=random.randint(4, 12))
    events.append(rec(t, ui, "iam", name, ATT_IP, CURL, err="AccessDenied"))
t += timedelta(seconds=30); events.append(rec(t, ui, "s3", "ListBuckets", ATT_IP, CURL))
# Role-A -> Role-B; this AssumeRole record is SUPPRESSED (not written to the replay)
t += timedelta(seconds=60); K2 = key(); tB = t
truth.append({"key": K2, "role": "pw25-Role-B", "first_call": iso(t + timedelta(seconds=15)), "note": "attacker Role-B session; its AssumeRole record was hidden"})
uiB = user_identity("role", "pw25-Role-B", K2, tB)
t += timedelta(seconds=15); events.append(rec(t, uiB, "iam", "ListRoles", ATT_IP, CURL))
t += timedelta(seconds=20); events.append(rec(t, uiB, "iam", "GetRole", ATT_IP, CURL, rp={"roleName": "pw25-Role-C"}))
# Role-B -> Role-C (privileged)
t += timedelta(seconds=40); K3 = key()
events.append(assume(t, uiB, "pw25-Role-C", ATT_IP, CURL, K3))
truth.append({"key": K3, "role": "pw25-Role-C", "first_call": iso(t + timedelta(seconds=20)), "note": "attacker Role-C session"})
uiC = user_identity("role", "pw25-Role-C", K3, t)
t += timedelta(seconds=20); events.append(s3list(t, uiC, ATT_IP, CURL))
t += timedelta(seconds=25); events.append(s3get(t, uiC, "reports/jan.csv", ATT_IP, CURL))
t += timedelta(seconds=30); events.append(s3get(t, uiC, "backup/backup-credentials.csv", ATT_IP, CURL))
# attacker keeps using the Role-B key for a while (lets the orphan check fire after the delivery allowance)
for m in range(3, 25, 3):
    events.append(rec(tB + timedelta(minutes=m, seconds=random.randint(0, 50)), uiB, "iam", "ListRoles", ATT_IP, CURL))

events.sort(key=lambda e: e["detail"]["eventTime"])
(OUT / "replay_synthetic.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n")
(OUT / "replay_truth.jsonl").write_text("\n".join(json.dumps(x) for x in truth) + "\n")
print(f"{len(events)} synthetic events, attack at {iso(T)}; ground truth for {len(truth)} attacker sessions")
