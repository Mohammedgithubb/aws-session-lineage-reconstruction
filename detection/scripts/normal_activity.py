"""Normal, harmless daily work for the 'normal week'. Run it on a schedule or leave it looping:
    python scripts/normal_activity.py --loop --minutes 20
Each round: pw25-dev-alice assumes Role-A, lists the bucket, reads a few report files."""
import argparse, random, time, datetime as dt
from botocore.exceptions import ClientError
from common import CFG, alice_session, assume

def one_round():
    s, k = assume(alice_session(), CFG["roles"]["A"], "alice-daily")
    s3 = s.client("s3")
    s3.list_buckets()
    for _ in range(random.randint(2, 5)):
        s3.list_objects_v2(Bucket=CFG["test_bucket"], Prefix="reports/")
        f = random.choice(["reports/jan.csv", "reports/feb.csv", "reports/mar.csv", "reports/apr.csv"])
        try:
            s3.get_object(Bucket=CFG["test_bucket"], Key=f)["Body"].read()
        except ClientError:
            pass            # apr.csv does not exist: a normal, occasional error
        time.sleep(random.uniform(3, 20))
    if random.random() < 0.05:       # rare ops task: look at a role through Role-B
        sb, _ = assume(s, CFG["roles"]["B"], "alice-ops")
        sb.client("iam").get_role(RoleName="pw25-Role-A")
    print(dt.datetime.now().strftime("%H:%M:%S"), "normal round done, Role-A key", k)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true"); ap.add_argument("--minutes", type=float, default=20)
    a = ap.parse_args()
    while True:
        try:
            one_round()
        except Exception as ex:
            print("round failed:", ex)
        if not a.loop:
            break
        time.sleep(a.minutes * 60 * random.uniform(0.6, 1.4))
