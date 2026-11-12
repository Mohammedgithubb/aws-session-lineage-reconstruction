# PW_25_NS_02 Live Detection: setup from zero

This builds the detection part: AWS sandbox, live detector (M1 to M5 + fusion) and the dashboard.
Everything runs in **your own AWS account**, in **us-east-1 (N. Virginia)**.
Expected cost: well under 1 USD for the demo (a $5 budget alarm is included).

```
detection/
├── infra/sandbox.yaml      AWS resources (CloudFormation)
├── detector/               Python detector + dashboard server (dashboard already built in detector/static)
├── dashboard/              React source for the dashboard (only needed if you change the UI)
├── scripts/                normal activity, demo attack, suppression test, teardown, synthetic replay
├── eval/evaluate.py        precision, recall, time to detect against ground truth
└── data/                   database, baseline, ground truth, synthetic replay
```

---

## Part A. Make your AWS account safe (10 min, one time)

1. Sign in to the AWS console as the **root user** (the email you signed up with).
2. Top right, your name > **Security credentials** > **Assign MFA device**. Use an authenticator app on your phone.
3. Go to **IAM > Users > Create user**:
   - User name: `pw25-admin`
   - Tick **Provide user access to the AWS Management Console** (optional).
   - Permissions: **Attach policies directly** > `AdministratorAccess`.
4. Open the new user > **Security credentials** > **Create access key** > *Command Line Interface (CLI)*.
   Save the **Access key ID** and **Secret access key**. You use these on your laptop.
5. From now on, use `pw25-admin`, not root.
6. Top right Region selector: choose **US East (N. Virginia) us-east-1**.

> Why us-east-1: IAM events are recorded only there, and the live stream rule is regional.
> Keep the demo in us-east-1 so every event reaches the detector.

---

## Part B. Create the sandbox with one template (5 min)

1. Console > **CloudFormation** > **Create stack** > **With new resources (standard)**.
2. **Upload a template file** > choose `infra/sandbox.yaml` > Next.
3. Stack name: `pw25-sandbox`. AlertEmail: your email. MonthlyBudgetUSD: `5`. Next, Next.
4. Tick **I acknowledge that AWS CloudFormation might create IAM resources with custom names**. Submit.
5. Wait for **CREATE_COMPLETE** (about 3 minutes).

What it creates:

| Resource | Name | Used by |
|---|---|---|
| CloudTrail trail with log file validation (digest files) | `pw25-trail` | M5 S2, S3 |
| Trail log bucket | `pw25-trail-<account>` | M5 |
| Test data bucket (normal files + decoys), S3 data events on | `pw25-test-data-<account>` | M3, M4 |
| Evidence bucket, S3 Object Lock (governance, 1 day) | `pw25-evidence-<account>` | sealing |
| EventBridge rule (all API calls, read and write) into SQS | `pw25-all-api-calls`, `pw25-cloudtrail-events` | live stream |
| Demo user and role chain | `pw25-dev-alice`, `pw25-Role-A` > `pw25-Role-B` > `pw25-Role-C` (privileged) | demo |
| Decoy user with **no permissions** + its key | `pw25-backup-svc` | M4 |
| Budget alarm | `pw25-sandbox` | cost safety |

If the stack fails on the EventBridge rule state, edit `infra/sandbox.yaml`, change
`State: ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` to `State: ENABLED`, and create again
(read-only calls such as ListRoles will then not reach the live stream).

---

## Part C. Laptop setup (10 min, one time)

1. Install **Python 3.11 or newer** (python.org; on Windows tick "Add python.exe to PATH").
2. Install **AWS CLI v2** (search "Install AWS CLI v2"). Needed for the digest check (S3).
3. Open a terminal and run:
   ```
   aws configure
   ```
   Access key / secret: the `pw25-admin` keys. Region: `us-east-1`. Output: `json`.
4. In the `detection` folder:
   ```
   python -m venv .venv
   .venv\Scripts\activate          (Windows)      or      source .venv/bin/activate   (Mac/Linux)
   pip install -r requirements.txt
   python -m detector setup --stack pw25-sandbox
   ```
   `setup` reads the stack outputs, writes `config.json` and `data/demo_credentials.ini`,
   and uploads 3 normal report files and 2 decoy files to the test bucket.

Do not share `config.json` or `data/demo_credentials.ini`. They hold sandbox keys.

---

## Part D. Learn normal behaviour (run tonight)

Open **two terminals** (activate `.venv` in both).

Terminal 1, the detector in learn mode:
```
python -m detector run --mode learn
```
Terminal 2, normal daily work every 10 minutes:
```
python scripts/normal_activity.py --loop --minutes 10
```
Leave both running for a few hours (overnight is good). Each round is about 10 API calls.
An identity needs 30 events before M1 and M2 score it, so even 1 to 2 hours works for a demo.
For the final results, run this for a full normal week.

Stop terminal 1 with **Ctrl+C**. It saves the baseline to `data/baseline.pkl`.
(The SQS queue keeps events for 4 days, so if your laptop sleeps nothing is lost: the detector catches up.)

---

## Part E. Live detection and the demo attack

Terminal 1:
```
python -m detector run --mode detect
```
Open **http://localhost:8000** in a browser.

Terminal 2 (keep normal activity going):
```
python scripts/normal_activity.py --loop --minutes 10
```
Terminal 3, the attack. **Switch your laptop to a phone hotspot first**, so the attacker's network is new:
```
python scripts/attack_chain.py
```
What happens on the dashboard, a few minutes after each step (CloudTrail delivery delay):
1. Role-A session: new network and tool `curl` (M1), burst of AccessDenied and odd call order (M2) > **Suspicious**, evidence sealed in the Object Lock bucket.
2. Role-B > Role-C never-seen privileged link (M3).
3. Decoy file read and decoy key used (M4) > **Compromised**.

Optional, about 15 minutes later (simulated log suppression, logging stays ON):
```
python scripts/suppress.py
```
It deletes the trail file that holds the Role-B AssumeRole record. Within the next S2 check
(every 3 min) Event History disagrees with the trail (M5 S2), and the hourly digest check fails (M5 S3).

Results against ground truth:
```
python -m detector evaluate
```

Automated response (revoking role sessions) is **off** by default. To turn it on:
`set PW25_RESPOND=1` (Windows) or `export PW25_RESPOND=1`, then start the detector.

---

## Part F. No internet in the review room? Use the replay

```
python -m detector replay
```
Open http://localhost:8000. It plays a **synthetic** CloudTrail file (3 normal days learned, then an attack
with a hidden Role-B issuance) in about 2 minutes. The header says "replay (synthetic data)".
Results: `python -m detector evaluate --truth data/replay_truth.jsonl`.
Say clearly that this is synthetic test data, not the AWS run.

---

## Part G. Clean up after the project

```
python scripts/teardown.py
```
Empties the buckets and deletes the stack. Delete the evidence bucket by hand after one day (Object Lock).

---

## What each file does (for the viva)

| File | Method | What it does |
|---|---|---|
| `detector/normalize.py` | all | Turns a CloudTrail record into one flat event (identity, key, network /24, tool, call, error, resources) |
| `detector/m1_baseline.py` | M1 | Rarity score R = Σ w·(−log2 p) with Laplace smoothing, Isolation Forest (scikit-learn), session drift |
| `detector/m2_sequence.py` | M2 | 2nd-order Markov next-call model, top-5 rule (DeepLog), Poisson error-burst test (SciPy) |
| `detector/m3_graph.py` | M3 | MIDAS-R with Count-Min Sketch, never-seen privileged link, role-chain depth |
| `detector/m4_honeytoken.py` | M4 | Decoy key / decoy object / decoy identity check |
| `detector/m5_isca.py`, `m5_jobs.py` | M5 | S1 orphan session (live), S2 Event History vs trail with Wald SPRT, S3 digest chain (`aws cloudtrail validate-logs`) |
| `detector/fusion.py` | F | Bel(C) = 1 − Π(1 − r·m), thresholds 0.30 / 0.60 / 0.90 |
| `detector/actions.py` | | Seal evidence to Object Lock; revoke sessions (AWSRevokeOlderSessions policy) |
| `detector/engine.py` | | Runs everything per event, keeps per-session evidence, raises alerts |
| `detector/api.py` | | Serves the dashboard and its data |
| `eval/evaluate.py` | | Precision, recall, F1, time to detect from `data/ground_truth.jsonl` |

Two rules keep the results honest:
1. The detector never reads `data/ground_truth.jsonl`. Only `evaluate` does.
2. The detector sees only what CloudTrail delivers. No marker is planted.

Changes from the methods document, found while testing:
- M3 score is scaled as 0 at the normal 99.9th percentile (tau) and 1 at ten times tau (log scale), because the
  plain log ratio made normal bursts look suspicious.
- Session drift (M1 part C) is checked only for temporary `ASIA` keys; long-lived user keys change network normally.
- The detector learns only from sessions that are still below Suspicious, so an attacker cannot teach it.
