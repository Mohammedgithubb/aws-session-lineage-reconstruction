"""Where events come from: the live SQS queue, or a replay file."""
import json, time
from .normalize import normalize

def sqs_loop(engine, cfg, stop):
    import boto3
    sqs = boto3.client("sqs", region_name=cfg["region"])
    while not stop.is_set():
        r = sqs.receive_message(QueueUrl=cfg["queue_url"], MaxNumberOfMessages=10, WaitTimeSeconds=20)
        for msg in r.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
                rec = body.get("detail", body)
                engine.process(normalize(rec))
            except Exception as ex:                       # keep running on one bad message
                print("skip message:", ex)
            sqs.delete_message(QueueUrl=cfg["queue_url"], ReceiptHandle=msg["ReceiptHandle"])
        if engine.mode == "learn" and engine.n_learned and engine.n_learned % 200 == 0:
            engine.save_baseline()

def replay_loop(engine, path, learn_hours, speed, stop):
    """Feed a recorded file. The first `learn_hours` are learned instantly (the 'normal week'),
    then the rest is played at `speed` times real time in detect mode."""
    recs = [json.loads(l) for l in open(path) if l.strip()]
    evs = sorted((normalize(r.get("detail", r)) for r in recs), key=lambda e: e["t"])
    t0 = evs[0]["t"]
    cut = t0 + learn_hours * 3600
    engine.mode = "learn"
    for e in evs:
        if e["t"] >= cut:
            break
        engine.process(e)
    engine.finalize_learning()
    engine.mode = "detect"
    prev = None
    for e in evs:
        if e["t"] < cut:
            continue
        if stop.is_set():
            return
        if prev is not None:
            time.sleep(min(max(e["t"] - prev, 0) / speed, 3.0))
        engine.process(e)
        prev = e["t"]
    engine.replay_done = True
