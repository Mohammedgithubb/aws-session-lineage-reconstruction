"""Command line:
  python -m detector setup   --stack pw25-sandbox      read the stack outputs, write config.json, upload test files
  python -m detector run     --mode learn|detect        live from the SQS queue
  python -m detector replay  [--file data/replay_synthetic.jsonl]   play a recorded/synthetic file (no AWS needed)
  python -m detector evaluate --truth data/ground_truth.jsonl
"""
import argparse, signal, threading, time, sys
import uvicorn
from .config import load
from .engine import Engine
from .api import build_app

def serve(engine, port):
    print(f"Dashboard: http://localhost:{port}")
    uvicorn.run(build_app(engine), host="127.0.0.1", port=port, log_level="warning")

def main():
    ap = argparse.ArgumentParser(prog="detector")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup"); s.add_argument("--stack", default="pw25-sandbox")
    r = sub.add_parser("run"); r.add_argument("--mode", choices=["learn", "detect"], default="detect"); r.add_argument("--port", type=int, default=8000)
    p = sub.add_parser("replay"); p.add_argument("--file", default="data/replay_synthetic.jsonl"); p.add_argument("--learn-hours", type=float, default=72)
    p.add_argument("--delta", type=int, default=300, help="S1 delivery allowance in seconds (short for demos)")
    p.add_argument("--speed", type=float, default=30); p.add_argument("--port", type=int, default=8000)
    e = sub.add_parser("evaluate"); e.add_argument("--truth", default="data/ground_truth.jsonl")
    a = ap.parse_args()
    cfg = load()

    if a.cmd == "setup":
        from .setup_stack import setup
        setup(a.stack, cfg); return
    if a.cmd == "evaluate":
        sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
        from eval.evaluate import evaluate
        evaluate(a.truth); return

    stop = threading.Event()
    if a.cmd == "replay":
        from .store import Store
        from .sources import replay_loop
        cfg["delta_seconds"] = a.delta
        if "synthetic" in a.file:     # decoys used inside the synthetic file
            cfg["decoy_key_ids"] = ["AKIADECOY0000000001"]
            cfg["decoy_arns"] = ["arn:aws:s3:::pw25-test-data-111122223333/backup/backup-credentials.csv"]
        store = Store(); store.reset()
        eng = Engine(cfg, mode="learn", live=False, store=store)
        threading.Thread(target=replay_loop, args=(eng, a.file, a.learn_hours, a.speed, stop), daemon=True).start()
        serve(eng, a.port); return

    from .sources import sqs_loop
    if not cfg["queue_url"]:
        sys.exit("config.json has no queue_url. Run: python -m detector setup")
    eng = Engine(cfg, mode=a.mode, live=True)
    if a.mode == "detect":
        if eng.load_baseline():
            eng.finalize_learning()
            print(f"Loaded baseline ({eng.n_learned} learned events)")
        else:
            print("No baseline yet: M1/M2 stay quiet until identities pass the warm-up. Run --mode learn first.")
        from .m5_jobs import Jobs
        eng.jobs = Jobs(eng, cfg); eng.jobs.start()
    else:
        eng.load_baseline()
    t = threading.Thread(target=sqs_loop, args=(eng, cfg, stop), daemon=True); t.start()
    def bye(*_):
        if eng.mode == "learn":
            eng.save_baseline(); print("Baseline saved to data/baseline.pkl")
        stop.set(); sys.exit(0)
    signal.signal(signal.SIGINT, bye)
    try:
        serve(eng, a.port)
    finally:
        if eng.mode == "learn":
            eng.save_baseline(); print("Baseline saved to data/baseline.pkl")

if __name__ == "__main__":
    main()
