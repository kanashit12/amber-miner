#!/usr/bin/env python3
"""Merge GitHub Actions grind results into the local Amber batch.

Reads one or more downloaded artifact files (results.jsonl from each shard,
or directories containing them), re-verifies every nonce against the validated
PoW construction, dedupes against the nonces already in the local batch, and
appends the new ones in the exact batch_w1.jsonl schema:
  {"nonce": int, "hash": "0x…", "miner": "0x…", "source": "…", "recorded_at": "…"}

Usage:
  collect.py result-0/results.jsonl result-1/results.jsonl ...
  collect.py ~/Downloads/amber-artifacts/          (a directory is scanned recursively)
  collect.py --batch ~/workspace/amber-check/batch_w1.jsonl files...

Default batch: ~/workspace/amber-check/batch_w1.jsonl
"""
import argparse, glob, json, os, sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from grind_shard import SEED, TARGET, MINER, pow_hash  # validated construction

DEFAULT_BATCH = os.path.expanduser("~/workspace/amber-check/batch_w1.jsonl")


def iter_inputs(paths):
    for p in paths:
        if os.path.isdir(p):
            for f in sorted(glob.glob(os.path.join(p, "**", "*.jsonl"), recursive=True)):
                yield f
        else:
            yield p


def load_nonces(path):
    nonces = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        nonces.add(int(json.loads(line)["nonce"]))
                    except Exception:
                        pass
    return nonces


def main():
    ap = argparse.ArgumentParser(description="Merge GitHub grind artifacts into the local Amber batch")
    ap.add_argument("inputs", nargs="+", help="artifact results.jsonl files and/or directories")
    ap.add_argument("--batch", default=DEFAULT_BATCH, help="local batch file to append to")
    args = ap.parse_args()

    known = load_nonces(args.batch)
    print(f"batch {args.batch}: {len(known)} nonces already present")

    added, dupes, bad = 0, 0, 0
    out = open(args.batch, "a", encoding="utf-8")
    try:
        for path in iter_inputs(args.inputs):
            n_file = 0
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        nonce = int(rec["nonce"])
                    except Exception:
                        bad += 1
                        continue
                    if nonce in known:
                        dupes += 1
                        continue
                    hv = pow_hash(SEED, MINER, nonce)
                    hx = "0x%064x" % hv
                    if hv > TARGET or ("hash" in rec and rec["hash"].lower() != hx):
                        print(f"  REJECT nonce={nonce} from {path}: hash mismatch/over target")
                        bad += 1
                        continue
                    new = {"nonce": nonce, "hash": hx, "miner": MINER,
                           "source": f"github actions amber-miner ({os.path.basename(os.path.dirname(path)) or os.path.basename(path)})",
                           "recorded_at": datetime.now(timezone.utc).isoformat()}
                    out.write(json.dumps(new) + "\n")
                    out.flush()
                    os.fsync(out.fileno())
                    known.add(nonce)
                    added += 1
                    n_file += 1
                    print(f"  + nonce={nonce} hash={hx}")
            print(f"{path}: {n_file} new")
    finally:
        out.close()
    print(f"DONE added={added} duplicates={dupes} rejected={bad} batch_total={len(known)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
