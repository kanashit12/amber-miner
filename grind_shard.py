#!/usr/bin/env python3
"""Amber (琥珀币) PoW shard grinder — for GitHub Actions runners. Finds nonces; never sends txs.

Construction (validated in ~/workspace/amber-check/PREP.md, 13/13 real miner nonces):
  H1 = keccak256(abi.encode(currentSeed, miner))
  valid iff keccak256(abi.encode(H1, nonce)) <= currentTarget

Defaults below are the live 2026-11-04 values (seed from contract storage slot 9,
target 2^226 - 1, miner = wallet 1). Override via --seed/--target/--miner if the
auto-submit job reports the seed rotated at a daily rollover.

Usage:
  grind_shard.py --start <int> --count <int> [--need 1] [--out results.jsonl] [--procs N]
  grind_shard.py --selftest

Every find is appended immediately (flush + fsync) to the results file as one JSON
line: {"nonce": int, "hash": "0x…", "miner": "0x…", "source": "…", "recorded_at": "…"}
— the same schema as ~/workspace/amber-check/batch_w1.jsonl, so collect.py can merge
GitHub results straight into the local batch.
"""
import argparse, json, os, sys, time
from datetime import datetime, timezone
from multiprocessing import Pool, cpu_count
from Crypto.Hash import keccak as _kk

SEED = 1171936696677116967947855102463325820488726368244161564174682728594779209803
TARGET = (1 << 226) - 1
MINER = "0xD6bE25e654A516c875AFFD2BBF116bB08179908c"

CHUNK = 1 << 18


def H(b):
    h = _kk.new(digest_bits=256)
    h.update(b)
    return h.digest()


def u256(n):
    return n.to_bytes(32, "big")


def a256(a):
    return bytes.fromhex(a[2:] if a.startswith("0x") else a).rjust(32, b"\0")


def pow_hash(seed, miner, nonce):
    """Full PoW hash for (seed, miner, nonce) as an int."""
    H1 = H(u256(seed) + a256(miner))
    return int.from_bytes(H(H1 + u256(nonce)), "big")


def _worker(job):
    seed, miner, target, lo, hi = job
    H1 = H(u256(seed) + a256(miner))
    for n in range(lo, hi):
        d = H(H1 + u256(n))
        if int.from_bytes(d, "big") <= target:
            return n, "0x" + d.hex()
    return None


def selftest():
    """Reproduce the known solution from PREP.md before trusting this script."""
    exp_H1 = "0xf0f31a43207f6bd834924781d83556070d6ce6ae066e51b31b74306a3acac473"
    exp_hash = "0x0000000203f5c0eb2677cf0d5b64c7cf0e7a32a4d3949589cb64ea15b54124d3"
    H1 = H(u256(SEED) + a256(MINER))
    assert "0x" + H1.hex() == exp_H1, f"H1 mismatch: 0x{H1.hex()} != {exp_H1}"
    hv = pow_hash(SEED, MINER, 457589469)
    assert "0x%064x" % hv == exp_hash, f"hash mismatch: 0x{hv:064x} != {exp_hash}"
    assert hv <= TARGET, "known nonce does not meet target"
    print(f"SELFTEST PASS: nonce 457589469 -> {exp_hash} (<= target 2^226-1, 30 leading zero bits)")
    return True


def main():
    ap = argparse.ArgumentParser(description="Amber PoW shard grinder (GitHub Actions)")
    ap.add_argument("--start", type=lambda s: int(s, 0), default=0, help="first nonce of this shard's range")
    ap.add_argument("--count", type=lambda s: int(s, 0), default=1 << 40, help="range size")
    ap.add_argument("--need", type=int, default=1, help="stop after this many finds")
    ap.add_argument("--out", default="results.jsonl", help="results JSONL file (appended)")
    ap.add_argument("--seed", type=lambda s: int(s, 0), default=SEED)
    ap.add_argument("--target", type=lambda s: int(s, 0), default=TARGET)
    ap.add_argument("--miner", default=MINER)
    ap.add_argument("--procs", type=int, default=0, help="worker processes (0 = cpu count)")
    ap.add_argument("--shard", default="", help="shard label recorded in each result")
    ap.add_argument("--selftest", action="store_true", help="verify against the known PREP.md solution and exit")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0

    procs = args.procs or cpu_count()
    end = args.start + args.count
    source = "github actions amber-miner" + (f" shard {args.shard}" if args.shard else "")
    print(f"grind start={args.start} count={args.count} need={args.need} procs={procs} "
          f"seed={args.seed} target_bits={args.target.bit_length()} miner={args.miner} out={args.out}",
          flush=True)

    found = 0
    tried = 0
    t0 = time.time()
    out_f = open(args.out, "a", encoding="utf-8")
    try:
        with Pool(procs) as p:
            base = args.start
            while base < end and found < args.need:
                jobs = []
                for i in range(procs):
                    lo = base + i * CHUNK
                    if lo >= end:
                        break
                    jobs.append((args.seed, args.miner, args.target, lo, min(lo + CHUNK, end)))
                for r in p.imap_unordered(_worker, jobs):
                    if r is not None:
                        n, hx = r
                        # re-verify in the parent before trusting a worker result
                        assert pow_hash(args.seed, args.miner, n) == int(hx, 16)
                        rec = {"nonce": n, "hash": hx, "miner": args.miner,
                               "source": source,
                               "recorded_at": datetime.now(timezone.utc).isoformat()}
                        out_f.write(json.dumps(rec) + "\n")
                        out_f.flush()
                        os.fsync(out_f.fileno())
                        found += 1
                        print(f"FOUND nonce={n} hash={hx}", flush=True)
                        if found >= args.need:
                            break
                tried = min(base + procs * CHUNK, end) - args.start
                base += procs * CHUNK
                dt = time.time() - t0
                print(f"  ...{tried:,} nonces tried, {tried / dt:,.0f} h/s, "
                      f"{found}/{args.need} found, {dt:.0f}s elapsed", flush=True)
    finally:
        out_f.close()
    dt = time.time() - t0
    print(f"DONE found={found} tried={tried:,} in {dt:.0f}s ({tried / max(dt, 1):,.0f} h/s avg)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
