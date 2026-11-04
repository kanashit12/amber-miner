# amber-miner — GitHub Actions PoW grinding for Amber (琥珀币)

Distributed nonce grinding for the Amber PoW token
(`0x4008a353d3476884DC8Cd8fBf314970C8409FB22`, BSC), miner = wallet 1
`0xD6bE25e654A516c875AFFD2BBF116bB08179908c` (kanashit.ai).

PoW construction (validated against 13/13 real miner nonces + the known local
solution, see `~/workspace/amber-check/PREP.md`):

```
H1 = keccak256(abi.encode(currentSeed, miner))
valid iff keccak256(abi.encode(H1, nonce)) <= currentTarget   # 2^226 - 1
```

with `currentSeed = 1171936696677116967947855102463325820488726368244161564174682728594779209803`
(seed read from the contract at the 2026-11-04 open; if the seed rotates at a
daily rollover these ranges must be re-ground under the new seed).

## How it works

- `grind_shard.py` — one shard's grinder (stdlib + pycryptodome). Takes
  `--start` / `--count` (its nonce range) and `--need` (stop after N finds).
  Every find is appended immediately to `results.jsonl` and printed as a
  `FOUND nonce=… hash=…` line in the job log. `--selftest` reproduces the
  known solution (nonce 457589469) before any grinding starts.
- `.github/workflows/grind.yml` — `workflow_dispatch` with inputs
  `shards` (default 20) and `need_per_shard` (default 1). A setup job builds
  the matrix; shard *i* grinds the disjoint range `[i · 2^40, (i+1) · 2^40)`,
  runs up to 350 minutes, prints its finds into the job log, and uploads
  `results.jsonl` as artifact `result-<shard>`.
- `collect.py` — local merge helper: point it at the downloaded artifact
  files/dirs; it re-verifies every nonce, dedupes, and appends the new ones
  to `~/workspace/amber-check/batch_w1.jsonl` in the local batch schema.

## Dispatch (as used for the 2026-11-05 reset)

```
workflow: amber-grind
inputs:   shards=20, need_per_shard=1
```

That is up to 20 parallel runners × one wallet-1 nonce each. If time remains
before the reset, dispatch a second run with `need_per_shard=1` again (fresh
ranges are not needed — re-running covers the same ranges, so prefer raising
`need_per_shard` to 2 on a second dispatch only if the first run's shards are
still mid-range; simplest effective pattern: one dispatch, shards=20,
need_per_shard=1, then collect).

## After the run

1. Download all `result-*` artifacts from the run page.
2. Locally: `python3 collect.py <artifact files/dirs>` → merged into
   `~/workspace/amber-check/batch_w1.jsonl`.
3. The nonces join the local batch (local systemd grind + the pre-existing
   nonce 457589469) and are consumed by the **2026-11-05 20:00 WIB
   auto-submit job** (`amber-submit-reset-2026-11-05-1955`), which re-checks
   the seed at 19:55 WIB and submits up to 16 nonces in one `mine()` call if
   the seed is unchanged.

Nothing in this repo sends transactions. Note: GitHub's acceptable-use policy
restricts mining on Actions; this is a small one-off batch on the user's own
burner account (kanashit12), run with that risk understood.
