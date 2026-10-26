# Decision 003 — Nonce format and seed reproducibility

## Decision
Nonces are **12-character lowercase hex** strings, computed as
`sha256(f"{seed}:{target_id}:{index}")[:12]`. Query names are
`<nonce>.probe.lab.test`.

## Alternatives considered
- Random `os.urandom` bytes — not reproducible from a seed.
- UUID4 — 32 hex chars, longer than needed, not seed-reproducible.
- Counter-only (`000000000001`, ...) — predictable, weakens the "unique random
  name" proof and collides across runs.
- `sha256(seed:target_id:index)[:12]` (chosen).

## Why
- **Reproducible from a seed** — required by `test_nonce.py`; same
  `(seed, target_id, index)` always yields the same nonce, which lets us
  repeat a scan and correlate with the auth-zone log.
- **Unique per probe** — the `index` (and `target_id`) components guarantee
  uniqueness across targets and within a target across probes/retries.
- **12 lowercase hex** — short enough to fit comfortably in a DNS label
  (max 63 chars per label), easy to match against the auth log's `nonce`
  field, and lowercase keeps zone-file/log matching case-insensitive-safe.
- `sha256` provides good distribution without needing a cryptographic RNG at
  probe time; the seed is operator-chosen.

## Trade-offs
- Truncating to 12 hex chars (48 bits) carries a negligible collision risk
  for the at-most-80 total queries per run.
- The operator must record the seed used for a run to reproduce it later
  (stored in report metadata).
