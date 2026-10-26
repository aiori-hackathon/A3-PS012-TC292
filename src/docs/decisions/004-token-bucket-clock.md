# Decision 004 — Token bucket with injectable clock/sleep

## Decision
`RateLimiter` uses one global `TokenBucket` plus one bucket per target.
`TokenBucket.wait()` blocks by calling an injectable `sleep` and reads time
from an injectable `clock`; both default to `time.monotonic` / `time.sleep`.

## Alternatives considered
- **Real `time.sleep` only** — simple but impossible to test deterministically
  (tests would have to wait real seconds).
- **`asyncio`-based limiter** — adds an event loop and async/await throughout
  the prober, overkill for a synchronous CLI tool.
- **Injectable clock + sleep (chosen)** — deterministic fake-clock tests.

## Why
- The build prompt requires `test_ratelimit.py` to verify global and per-target
  rates "using a fake clock." Injecting `clock` and `sleep` makes this
  deterministic without real delays.
- Token bucket is the standard, simple algorithm for rate limiting and maps
  cleanly to `global_qps` / `per_target_qps` / `capacity`.
- One bucket per target means a fast target can't starve a slow one; the
  global bucket enforces the aggregate cap.

## Trade-offs
- Blocking `sleep` serializes probing (one target at a time). This is
  intentional for safety: it keeps observed query rates strictly under the
  configured caps. Parallelism can be added later if needed.
