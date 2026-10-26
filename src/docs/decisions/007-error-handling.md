# Decision 007 — Error handling: result objects vs exceptions

## Decision
Network failures (timeouts, OS errors) are captured inside a
`ProbeResult` dataclass with an `error` field rather than raised as
exceptions. The prober never propagates a transport error to the caller.

## Alternatives considered
- **Raise exceptions on timeout/error** — the scan loop would need try/except
  around every probe, scattering error handling.
- **Return `ProbeResult` with `error` set (chosen)** — the caller always gets
  a result; classification rules consume `rcode`, `error`, and flags uniformly.

## Why
- The classifier's rule set is defined over outcomes ("No response after
  retries → Inconclusive (timeout)", "SERVFAIL/bad reply → Inconclusive").
  Modeling each probe as a `ProbeResult` makes those rules pure functions of
  the result, easier to test (`test_classifier.py` will build synthetic
  results).
- Keeps the scan loop simple: probe, store, classify. No control flow for
  exception handling.

## Trade-offs
- Callers must remember to check `result.error` instead of catching
  exceptions; the dataclass makes `error=None` the happy path, which is
  visually obvious.
