# Decision 005 — Kill-switch location (`./KILL` file)

## Decision
The kill switch is triggered by the existence of a file named `KILL` in the
current working directory (`./KILL`), checked by `SafetyGate.kill_switch()`
before every query. `SIGINT` also sets the kill flag, as does reaching
`max_total_queries`.

## Alternatives considered
- **`KILL` in `src/`** — inconsistent with where the operator runs `make demo`
  (repo root).
- **Environment variable** — not visible/inspectable mid-run, harder for a
  human to trigger.
- **`./KILL` file (chosen)** — trivial for an operator to create (`touch KILL`)
  and remove, and easy to test (`test_kill_switch_file` creates it in a tmp
  dir).

## Why
- The build prompt explicitly says: "creating the file `KILL` mid-run stops
  the scan within one query, and partial evidence is saved."
- A filesystem flag is language-agnostic and works even if the process is
  busy in a blocking call (checked on the next loop iteration).
- Checked before every query via the prober's `rate_limiter.wait` /
  `SafetyGate.record_query` flow, so it stops within one query.

## Trade-offs
- The operator must remember to delete `KILL` before the next run, or every
  subsequent run will exit immediately.
