# Decision 006 — Transport: UDP first, TCP fallback on TC

## Decision
Every probe is sent over UDP first. If the reply carries the **TC (truncated)**
flag, the same query is retried over TCP. TCP is never the first choice.

## Alternatives considered
- **TCP for everything** — reliable but slower (handshake), unnecessary for
  small DNS queries and would increase latency for all 20 targets.
- **UDP only** — truncated responses would be silently incomplete, breaking
  targets like t16 (truncates UDP, full answer over TCP).
- **UDP first, TCP on TC (chosen)** — matches the build prompt's prober spec.

## Why
- DNS standard behavior: UDP is the default transport; TCP is the fallback
  for truncated responses (RFC 1035 §4.2.2).
- t16 is explicitly seeded to "truncate UDP replies, full answer over TCP,"
  so TCP fallback is required to classify it correctly.
- Avoids the TCP handshake cost on the common case.

## Trade-offs
- Adds one extra round-trip (and timeout) only when TC is seen, which is
  rare. Covered by `timeout_seconds` and retries.
