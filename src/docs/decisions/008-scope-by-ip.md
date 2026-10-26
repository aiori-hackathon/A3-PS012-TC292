# Decision 008 — Scope validation by IP address

## Decision
`SafetyGate.check_scope(ip)` refuses any IP not present in `scope.yaml`
(targets are matched by their `ip` field). Probing a hostname is not
supported; targets are always addressed by IP.

## Alternatives considered
- **Match targets by hostname or ID** — hostnames can resolve to different
  IPs at different times, weakening the guarantee that only authorised IPs
  are contacted.
- **Match by IP (chosen)** — the build prompt's scope file lists each target
  with a static IP, and the lab uses static IPs so scope and ground truth
  stay stable.

## Why
- The safety requirement is absolute: "No target outside `scope.yaml` is ever
  contacted." Matching by the exact IP string is the strongest, simplest
  enforcement — there is no DNS resolution step that could be hijacked or
  change between runs.
- The lab's static IPs (172.28.0.101–120) make this stable and testable.

## Trade-offs
- If a target's IP changes, scope.yaml must be updated before re-running.
  This is acceptable for an authorised lab assessment.
