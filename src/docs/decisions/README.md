# Decision Log Index

Each file in this directory records a single design decision taken during
Phase 2 (Prober and safety), the alternatives considered, and why the chosen
option was selected. This satisfies the build prompt's `docs/decisions.md`
requirement as one file per decision.

| # | Decision | File |
|---|----------|------|
| 1 | Project-config file location (root vs. `src/`) | `001-project-config-location.md` |
| 2 | DNS library: dnspython vs dnslib | `002-dns-library-dnspython.md` |
| 3 | Nonce format and seed reproducibility | `003-nonce-format.md` |
| 4 | Token bucket with injectable clock/sleep | `004-token-bucket-clock.md` |
| 5 | Kill-switch location (`./KILL` file) | `005-kill-switch-location.md` |
| 6 | Transport: UDP first, TCP fallback on TC | `006-udp-tcp-fallback.md` |
| 7 | Error handling: result objects vs exceptions | `007-error-handling.md` |
| 8 | Scope validation by IP address | `008-scope-by-ip.md` |
| 9 | Python 3.10 forward compatibility | `009-python-version.md` |
| 10 | Lab client container for host-to-container DNS | `010-lab-client-container.md` |
