# Decision 002 — DNS library: dnspython vs dnslib

## Decision
Use **dnspython** (v2.x) for all DNS message construction and UDP/TCP queries.

## Alternatives considered
- **dnspython** (chosen).
- **dnslib** — a lighter pure-Python DNS library.

## Why dnspython
- The build prompt's allowed-libraries list explicitly names `dnspython` and
  describes the prober in terms of dnspython concepts
  (`dns.message.make_query`, `dns.query.udp`, flags, rcode).
- dnspython exposes the DNS header flags (`QR, AA, TC, RD, RA`), rcodes, and
  EDNS control directly, which the classifier needs to implement its rules
  exactly as written (e.g. "Probe A returned SERVFAIL", "RA=1", "TC flag").
- dnspython is mature, well-documented, and already available on PyPI.

## Trade-offs
- dnspython is a heavier dependency than dnslib, but it is an allowed library
  and the feature surface we need (flags, rcode, EDNS payload cap, TCP/UDP)
  is idiomatic there.
