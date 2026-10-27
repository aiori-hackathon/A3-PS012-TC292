# Build Prompt: Authorised DNS Resolver Exposure Assessment (AIORI-3, PS-012)

Paste everything below into your coding agent (Claude Code, Cursor, etc.) from an empty repository named `A3-PS012-TC292`.

---

## 0. Your role and rules of work

You are a senior security engineer building a hackathon project end to end. Build it in the phases in section 12. After each phase, run the tests, fix failures, and commit with a clear message. Do not tell me a phase is done until you have run it and shown the output.

Coding style (important):
- Python 3.11, **simple and readable code**. Small functions, plain dicts and dataclasses, minimal abstractions, short comments that explain why.
- No heavy frameworks. Allowed libraries: `dnspython`, `PyYAML`, `Jinja2`, `pytest`, `pandas` only if it really simplifies the report (prefer plain Python).
- Every module gets a short docstring. Every public function gets type hints.

Do not ask me questions. Where something is unspecified, choose the simplest reasonable option and note it in `docs/decisions.md`.

---

## 1. Project summary

**Team:** Binary Beans, IEM Kolkata. **Team ID:** A3-PS012-TC292.
**Problem:** PS-012, Authorised DNS Resolver Exposure Assessment (Cybersecurity).

Open recursive DNS resolvers can be abused as reflectors in DDoS amplification attacks, and operators rarely know which of their servers are exposed. Common checks (a single `dig`, or the RA flag) can mislead, especially with forwarders and fake resolvers.

**Build:** a safe, reproducible command-line tool that assesses **up to 20 authorised DNS servers** from a separate client machine and classifies each as:

- `Recursive` (resolves names for outside clients: exposed)
- `Authoritative-only` (answers for its own zone, does not recurse)
- `Refused` (refuses queries from this client)
- `Inconclusive` (cannot be decided; a reason is always stored)

**Key idea (the differentiator):** prove recursion instead of inferring it from flags. The tool queries each target for a **unique random name (nonce) inside a test zone we control**. Our own authoritative server for that zone logs every query it receives. If the nonce appears in that log, the target genuinely performed recursion. Match on the **nonce, not the source IP**, so forwarders are handled correctly.

**Validation:** a Docker Compose lab of 20 seeded servers with a `ground_truth.yaml`. The tool's labels are compared with ground truth to produce a confusion matrix and an error analysis.

Non-goals (never implement these): internet-wide scanning, IP spoofing, amplification or stress testing, `ANY` queries, oversized EDNS, probing anything outside the scope file.

---

## 2. Repository layout

```
A3-PS012-TC292/
  README.md
  Makefile
  pyproject.toml
  requirements.txt
  src/config/
    scope.yaml            # authorised targets (max 20)
    rate.yaml             # rate limits and query caps
  src/lab/
    docker-compose.yml
    authzone/             # our test-zone authoritative server (logs queries)
    targets/              # one folder per target config
    ground_truth.yaml
  src/dnsassess/
    __init__.py
    cli.py                # argparse entry point
    config.py             # load and validate yaml
    safety.py             # SafetyGate + kill switch
    ratelimit.py          # token bucket
    prober.py             # nonce, UDP/TCP queries
    evidence.py           # EvidenceStore (JSONL) + auth log reader
    classifier.py         # classify(evidence) -> label + reason
    comparator.py         # confusion matrix + error causes
    report.py             # JSON, CSV, HTML
    templates/report.html.j2
  src/tests/
    test_classifier.py
    test_ratelimit.py
    test_safety.py
    test_nonce.py
    test_integration_lab.py
  src/docs/
    architecture.md       # UML + DFD descriptions (mermaid)
    decisions.md
    pseudocode.md
  src/demo/
    run_demo.sh
```

All application source code lives under `src/` — the `dnsassess` package in `src/dnsassess/` holds every Python module (`cli.py`, `config.py`, `safety.py`, `ratelimit.py`, `prober.py`, `evidence.py`, `classifier.py`, `comparator.py`, `report.py`) plus the Jinja2 template. No source files live at the repository root; `config/`, `lab/`, `tests/`, `docs/` and `demo/` hold configuration, lab fixtures, tests, documentation and the demo script respectively.
```



## 3. Configuration files

### `config/scope.yaml`
Every target must be listed. Probing anything not listed is impossible by design.

```yaml
authorisation:
  owner: "Team Binary Beans lab"
  authorised_by: "Prof (Dr) Rupayan Das"
  authorised_on: "2026-10-16"
  statement: "All listed servers are lab containers owned by the team."
test_zone: "probe.lab.test"
test_zone_ip: "172.28.0.10"        # our authoritative server
targets:                            # at most 20 entries
  - id: t01
    name: bind-open
    ip: 172.28.0.101
    serves_zone: "owned.t01.lab.test"   # zone this target is authoritative for, if any
  # ... t02 to t20
```

### `config/rate.yaml`
```yaml
global_qps: 5            # queries per second across all targets
per_target_qps: 1
max_queries_per_target: 3   # includes retries and TCP fallback
timeout_seconds: 2.0
max_total_queries: 80
edns_payload: 1232         # never larger
```

---

## 4. Components (match these names; they appear in our architecture diagram)

1. **Config / CLI** (`cli.py`, `config.py`): commands `scan`, `compare`, `report`, `demo`. Flags: `--scope`, `--rate`, `--out`, `--seed`. Validate yaml and fail loudly with clear messages.
2. **SafetyGate** (`safety.py`):
   - `check_scope(target)`: refuse any IP not in `scope.yaml`.
   - `enforce_max_20(targets)`: abort if more than 20.
   - `kill_switch()`: returns True if the file `./KILL` exists, or `SIGINT` was received, or `max_total_queries` is reached. Checked before every query. On trigger, stop cleanly and save partial evidence.
   - Refuse to run if the `authorisation` block is missing or incomplete.
3. **RateLimiter** (`ratelimit.py`): token bucket, one global bucket plus one per target. `wait(target_id)` blocks until a token is available. Track queries sent per target and enforce `max_queries_per_target`.
4. **Prober** (`prober.py`, uses `dnspython`):
   - `make_nonce(seed)`: 12-char lowercase hex, unique per probe; query name is `<nonce>.probe.lab.test`.
   - `send_udp(...)` then `tcp_retry(...)` only if the UDP reply has the TC flag.
   - Probe A (recursion probe): `A` query for the nonce name with `RD=1`.
   - Probe B (zone probe): `SOA` query for the target's `serves_zone` with `RD=0`. This tells Authoritative-only apart from Refused.
   - Record flags (`QR, AA, TC, RD, RA`), `rcode`, answer data, response time, transport used.
   - Never send `ANY`, never set EDNS payload above `edns_payload`.
5. **EvidenceStore** (`evidence.py`): append one JSON line per probe to `out/evidence.jsonl`. Also reads the test-zone server's query log (`lab/authzone/logs/queries.jsonl`) and indexes it by nonce.
6. **Classifier** (`classifier.py`): rules in section 6. Returns `{label, reason, evidence_ids}`.
7. **Comparator** (`comparator.py`): confusion matrix, per-class precision and recall, list of every mismatch with a root-cause category.
8. **ReportGenerator** (`report.py`): JSON, CSV and HTML with remediation text based on RFC 5358 (BCP 140): restrict recursion to intended clients with access control lists, and block outside access to recursive service.
9. **Target DNS servers** and **Test-zone server**: the lab, section 5.

---

## 5. Lab (Docker Compose)

Two networks: `client_net` (the probing client) and `lab_net` (targets and the test-zone server). The client container reaches targets through published static IPs in `172.28.0.0/24`. Use static IPs so scope and ground truth stay stable.

**Test-zone authoritative server** (`lab/authzone/`): a tiny Python server (using `dnspython` message parsing over UDP and TCP, or `dnslib`) that:
- is authoritative for `probe.lab.test`;
- answers **any** name under it with an `A` record `192.0.2.1` (documentation range) and `AA=1`;
- appends one JSON line per query to `queries.jsonl`: `{ts, qname, qtype, src_ip, nonce}` where `nonce` is the leftmost label.

**Making recursion reach our zone:** every recursive target must be configured to send queries for `probe.lab.test` to the test-zone server (stub zone or forward zone). Document this per resolver in its config. Without this, no recursive target can ever show a nonce in our log.

**20 seeded targets** with their expected labels (write them into `lab/ground_truth.yaml`):

| ID | Setup | Expected label |
|----|-------|----------------|
| t01 | BIND, recursion yes, allow-recursion any | Recursive |
| t02 | BIND, allow-recursion limited to localhost | Refused |
| t03 | Unbound, access-control allow all | Recursive |
| t04 | Unbound, access-control refuse for client range | Refused |
| t05 | Knot Resolver, open | Recursive |
| t06 | dnsmasq with upstream set to the test-zone server | Recursive |
| t07 | NSD authoritative for its own zone | Authoritative-only |
| t08 | Knot DNS authoritative | Authoritative-only |
| t09 | PowerDNS Authoritative | Authoritative-only |
| t10 | PowerDNS Recursor, open | Recursive |
| t11 | Forwarder to an open upstream resolver (nonce arrives from the upstream IP) | Recursive |
| t12 | Forwarder to a closed upstream | Refused |
| t13 | Firewall drops all traffic from the client | Inconclusive (timeout) |
| t14 | Always answers SERVFAIL (small Python server) | Inconclusive (SERVFAIL) |
| t15 | Rate-limited: answers first N queries then drops | Inconclusive (rate limit) or Recursive if answered in time |
| t16 | Truncates UDP replies, full answer over TCP, open recursion | Recursive (needs TCP fallback) |
| t17 | "Lying" resolver: sets RA=1 and returns an A record without ever contacting our zone | Inconclusive (RA set, no nonce seen) |
| t18 | High latency (about 1.5 s delay) but open | Recursive (tests timeout and retry) |
| t19 | Random 30% packet loss, open | Recursive or Inconclusive; document expected behaviour |
| t20 | Authoritative for owned zone, refuses everything else | Authoritative-only |

For t13, t15, t17, t18 and t19 use small Python fake servers or `iptables`/`tc netem` inside the container (add `cap_add: [NET_ADMIN]`). Keep these simple and documented.

`make lab-up` starts everything and waits until all 20 targets answer at least a health check. `make lab-down` tears it down.

---

## 6. Classification rules (implement exactly, in this order)

Inputs per target: results of Probe A (recursion probe), Probe B (zone probe), and the auth-log entries for that probe's nonce.

1. No response to any probe after retries and TCP fallback → `Inconclusive`, reason `timeout`.
2. Probe A returned `SERVFAIL`, a malformed packet, or an unexpected rcode with no other evidence → `Inconclusive`, reason `servfail` or `bad_reply`.
3. Probe A answered `NOERROR` with the expected `A` record **and** the nonce appears in the auth log within the time window → `Recursive`. Record `via_forwarder: true` if the log's `src_ip` differs from the target IP. Do not require equal IPs.
4. Probe A answered but the nonce is **not** in the auth log (even if `RA=1`) → `Inconclusive`, reason `answer_without_upstream_evidence` (fake resolver, cache, or log delay). Re-check the log once after a short wait before deciding.
5. Probe A returned `REFUSED` and Probe B returned `REFUSED` (or no answer from a closed ACL) → `Refused`.
6. Probe B returned an answer with `AA=1` and Probe A was `REFUSED`, no answer, or `NXDOMAIN` without nonce evidence → `Authoritative-only`.
7. Anything else → `Inconclusive`, reason `conflicting_evidence`, with the raw flags and rcodes stored.

Every result stores: `label`, `reason`, flags and rcodes for both probes, transport used, latency, nonce, whether the nonce was seen, and `via_forwarder`.

---

## 7. Comparator and error analysis

- Read `lab/ground_truth.yaml` and the tool output.
- Build a 4x4 confusion matrix (rows: truth, columns: predicted).
- Print accuracy, plus precision and recall per class.
- For each mismatch write one line with a cause category from this fixed list: `rate_limit`, `packet_loss`, `timeout_too_short`, `log_delay`, `rule_gap`, `config_error_in_lab`, `other`. Add a one-sentence explanation. Goal: **every miss has a documented root cause**.

---

## 8. Reports

`dnsassess report` writes to `out/`:
- `results.json` (full evidence per target),
- `results.csv` (one row per target: id, name, ip, label, reason, via_forwarder, latency_ms),
- `report.html` (Jinja2, no external assets): summary counts, per-target table with colour-coded labels, confusion matrix, error analysis, and for each `Recursive` target a remediation box: "Restrict recursion to intended clients with an access control list (RFC 5358 / BCP 140)".

Include the run metadata in every report: tool version, seed, config hash (sha256 of both yaml files), start and end time.

---

## 9. Safety requirements (acceptance-critical)

- No target outside `scope.yaml` is ever contacted. Add a test that tries one and expects a refusal.
- At most 20 targets. Add a test with 21 and expect an abort.
- No more than `max_queries_per_target` queries to a target. Add a test.
- Rate limits verified. Preferred: capture the client's traffic with `tcpdump` during a full run (`make verify-rate`) and print the observed peak queries per second per target and globally. It must stay at or below the configured caps.
- Kill switch: creating the file `KILL` mid-run stops the scan within one query, and partial evidence is saved. Add a test.
- Only `A` and `SOA` queries, EDNS payload at most 1232, source address is the real client address.
- README has a "Responsible use" section: only run against servers you own or are explicitly authorised to test.

---

## 10. Tests

`pytest` must pass without Docker for unit tests. Required:
- `test_classifier.py`: one fixture per rule branch (at least 10 cases, including a forwarder case where the log's `src_ip` differs from the target).
- `test_ratelimit.py`: token bucket honours global and per-target rates (use a fake clock).
- `test_safety.py`: out-of-scope refusal, 21 targets abort, missing authorisation abort, kill switch.
- `test_nonce.py`: nonces are unique, lowercase hex, and reproducible from a seed.
- `test_integration_lab.py`: marked `@pytest.mark.lab`, runs only when the lab is up; asserts overall accuracy on the lab is at least 90% and that every mismatch has a cause.

---

## 11. Demo and optional enhancements

**One-command demo:** `make demo` runs: lab up, scan, compare, report, then prints the confusion matrix and the path to `out/report.html`. It must work from a clean clone with only Docker and Python installed.

**Optional enhancements (do after the core works):**
1. Fix-and-rescan: `make fix-demo` changes t01 (BIND) to restrict recursion, rescans, and shows `Recursive` turning into `Refused` in a before/after table.
2. Packet-capture rate verification as described in section 9.
3. Three repeated runs with the same seed; verify labels agree across runs and print a stability line.

---

## 12. Phases (follow in order)

| Phase | Dates (plan) | Deliverable | Done when |
|-------|--------------|-------------|-----------|
| 1 Lab and ground truth | 16-19 Oct | Compose lab, test-zone server, 20 targets, `ground_truth.yaml` | `make lab-up` starts all 20 targets; a manual probe shows up in the test-zone log |
| 2 Prober and safety | 20-23 Oct | Prober, SafetyGate, RateLimiter, kill switch, unit tests | A full 20-target run stays inside the rate caps |
| 3 Classifier and comparator | 24-27 Oct | Rules, confusion matrix, error analysis | Every miss has a documented root cause |
| 4 Reports and verification | 28-29 Oct | JSON, CSV, HTML, packet-capture check, 3 repeat runs | Labels agree across the three runs |
| 5 Demo and submission | 30-31 Oct | `make demo`, README, `docs/pseudocode.md`, code freeze | An evaluator can reproduce the demo from the repository |

If today's date is already past a phase start, do the phases in order but faster; do not skip the safety work.

---

## 13. Documentation to produce

- `README.md`: problem, approach (nonce proof of recursion), architecture diagram (mermaid), quick start (`make demo`), results table, safety and responsible-use section, limitations.
- `docs/architecture.md`: mermaid class diagram with components 1-10 (Config/CLI, SafetyGate, RateLimiter, Prober, Target DNS servers, Test-zone server, EvidenceStore, Classifier, Comparator, ReportGenerator) and a mermaid data flow diagram (Operator, Lab DNS targets, Test-zone server; processes: validate config, schedule, send probes, correlate with zone log, classify, compare, build report; stores: scope and rate config, evidence log, ground truth, results and reports).
- `docs/pseudocode.md`: a short pseudocode of the core loop, for the hackathon submission:

```
for target in scope.targets:
    gate.check(target)                      # scope, max 20, kill switch
    nonce = make_nonce(seed)
    a = probe_A(target, nonce)              # recursive query, rate limited
    b = probe_B(target)                     # zone SOA, RD=0
    log = auth_log.find(nonce)              # did our own server see the nonce?
    label, reason = classify(a, b, log)
    store(target, a, b, log, label, reason)
compare(results, ground_truth)              # confusion matrix, error causes
write_reports(results)
```

- `docs/decisions.md`: every assumption you made.

---

## 14. Definition of done

- [ ] `make lab-up && make demo` works from a clean clone.
- [ ] All unit tests pass; lab integration test passes with at least 90% accuracy.
- [ ] Every mismatch has a documented root cause.
- [ ] Safety tests pass (scope, max 20, query cap, kill switch).
- [ ] Observed query rate is at or below the configured limits (shown by `make verify-rate`).
- [ ] README, architecture, pseudocode and decisions docs are complete.
- [ ] Repository is named `A3-PS012-TC292`.

Start with Phase 1 now. Show me the lab running before moving on.
