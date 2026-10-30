# DNS Resolver Exposure Assessment

This authorized lab tool classifies DNS resolvers using nonce-based proof of
recursion. Run it only against systems you own or are explicitly authorized to
test.

## Terminology

- **Canary query** — the per-target unique nonce query under `probe.lab.test`
  (`prober.py`).
- **Canary evidence** — the auth-zone query log; recursion is proven when the
  nonce appears there, matched by nonce value, not source IP (`evidence.py`,
  `classifier.py`).
- **Canary server** — the team-owned authoritative `authzone` container serving
  the test zone and logging every query (`src/lab/authzone/`).
- **External probe client** — the dedicated `lab-client` container on its own
  network; all probes leave its real source IP.
- **Control client** — the same `lab-client`: it is the only traffic source
  besides target-local healthchecks (which never touch the canary log), and the
  refused fixtures provide negative controls whose nonces never appear. Every
  scan starts with a **canary attribution self-check** (`selfcheck.py`): one
  control query must reach the canary log attributed to the client's own src IP
  or the scan refuses to run — see the control self-check record in
  `evidence.jsonl` and `run_metadata.canary_selfcheck`.

## One-command demo

From the repository root:

```sh
uv run --directory src python run_demo.py
```

This builds and starts the Docker lab, waits for its services, scans the
authorized targets from the dedicated lab client, compares results with
ground truth, prints the confusion matrix and metrics, and generates the JSON,
CSV, and HTML reports. It stops and returns a failure status if any step fails.
The lab has 20 targets. Reports are written under `src/out/`.

One full run takes about **25–30 seconds** of lab time after the images are
built; the wait is dominated by the intentional timeout fixture (t13, 3 s per
attempt, up to 3 attempts) and the auth-zone log poll (`--log-wait`, default
6 s), plus the 1 qps per-target limiter. Every query waits on the limiter, so
a rate-limited scanner simply takes time — it has not hung.

The 20 target containers are **Python emulations reproducing the query
behaviour of common DNS software** (open/closed resolvers, authoritative-only,
forwarder, packet dropper, truncation, rate limiter, liar, and so on) — they
are *not* official BIND/Unbound/NSD/Knot/PowerDNS images. Validating against
real upstream images is future work; the tool speaks standard DNS regardless.

If GNU Make is installed, `make demo` runs the same command using `uv`.

## Phase 4 verification

Rebuild the lab before verification when Docker images or lab fixtures change:

```sh
docker compose -f src/lab/docker-compose.yml up -d --build --force-recreate
uv run --directory src python verify_rate.py
docker exec lab-client python3 -m dnsassess.cli verify-stability --scope /app/config/scope.yaml --rate /app/config/rate.yaml --out /app/out/stability --seed phase4-stability --auth-log /var/log/authzone/queries.jsonl --runs 3
```

`verify-rate` captures DNS requests from the lab client with `tcpdump` and
checks the configured global, per-target, and per-target query-count limits.
UDP timeout retries wait on the same limiter and count toward the caps.
`verify-stability` runs three scans with the same seed and fails if any target's
label changes. The packet-loss fixture drops only the first packet per query
name (deterministically), and the rate-limited fixture uses a rolling time
window so repeated runs can be compared.

The reports include JSON evidence, a per-target CSV, and an HTML summary with
run metadata, a confusion matrix, mismatch analysis, and remediation guidance.

## Lab results and error analysis

The first lab run scored **19/20**. Its one mismatch was t02: the supposedly
closed resolver also hosted an authoritative zone, so the zone probe returned
an authoritative answer and the classifier correctly chose
`Authoritative-only`. We corrected the lab fixture by removing that zone and
keeping recursion limited to localhost. Both probes now receive `REFUSED`,
and the corrected lab scored **20/20**.

The corrected seeded run's confusion matrix (rows are ground truth; columns
are predictions):

| Truth \ Predicted | Recursive | Authoritative-only | Refused | Inconclusive |
|---|---:|---:|---:|---:|
| Recursive | 10 | 0 | 0 | 0 |
| Authoritative-only | 0 | 4 | 0 | 0 |
| Refused | 0 | 0 | 3 | 0 |
| Inconclusive | 0 | 0 | 0 | 3 |

Same-seed testing with `seed-A` produced identical labels for **20/20 targets
across three scans**. Four scans with other seeds (`seed-A` through `seed-D`)
each scored **20/20**; t19 packet-loss needed its configured UDP retry in two
of them (2 attempts instead of 1) and stayed `Recursive`. Earlier one-shot
probing made t19's nonce-keyed deterministic loss seed-dependent; the UDP
retries (`udp_retries` in `rate.yaml`) plus the transient-loss fixture
removed that dependence.

t15 stayed Recursive in these runs: the configured per-target limiter sent
too few requests to exceed t15's five-queries-per-five-seconds threshold.
These runs therefore do **not** claim to have exercised t15's drop behavior.

`verify-rate` re-verifies the caps: the latest capture passed with a 5 qps
global peak (cap 5) and 1 qps per target (cap 1) across 29 DNS questions,
including every retry.

## Limitations

- The 20/20 result demonstrates agreement on this known, seeded lab; it does
  not establish accuracy on arbitrary production DNS deployments.
- A server that is authoritative for a zone and refuses recursion can look
  like `Authoritative-only` when the zone probe receives an authoritative
  answer. The classifier cannot infer the server's intended role from that
  response alone; keep the lab ground truth and server configuration aligned.
- Rate-limited servers may return different evidence depending on query
  history and configured limits. Respect the configured rate caps; a run that
  does not exceed a fixture's threshold has not tested its drop behavior.
- Recursion proof is polled from the test-zone log for up to `--log-wait`
  seconds (default 6) instead of a fixed sleep, but log delivery beyond that
  window can still leave a genuinely recursive target `Inconclusive`.
- The report's config hash covers `scope.yaml` and `rate.yaml`, not Docker
  fixture files such as target server configs or `ground_truth.yaml`.

#Team Introduction Video
Link -> https://youtu.be/d-ecCpZZQyw