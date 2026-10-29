# DNS Resolver Exposure Assessment

This authorized lab tool classifies DNS resolvers using nonce-based proof of
recursion. Run it only against systems you own or are explicitly authorized to
test.

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
`verify-stability` runs three scans with the same seed and fails if any target's
label changes. The packet-loss fixture is deterministic for each nonce, and
the rate-limited fixture uses a rolling time window so repeated runs can be
compared.

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
across three scans**. Three additional scans with different seeds showed:

| Seed | t15 rate-limited | t19 packet-loss |
|---|---|---|
| `seed-B` | Recursive (10.35 ms) | Recursive (5.24 ms) |
| `seed-C` | Recursive (10.26 ms) | Inconclusive (timeout, 3003.75 ms) |
| `seed-D` | Recursive (6.63 ms) | Inconclusive (timeout, 3003.59 ms) |

t19's deterministic 30% loss is keyed by the nonce, so changing the seed can
change whether that probe is dropped. t15 stayed Recursive in these runs:
the configured per-target limiter sent too few requests to exceed t15's
five-queries-per-five-seconds threshold. These runs therefore do **not** claim
to have exercised t15's drop behavior.

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
- Recursion proof depends on receiving and correlating the test-zone log in
  time. Delayed or missing log entries can leave a genuinely recursive target
  `Inconclusive`.
- The report's config hash covers `scope.yaml` and `rate.yaml`, not Docker
  fixture files such as target server configs or `ground_truth.yaml`.
