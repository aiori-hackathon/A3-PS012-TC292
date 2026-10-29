# A3-PS012-TC292 — Authorised DNS Resolver Exposure Assessment

This project assesses DNS recursion only on listed, authorised targets. It
proves recursion using a unique nonce and evidence from the project's own
authoritative test-zone server; it does not infer exposure from the RA flag
alone. Never use it against systems you do not own or have explicit permission
to test.

## One-command demo

From the repository root, with Docker Desktop running:

```powershell
uv run --directory src python run_demo.py
```

The runner builds and waits for the Compose lab, scans from the dedicated
client container, compares against the seeded ground truth, prints the
confusion matrix, and generates JSON, CSV, and HTML reports under `src/out/`.
It stops and returns a failure status if any step fails.

If GNU Make is installed, `make demo` invokes the same `uv`-managed runner.
Run unit and lab tests with:

```powershell
uv run pytest
```

## Corrected lab results

The first lab run scored **19/20**. The mismatch was t02: the supposedly
closed resolver also hosted an authoritative zone, so the SOA probe received
an authoritative answer and the classifier returned `Authoritative-only`. We
corrected the fixture by removing that zone and keeping recursion limited to
localhost. Both probes now receive `REFUSED`; the corrected seeded run scored
**20/20**.

| Ground truth \ Predicted | Recursive | Authoritative-only | Refused | Inconclusive |
|---|---:|---:|---:|---:|
| Recursive | 10 | 0 | 0 | 0 |
| Authoritative-only | 0 | 4 | 0 | 0 |
| Refused | 0 | 0 | 3 | 0 |
| Inconclusive | 0 | 0 | 0 | 3 |

This is agreement with the known seeded lab, not proof the tool is perfect on
other DNS deployments.

### Repeat-run observations

Three scans using `seed-A` agreed on all **20/20 labels**. Three further scans
with different seeds produced:

| Seed | t15 rate-limited | t19 packet-loss |
|---|---|---|
| `seed-B` | Recursive (10.35 ms) | Recursive (5.24 ms) |
| `seed-C` | Recursive (10.26 ms) | Inconclusive (timeout, 3003.75 ms) |
| `seed-D` | Recursive (6.63 ms) | Inconclusive (timeout, 3003.59 ms) |

t19's deterministic 30% packet loss is keyed by the nonce, so changing the
seed can determine whether a query is dropped. t15 stayed Recursive in these
runs because the configured per-target limiter sent too few requests to hit
its five-queries-per-five-seconds threshold. Its fast responses do **not**
show that the rate-limit behavior was exercised.

## Rate-limit verification

With the lab running, capture the DNS requests and compare them to the caps in
`src/config/rate.yaml`:

```powershell
uv run --directory src python verify_rate.py
```

Equivalent Make target when Make is available: `make verify-rate`. The latest
capture passed with **5 qps peak globally** (cap 5) and **1 qps peak per
target** (cap 1); 27 DNS questions were captured.

## Limitations

- Results establish consistency only for these known lab cases, not general
  accuracy on arbitrary production servers.
- A server that hosts an authoritative zone while refusing recursion can
  appear `Authoritative-only` when that zone's probe gets an authoritative
  answer. Keep ground truth consistent with the server's actual configuration.
- A rate-limited server may not expose its drop behavior unless a run reaches
  its threshold. Do not exceed configured probe limits just to force a result.
- Classification depends on timely test-zone logs; delayed or missing log
  entries can leave a recursive resolver `Inconclusive`.
- The report's config hash covers `scope.yaml` and `rate.yaml`, not the Docker
  target fixtures or ground-truth file.

For detailed Phase 4 usage, see [src/README.md](./src/README.md). The short
implementation outline is [src/docs/pseudocode.md](./src/docs/pseudocode.md).
