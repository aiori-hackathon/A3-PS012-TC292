# A3-PS012-TC292 — Authorised DNS Resolver Exposure Assessment

This project assesses DNS recursion only on listed, authorised targets. It
proves recursion using a unique nonce and evidence from the project's own
authoritative test-zone server; it does not infer exposure from the RA flag
alone. Never use it against systems you do not own or have explicit permission
to test.

## Terminology (rubric ↔ implementation)

The problem statement's vocabulary maps to the implementation as follows:

| Term | What it means here | Where it lives |
|---|---|---|
| **Canary query** | The **nonce query**: a unique 12-hex-nonce qname under `probe.lab.test`, sent per target. Deterministic from (seed, target, index) — re-runs produce the same names. | `prober.py::make_nonce`, every `evidence.jsonl` row |
| **Canary evidence** | The auth-zone query log. Recursion is *proven* when the target's forwarded query for the nonce name reaches our zone; matched **by nonce value, not source IP** (the recorded `src_ip` feeds `via_forwarder` detection). | `evidence.py::AuthZoneLogReader`, `classifier.py` |
| **Canary server** | The team-owned **authoritative `authzone` container** for `probe.lab.test` — it serves the zone and logs every query it receives. | `src/lab/authzone/`, `scope.yaml::test_zone` |
| **External probe client** | The dedicated **`lab-client` container**, on its own network: every probe leaves its real source IP, independent of the targets and the canary server. | `src/lab/docker-compose.yml`, `cli.py scan` |
| **Control client** | The controlled `lab-client` is the **only** traffic generator besides target healthchecks (which query each container's own loopback and never reach the canary log). Before every scan it also runs a **canary attribution self-check**: one control query (`selfcheck-…` qname) straight to the canary server must appear in the canary log attributed to the client's own src IP, or the scan refuses to run (`selfcheck.py`, `cli.py` Phase 0). **Structural controls** complete the picture: (1) the canary log is noise-free, so every entry is evidence; (2) the refused fixtures (t02, t04, t12) are *negative controls* — valid REFUSED replies whose nonces correctly never appear in the canary log; (3) probe B (SOA, RD=0) provides a second, independent signal so no label rests on a single query. | `selfcheck.py`, `docker-compose.yml` healthchecks, classifier reasons `both_probes_refused` |

The five pieces compose the core proof: the **external probe client** sends
the **canary query**, and only if the target genuinely recurses does the
**canary server** record **canary evidence**. For the full decision rules see
[`src/docs/pseudocode.md`](./src/docs/pseudocode.md) and the Limitations below.

## Live demo

Three ways to review the working demo, fastest first:

1. **Recorded terminal replay (instant, no setup)** —
   [`deliverables/terminal-replay.html`](./deliverables/terminal-replay.html)
   replays real recordings of the full demo run (scan → compare → 20/20 →
   reports), the rate-verification capture, and the kill switch stopping a
   scan cleanly, with play/pause/scrub controls and no external dependencies.
2. **Static deliverables (instant, no setup)** — the pre-generated demo
   artifacts are committed directly in [`deliverables/`](./deliverables) for
   evaluator review (open the files locally; the landing page is
   `deliverables/index.html`). It links `report.html`, `results.json`,
   `results.csv`, the full probe `evidence.jsonl`, and the rate-verification
   capture.
3. **Run it yourself (manual setup)** — the tool is a CLI, so this is the
   genuinely interactive option. Install the two prerequisites, then run:

   - [Docker Engine or Docker Desktop](https://docs.docker.com/get-docker/)
     (the 22-container lab needs a working Docker daemon: 20 targets,
     the test-zone canary server, and the separate client), and
   - [uv](https://docs.astral.sh/uv/getting-started/installation/)
     (`curl -LsSf https://astral.sh/uv/install.sh | sh`).

   ```sh
   make lab-up      # or let make demo do this
   make demo        # lab up -> scan -> compare -> reports
   ```

   (without Make: `uv run --directory src python run_demo.py`, which is
   exactly what `make demo` invokes)

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

### How long a run takes

One full demo takes **about 25–30 seconds** of lab time (plus the one-off
image build). Most targets finish in milliseconds, and the slower parts are
expected, not a hang:

- t13 (drop-everything fixture) times out at 3 s per attempt, with up to
  3 attempts per probe (`max_queries_per_target`: 3) — up to ~9 s per probe.
- The scan polls the auth-zone log for up to `--log-wait` seconds (default 6)
  for nonce evidence that never arrives (t13, t17); that adds up to ~6 s.
- Every query otherwise waits on the 1 qps per-target limiter, so 20 targets
  × 2 probes take their share of the 5 qps global budget.

This duration grew from ~17 s in earlier versions when UDP retries and the
polling `--log-wait` replaced a fixed 2 s sleep; the increase is the corrected
retry policy and the configurable evidence wait, not added load. Lower
`--log-wait` (e.g. `--log-wait 2`) shortens a run at the risk of missing late
log entries.

### What the lab is (and is not)

The 20 target containers are **Python emulations that reproduce the query
behaviour of common DNS software** (an open / closed / authoritative-only /
forwarding resolver, a packet dropper, a truncating server, a rate limiter,
etc. — the t0* fixture names reference those behaviours). They are **not**
official BIND, Unbound, NSD, Knot, or PowerDNS container images. Validating
the classifier against real upstream images is explicitly future work; the
tool itself only speaks standard DNS either way.

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

Three scans using `seed-A` agreed on all **20/20 labels**. Four further scans
with different seeds (A–D) also each scored **20/20**, including t19.

Those earlier observations are reproduced on a later code state in
[`deliverables/stability-summary.json`](./deliverables/stability-summary.json):
three consecutive runs with seed `stab-A` plus one run with seed `stab-B`
produced **identical labels for all 20 targets**, with probe attempts of 1
everywhere except the timeout-modeled t13 (3, the configured cap).

| Seed | t19 packet-loss | t19 UDP attempts | t13 attempts (timeout model) |
|---|---|---|---|
| `seed-A` | Recursive | 1 | 3 |
| `seed-B` | Recursive | 1 | 3 |
| `seed-C` | Recursive | 2 (retry recovered) | 3 |
| `seed-D` | Recursive | 2 (retry recovered) | 3 |

Earlier versions of the tool sent each UDP probe once, so t19's
deterministic (nonce-keyed) loss made its label depend on the seed: seeds C
and D produced `Inconclusive`. Two fixes removed that dependence:

1. The prober now retries a timed-out UDP probe up to `udp_retries` times
   (`rate.yaml`, default 2), re-waiting on the rate limiter and reusing the
   same qname and nonce so the auth-zone log still correlates.
2. The t19 fixture models *transient* loss: the first packet per query name
   is dropped deterministically (30% band), while a retry of the same name
   is always forwarded.

t15 stayed Recursive in these runs: the configured per-target limiter sent
too few requests to reach its five-queries-per-five-seconds threshold. Its
fast responses do **not** show that the rate-limit behavior was exercised.

## Rate-limit verification

With the lab running, capture the DNS requests and compare them to the caps in
`src/config/rate.yaml`:

```powershell
uv run --directory src python verify_rate.py
```

Equivalent Make target when Make is available: `make verify-rate`. The latest
capture (after adding retries) passed with **5 qps peak globally** (cap 5) and
**1 qps peak per target** (cap 1); 30 DNS questions were captured (29 probe
queries plus the one canary self-check control query). Retries wait on the
same rate limiter and count toward the `max_queries_per_target` and
`max_total_queries` budgets, which the scan enforces before every query.

## Limitations

- Results establish consistency only for these known lab cases, not general
  accuracy on arbitrary production servers.
- A server that hosts an authoritative zone while refusing recursion can
  appear `Authoritative-only` when that zone's probe gets an authoritative
  answer. Keep ground truth consistent with the server's actual configuration.
- A rate-limited server may not expose its drop behavior unless a run reaches
  its threshold. Do not exceed configured probe limits just to force a result.
- Recursion proof is polled from the test-zone log for up to `--log-wait`
  seconds (default 6) instead of a fixed sleep, but log delivery beyond that
  window can still leave a recursive resolver `Inconclusive`.
- The report's config hash covers `scope.yaml` and `rate.yaml`, not the Docker
  target fixtures or ground-truth file.
- Abstract slide 6 lists two "further enhancements". The packet-capture rate
  verification is done (`make verify-rate`). The second one, a fix-and-rescan
  step showing a `Recursive` server turning `Refused`, is deliberate future
  work: it needs an opt-in lab toggle so a scan can flip one fixture's policy
  and re-run safely, without ever touching the authorisation boundaries.

For detailed Phase 4 usage, see [src/README.md](./src/README.md). The short
implementation outline is [src/docs/pseudocode.md](./src/docs/pseudocode.md).
