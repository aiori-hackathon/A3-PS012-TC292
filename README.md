<!-- logo:begin -->
<div align="center">
  <img src="media\logo.png" alt="Binary Beans" width="500" style="max-width: 100%; height: auto; filter: drop-shadow(0 4px 6px rgba(0,0,0,0.1));">
</div>
<!-- logo:end -->

# Authorised DNS Resolver Exposure Assessment

A professional tool for the nonce-based classification of authorised lab resolvers. It proves recursion using a unique nonce and evidence from a dedicated authoritative test-zone server, ensuring that recursion is proven by actual query forwarding rather than inferred from the RA flag.

<!-- badges:begin -->
<div align="center">
  <a href="https://portal.aiori.in/aiori-3/hackathon-guideline/" target="_blank" rel="noopener"><img alt="AIORI 3 Hackathon" src="https://img.shields.io/static/v1?label=AIORI%203&amp;message=Hackathon&amp;color=C55E33&amp;labelColor=38454E&amp;style=for-the-badge"></a>
  <a href="https://portal.aiori.in/aiori-3/hackathon-guideline/" target="_blank" rel="noopener"><img alt="Problem statement PS-012" src="https://img.shields.io/static/v1?label=problem%20statement&amp;message=PS-012&amp;color=C55E33&amp;labelColor=38454E&amp;style=for-the-badge"></a>
  <a href="https://portal.aiori.in/aiori-3/hackathon-guideline/" target="_blank" rel="noopener"><img alt="Track 2 Cyber Security" src="https://img.shields.io/static/v1?label=track%202&amp;message=Cyber%20Security&amp;color=C55E33&amp;labelColor=38454E&amp;style=for-the-badge"></a>
  <br>
  <a href="https://docs.python.org/" target="_blank" rel="noopener"><img alt="Built with Python" src="https://img.shields.io/static/v1?label=built%20with&amp;message=Python&amp;color=3776AB&amp;labelColor=38454E&amp;style=for-the-badge&amp;logo=python&amp;logoColor=white"></a>
  <a href="https://docs.astral.sh/uv/" target="_blank" rel="noopener"><img alt="Managed with uv" src="https://img.shields.io/static/v1?label=managed%20with&amp;message=uv&amp;color=4B5563&amp;labelColor=38454E&amp;style=for-the-badge&amp;logo=uv&amp;logoColor=white"></a>
  <a href="deliverables/report.html" target="_blank" rel="noopener"><img alt="Report Verified" src="https://img.shields.io/static/v1?label=report%20verified&amp;message=20%2F20&amp;color=C55E33&amp;labelColor=5C8D8D&amp;style=for-the-badge"></a>
</div>
<!-- badges:end -->

| Name | Role | Link |
| :--- | :--- | :--- |
| Rwitabrato Hanpal | Team lead and core developer| [GitHub](https://github.com/GhostisLive) |
| Anushka Ghosh | Lab and validation | [GitHub](https://github.com/Code-0ne) |
| Prof (Dr) Rupayan Das | Faculty Mentor | [GitHub](https://github.com/rupayanacm-ai) |

**Team Name:** Binary Beans  
**Team Code:** A3-PS012-TC292  
**Presentation:** [`A3-PS012-TC292.pdf`](A3-PS012-TC292.pdf)

## Judge fast path

- [**Report (HTML)**](deliverables/report.html) — Self-contained results report with claims registry and drift checks
- [**Deck PDF**](A3-PS012-TC292.pdf) — Team presentation deck
- [**Quickstart**](#quickstart) — Prebuilt viewer or a full native build
- [**Honest limits**](#honest-limits) — Empirical measurements only; no formal guarantees

## Live demo

Three ways to review the working demo, fastest first:

1. **Recorded terminal replay (instant, no setup)** — [`deliverables/terminal-replay.html`](./deliverables/terminal-replay.html)
2. **Static deliverables (instant, no setup)** — the pre-generated demo artifacts are committed directly in [`deliverables/`](./deliverables)
3. **Run it yourself (manual setup)** — Install Docker and uv, then run:
   ```sh
   make demo
   ```

## Headline results

The tool achieved **20/20** agreement with the known seeded lab.

| Ground truth \ Predicted | Recursive | Authoritative-only | Refused | Inconclusive |
|---|---:|---:|---:|---:|
| Recursive | 10 | 0 | 0 | 0 |
| Authoritative-only | 0 | 4 | 0 | 0 |
| Refused | 0 | 0 | 3 | 0 |
| Inconclusive | 0 | 0 | 0 | 3 |

## Quickstart

The tool is a CLI that manages a 22-container lab environment.

### One-command demo
From the repository root, with Docker Desktop running:

```powershell
uv run --directory src python run_demo.py
```

The runner builds the Compose lab, scans from the dedicated client container, compares against ground truth, and generates reports under `src/out/`.

## Terminology (rubric ↔ implementation)

| Term | What it means here | Where it lives |
|---|---|---|
| **Canary query** | The **nonce query**: a unique 12-hex-nonce qname under `probe.lab.test`. | `prober.py::make_nonce` |
| **Canary evidence** | The auth-zone query log. Recursion is *proven* when the target's forwarded query reaches our zone. | `evidence.py`, `classifier.py` |
| **Canary server** | The team-owned **authoritative `authzone` container** for `probe.lab.test`. | `src/lab/authzone/` |
| **External probe client** | The dedicated **`lab-client` container**, on its own network. | `src/lab/docker-compose.yml` |
| **Control client** | The controlled `lab-client` used for canary attribution self-checks. | `selfcheck.py` |

## Repository map

- `src/` — Core implementation
  - `cli.py` — Command line interface
  - `prober.py` — DNS probing logic
  - `classifier.py` — Labeling logic based on evidence
  - `evidence.py` — Log parsing and evidence extraction
  - `lab/` — Dockerized lab environment
- `deliverables/` — Final reports and demo artifacts
- `tests/` — Unit and integration tests

## Honest limits

- **Emulated Targets**: The lab uses Python emulations of DNS behavior, not official BIND/Unbound images.
- **Network Isolation**: Assumes a controlled lab environment; real-world network noise may affect timing.
- **Scope**: Limited to the specific fixtures defined in the problem statement.
s Cand D produced `Inconclusive`. Two fixes removed that dependence:

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
