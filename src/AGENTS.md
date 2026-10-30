# AGENTS.md — A3-PS012-TC292 DNS Resolver Exposure Assessment

## Source of truth
`src/PS012_BUILD_PROMPT.md` is the authoritative build spec — repo layout, commands, safety rules, classification rules, tests, and phase order. Read it before writing code. The root `README.md` and `A3-PS012-TC292.pdf` are a team intro/slide deck, not implementation guidance.

## Project Overview
DNS resolver exposure assessment tool for AIORI-3 hackathon. Classifies up to 20 authorised DNS servers as Recursive, Authoritative-only, Refused, or Inconclusive using nonce-based recursion proof (not flag inference).

## Key Commands
```
make lab-up          # Start Docker lab (20 targets + test-zone server)
make lab-down        # Tear down lab
make demo            # Full run: lab-up → scan → compare → report → print matrix
make verify-rate     # Capture traffic, verify query rates ≤ config caps
uv run pytest        # Unit tests (no Docker required)
uv run pytest -m lab # Integration test (requires lab running)
```

## Repository Structure
```
A3-PS012-TC292/
├── Makefile                 # All commands above
├── pyproject.toml / requirements.txt
├── src/
│   ├── config/              # scope.yaml, rate.yaml (authorised targets, limits)
│   ├── lab/                 # docker-compose.yml, authzone/, targets/, ground_truth.yaml
│   ├── dnsassess/           # Python package (all source code)
│   │   ├── cli.py           # Commands: scan, compare, report, demo
│   │   ├── config.py        # YAML loading/validation
│   │   ├── safety.py        # SafetyGate: scope check, max 20, kill switch (./KILL file)
│   │   ├── ratelimit.py     # Token bucket (global + per-target)
│   │   ├── prober.py        # Nonce gen, UDP/TCP queries, A+SOA probes
│   │   ├── evidence.py      # JSONL evidence + auth-zone log reader
│   │   ├── classifier.py    # Rules from build prompt §6
│   │   ├── comparator.py    # Confusion matrix + error causes
│   │   ├── report.py        # JSON, CSV, HTML (Jinja2)
│   │   └── templates/report.html.j2
│   ├── tests/               # Unit + integration tests
│   ├── docs/                # architecture.md, decisions.md, pseudocode.md
│   └── demo/run_demo.sh
```

## Configuration Files
`src/config/scope.yaml`: Authorised targets (max 20), test zone `probe.lab.test`, test-zone IP `172.28.0.10`

`src/config/rate.yaml`: `global_qps: 5`, `per_target_qps: 1`, `max_queries_per_target: 3`, `timeout_seconds: 2.0`, `max_total_queries: 80`, `edns_payload: 1232`, `udp_retries: 2`

## Safety Requirements (Critical)
- Never probe outside `scope.yaml` — enforced by `SafetyGate.check_scope()`
- Max 20 targets — enforced by `SafetyGate.enforce_max_20()`
- Kill switch: create `./KILL` file or send `SIGINT` to stop cleanly
- `max_total_queries` and `max_queries_per_target` budgets are enforced before
  every single query; UDP timeout retries count toward both
- Only `A` (RD=1) and `SOA` (RD=0) queries; EDNS ≤ 1232 bytes
- Real source IP (no spoofing)
- `authorisation` block in `scope.yaml` must be complete, or refuse to run

## Classification Rules (Order Matters)
1. No response after retries → `Inconclusive` (timeout)
2. SERVFAIL/bad reply → `Inconclusive` (servfail/bad_reply)
3. NOERROR + expected A + nonce in auth log → `Recursive` (track via_forwarder if log `src_ip` ≠ target IP)
4. Answer but no nonce in log → `Inconclusive` (answer_without_upstream_evidence)
5. Both probes REFUSED → `Refused`
6. Probe B AA=1 + Probe A refused/NXDOMAIN/no nonce → `Authoritative-only`
7. Else → `Inconclusive` (conflicting_evidence)

## Testing
- Unit tests: `test_classifier.py` (10+ cases), `test_ratelimit.py` (fake clock), `test_safety.py`, `test_nonce.py`
- Integration: `test_integration_lab.py` (requires lab, expects ≥90% accuracy)
- All mismatches must have documented root cause: `rate_limit`, `packet_loss`, `timeout_too_short`, `log_delay`, `rule_gap`, `config_error_in_lab`, `other`

## Development Notes
- Python 3.11, simple readable code, small functions, plain dicts/dataclasses
- Allowed libs: `dnspython`, `PyYAML`, `Jinja2`, `pytest`, `pandas` (optional)
- Every module: docstring. Public functions: type hints.
- Document decisions in `src/docs/decisions.md` (ADR dir: `src/docs/decisions/`)
- Architecture diagrams in `src/docs/architecture.md` (Mermaid)

## Package manager
Use `uv` (not pip): `uv add <pkg>` to install, `uv sync` to install from lockfile, `uv run <cmd>` to run.

Python 3.11 per spec; this environment has Python 3.10.12 (uv will use the available Python).
Install/sync dependencies with: `uv sync` (or `uv add <pkg>` to add a new one).

## Entry point
`cli.py` — argparse commands: `scan`, `compare`, `report`, `demo`. Flags: `--scope`, `--rate`, `--out`, `--seed`.

## Unit tests (no Docker)
`uv run pytest` — must pass without Docker (runs from repo root via Makefile `make test`, or `cd src && uv run pytest`).

## Lab integration test
`uv run pytest tests/test_integration_lab.py -m lab` — only when the Docker Compose lab is up (`make lab-up`).
