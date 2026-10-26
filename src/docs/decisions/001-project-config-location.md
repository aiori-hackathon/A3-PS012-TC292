# Decision 001 — Project-config file location

## Decision
Keep `requirements.txt`, `pyproject.toml`, and `Makefile` at the repository
root, while all application source lives under `src/`.

## Alternatives considered
- **A. Everything under `src/`** (config + source + tests together).
- **B. Config at root, source under `src/`** (chosen).
- **C. Config under `src/` with source, root only holds README/PDF.**

## Why B
- The build prompt's repository layout explicitly places `Makefile`,
  `pyproject.toml`, and `requirements.txt` at the root, with only source,
  tests, docs, config, lab, and demo under `src/`.
- Keeping install/packaging metadata at the root matches standard Python
  project conventions and makes `pip install -e .` and `pytest` discovery
  predictable.
- Putting the Makefile at the root keeps `make test` / `make demo` usable
  without changing into `src/`.

## Trade-offs
- Slightly split mental model (root config vs. src code), but this mirrors
  the mandated layout and is the least-surprising option for contributors.
