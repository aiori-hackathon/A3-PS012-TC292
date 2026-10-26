# Decision 009 — Python 3.10 forward compatibility

## Decision
Code is written for Python 3.10+ using `from __future__ import annotations`
and `X | Y` union syntax only where 3.10 supports it at runtime.

## Alternatives considered
- **Target Python 3.11** (as the build prompt states) and use `type` / `X
  | Y` freely.
- **Target Python 3.10** (the interpreter actually installed here) with
  `from __future__ import annotations` (chosen).

## Why
- The build prompt says "Python 3.11," but the installed interpreter is
  Python 3.10.12. Writing 3.10-compatible code means the tool runs in this
  environment without waiting for an interpreter upgrade.
- `from __future__ import annotations` defers evaluation of annotations, so
  `list[Target]` and `str | Path` in signatures work on 3.10.
- Dataclasses, `typing.Optional`, and `pathlib` all behave identically on
  3.10 and 3.11 for our use.

## Trade-offs
- None material; we avoid any 3.11-only syntax (e.g. `typing.Self`,
  variadic generics) so the code stays portable.
