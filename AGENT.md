# Amp Agent Guide for cb_query_tester

This document defines how Amp should operate in this repository: commands, conventions, and guardrails. Treat this as ground truth when running verification gates or making changes.

## Project layout
- Main script: `cb_query_tester.py`
- Tests: `tests/`
- Dependencies: `requirements.txt`
- User documentation: `README.md`

## Environment setup
- Python: 3.8+ (tested with 3.11 and 3.13)
- Recommended virtualenv:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## Run the tool
- Basic run (human-readable output):
```bash
python3 cb_query_tester.py -U <cluster-url> -u <username> -p <password> -b <bucket>
```
- JSON report:
```bash
python3 cb_query_tester.py -U <url> -u <user> -p <pass> -b <bucket> -j -r
```
- Skip diagnostics and include timeline:
```bash
python3 cb_query_tester.py -U <url> -u <user> -p <pass> -b <bucket> -s -t
```
- Environment variables supported: `CB_USERNAME`, `CB_PASSWORD`.

## Verification gates (order)
1) Typecheck (if available)
```bash
# Only run if mypy is installed/configured
mypy .
```
2) Lint (if available)
```bash
# Prefer ruff if present
ruff check .
# Or flake8
flake8 .
```
3) Tests (always)
```bash
python3 -m unittest discover -s tests -p "test_*.py" -t . -v
```
4) Build: N/A (this is a Python script; no packaging/build step by default).

## Testing conventions
- Test files live under `tests/` and follow `test_*.py` naming.
- Tests isolate networking and external SDKs via stubs/mocks.
- Discovery requires `tests/__init__.py` (present) or `-t .` top-level option.

## Coding conventions
- Style: PEP 8. Prefer small, cohesive diffs.
- Logging: use the module-level `logger` already configured in `cb_query_tester.py`; avoid `print` except in the dedicated reporting function.
- Typing: add type hints when modifying or adding functions; avoid `Any` and suppressions.
- Error handling: raise/propagate `CouchbaseException` and `TimeoutException`; for CLI failures, return a structured error report (current pattern in `main`).
- I/O: keep functions pure where feasible; side-effects (network, subprocess) are wrapped and mockable.

## Guardrails
- Simple-first: prefer localized fixes; avoid cross-file refactors without need.
- Reuse-first: mirror existing patterns for logging, argument parsing, metrics, and reporting.
- No new dependencies without explicit approval.
- If a change affects >3 files or multiple subsystems, propose a short plan before edits.

## Common tasks
- Add a unit test:
  - Place under `tests/` with name `test_<area>.py`.
  - Use `unittest` and `unittest.mock`; stub external SDKs when importing the main module.
- Update ignore rules:
  - Edit `.gitignore` (already includes venv, caches, build artifacts, IDE files, and JSON reports).

## CI default command
```bash
python3 -m unittest discover -s tests -p "test_*.py" -t . -v
```

## Notes
- JSON reports can be large; they are ignored via `*.json` in `.gitignore`.
- Network diagnostics (ping/traceroute) can be slow; they can be skipped with `-s` during automated runs.
