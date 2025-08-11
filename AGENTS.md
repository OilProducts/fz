# Repository Guidelines

## Project Structure & Module Organization
- Source: `src/fz/` with packages `runner/`, `corpus/`, `coverage/`, `harness/`, and `arch/`. Entry points: `fz`, `fz-corpus`, `fz-cfg` (see `pyproject.toml`).
- Tests: `tests/` with `coverage/` and `harness/` suites plus unit tests like `test_*.py`.
- Examples: `examples/` contains small C targets and scripts for local fuzzing.
- Default corpus: `./corpus/` (create if missing or pass `--corpus-dir`).

## Build, Test, and Development Commands
- Install (dev): `pip install -e .` (macOS: also `pip install macholib`).
- Sanity checks:
  ```bash
  python3 -m compileall src
  python3 -m fz --file-input --corpus-dir ./corpus/ --target /usr/bin/file --iterations 1
  python3 -m fz --file-input --corpus-dir ./corpus/ --target /usr/bin/file --iterations 2
  pytest -q
  ```
- Targeted tests: `pytest tests/coverage` to build and exercise the coverage fixture.
- CLI examples: `fz --target /path/to/binary --iterations 100` and `fz-corpus list --corpus-dir ./corpus`.

## Coding Style & Naming Conventions
- Python 3.8+, 4‑space indentation, PEP8.
- Naming: modules/functions `snake_case`, classes `CamelCase`, constants `UPPER_SNAKE_CASE`.
- Prefer type hints and short, focused functions. Keep dependencies minimal and cross‑platform code paths explicit.

## Testing Guidelines
- Framework: `pytest`. Name tests `test_*.py`; colocate helpers in `tests/`.
- Coverage fixture: `tests/coverage/fixture.c` compiles at runtime via the `tiny_binary` fixture in `tests/conftest.py`.
- Add tests for new behavior and reproduce fixes with failing tests first. Use `pytest -q -k <expr>` for focused runs.

## Commit & Pull Request Guidelines
- Commits: imperative mood, concise subject (≤72 chars). Use optional prefixes where helpful: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.
- PRs: include a clear description, linked issues, test plan (commands above), platforms tested (Linux/macOS), and notes on CLI/behavior changes. Update docs (`README.md`) if user‑facing flags or outputs change.

## Security & Configuration Tips
- Do not fuzz untrusted binaries without isolation. Prefer containers/VMs and separate users. Be mindful of auto `qemu-user` selection for cross‑arch targets. Keep corpus/output paths isolated per run.
