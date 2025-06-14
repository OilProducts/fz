# AGENT Instructions

## Recommended Testing
Before submitting changes, run the following sanity checks:

```bash
python3 -m compileall src
python3 -m fz --file-input --corpus-dir ./corpus/ --target /usr/bin/file --iterations 1
python3 -m fz --file-input --corpus-dir ./corpus/ --target /usr/bin/file --iterations 2  # optional sanity check
pytest -q
```

This verifies bytecode compilation of the source tree and exercises basic block coverage using a known system binary.

## Test Fixture Compilation
Coverage tests use a small C source file in `tests/coverage/fixture.c`.
The `tiny_binary` fixture in `tests/conftest.py` builds this executable at runtime
when the tests run. The compiled binary is temporary and ignored by `.gitignore`.
To run the coverage tests simply invoke `pytest tests/coverage`.
