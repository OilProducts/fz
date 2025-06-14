# AGENT Instructions

## Recommended Testing
Before submitting changes, run the following sanity checks:

```bash
python3 -m compileall src
python3 -m fz --file-input --corpus-dir ./corpus/ --target /usr/bin/file --iterations 1
python3 -m fz --file-input --corpus-dir ./corpus/ --target /usr/bin/file --iterations 2  # optional sanity check
```

This verifies bytecode compilation of the source tree and exercises basic block coverage using a known system binary.

## Test Fixture Compilation
Coverage tests use a small C fixture in `tests/coverage/fixture.c`.
The binary should be compiled at runtime via the `tiny_binary` fixture in `tests/conftest.py` and must not be committed to the repository.
The compiled binary is ignored by `.gitignore`.
