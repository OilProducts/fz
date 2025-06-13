# AGENT Instructions

## Recommended Testing
Before submitting changes, run the following sanity checks:

```bash
python3 -m compileall src
python3 -m fz --file-input --corpus-dir ./corpus/ --target /usr/bin/file --iterations 1
python3 -m fz --file-input --corpus-dir ./corpus/ --target /usr/bin/file --iterations 2  # optional sanity check
```

This verifies bytecode compilation of the source tree and exercises basic block coverage using a known system binary.
