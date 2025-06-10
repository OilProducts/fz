# AGENT Instructions

## Recommended Testing
Before submitting changes, run the following sanity checks:

```bash
python3 -m py_compile *.py
python3 main.py --file-input --corpus-dir ./corpus/ --target /usr/bin/file --debug --iterations 1
python3 main.py --file-input --corpus-dir ./corpus/ --target /usr/bin/file --debug --iterations 2  # optional sanity check
```

This verifies bytecode compilation and exercises basic block coverage using a known system binary.
