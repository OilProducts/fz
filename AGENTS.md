# AGENT Instructions

## Recommended Testing
Before submitting changes, run the following sanity checks:

```bash
python3 -m py_compile *.py
python3 main.py --file-input --corpus-dir ./corpus/ --target /usr/bin/file --debug --block-coverage --iterations 1
python3 main.py --file-input --corpus-dir ./corpus/ --target /usr/bin/file --debug --block-coverage --iterations 2  # optional sanity check
```

This verifies bytecode compilation and exercises block coverage mode using a known system binary.
