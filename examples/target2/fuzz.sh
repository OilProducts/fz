#!/bin/sh
# Build the target and run the Python fuzzer against it
set -e

# Build the C program
make -C "$(dirname "$0")"

# Create a corpus directory relative to this script
CORPUS_DIR="$(dirname "$0")/corpus"
mkdir -p "$CORPUS_DIR"

# Run the fuzzer with a small number of iterations by default
# Input size is 65 to accommodate "X" prefix + 64 bytes for the overflow
python3 ../../main.py --target "$(dirname "$0")/target2" --iterations 10 \
    --input-size 65 --corpus-dir "$CORPUS_DIR" --output-bytes 1024 "$@"
