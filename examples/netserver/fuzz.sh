#!/bin/sh
# Build the target and run the Python fuzzer against it
set -e

# Build the C program
make -C "$(dirname "$0")"

# Create a corpus directory relative to this script
CORPUS_DIR="$(dirname "$0")/corpus"
mkdir -p "$CORPUS_DIR"

# Run the fuzzer using the TCP network harness
python3 -m fz --target "$(dirname "$0")/server" --tcp 127.0.0.1 9000 \
    --iterations 10 --input-size 32 --corpus-dir "$CORPUS_DIR" --output-bytes 1024 "$@"
