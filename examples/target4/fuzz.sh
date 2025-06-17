#!/bin/sh
# Build the network server and run the Python fuzzer using the LD_PRELOAD stub
set -e

# Build the C program
make -C "$(dirname "$0")"

# Create a corpus directory relative to this script
CORPUS_DIR="$(dirname "$0")/corpus"
mkdir -p "$CORPUS_DIR"

# Build the LD_PRELOAD network stub library
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
make -C "$ROOT_DIR/src/fz/harness/preload" clean all
STUB_LIB="$ROOT_DIR/src/fz/harness/preload/build/libnet_stub.so"

# Run the fuzzer using the LD_PRELOAD harness
fz --target "$(dirname "$0")/target4" \
    --preload "$STUB_LIB" --iterations 10 --input-size 32 \
    --corpus-dir "$CORPUS_DIR" --output-bytes 1024 "$@"

