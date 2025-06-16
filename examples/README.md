# Example Fuzz Targets

This directory contains small programs used as fuzzing examples for the project.
Each subdirectory holds an individual target along with its build files and a `fuzz.sh` script to run the fuzzer.

## How to Fuzz Examples

For each example target located in a subdirectory (e.g., `examples/<target_name>`):
1. Navigate to the target's directory: `cd examples/<target_name>`
2. Execute the fuzzing script: `./fuzz.sh`

This script will compile the target program and then run the main fuzzer against it. Specific parameters like input size are configured within each `fuzz.sh` script.

---

## Target 1: Basic Stack Smash (`examples/target1`)

**Challenge:** Discovering a direct buffer overflow.

`target1.c` is a very simple program that reads data from `stdin` directly into a small fixed-size buffer on the stack without any bounds checking. The fuzzer's challenge is to provide an input larger than this buffer to trigger a crash via stack smashing.

## Target 2: Conditional Stack Smash with Single-Byte Prefix (`examples/target2`)

**Challenge:** Satisfying a simple prefix condition to reach a buffer overflow.

`target2.c` introduces a condition before a stack buffer overflow: the input must start with the magic byte 'X'. If this magic byte is present, the program then attempts to copy subsequent input bytes into a small stack buffer, leading to an overflow if the input is sufficiently long. If the 'X' prefix is missing, the vulnerable code path is not reached.


## Target 3: Multi-Threaded Network Server (`examples/netserver`)

**Challenge:** Reaching crash conditions over TCP connections.

`server.c` implements a simple threaded TCP server listening on port 9000. It accepts multiple
clients simultaneously and keeps each connection open for a few seconds. Specific input strings
trigger clear crashes:

- `"OVERFLOW:"` followed by more than seven bytes causes a stack buffer overflow.
- `"DOUBLEFREE"` triggers a double free on the heap.
- `"CRASH"` dereferences a null pointer.

Run `fuzz.sh` in this directory to build the server and fuzz it using the network harness.

## Target 4: Network Service with Multiple Crashes (`examples/target4`)

**Challenge:** Fuzzing a TCP server that contains several vulnerable code paths.

`target4.c` listens on port 9999 and spawns a new process for each incoming
connection. Depending on the bytes sent by the client, it can trigger distinct
crashes:

- `OVERFLOW:` followed by data overflows a small stack buffer.
- `MAGIC1234` causes a NULL pointer dereference but requires the exact string to
  reach this path.
- `DIVZERO:` with the value `0` leads to a divide-by-zero crash.

Every connection stays open for a couple of seconds (longer when `WAIT` is
received) so multiple clients can be connected simultaneously.
Run `./fuzz.sh` to build the server and fuzz it using the new LD_PRELOAD
network stub harness.
