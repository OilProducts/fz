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
