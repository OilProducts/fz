# Project: fz
A lightweight, extensible, and reasonably performant fuzzer written in Python. This project aims for near feature-parity with modern open-source fuzzers while maintaining minimal dependencies.

# Core Goals
Minimal Dependencies: Keep the core fuzzer lean and easy to set up.

Performant (for Python): Strive for efficient execution, acknowledging Python's performance characteristics.

Near Feature Parity: Implement the key capabilities found in state-of-the-art fuzzers.

Proven Effectiveness: Prove the fuzzer's capability by using it to discover at least one verifiable bug in a target application.

# Architectural Overview & Roadmap
The fuzzer is designed around three distinct phases: Setup, Test, and Evaluate. The setup phase is optimized to run only once, not on every fuzzing iteration, to maximize throughput.

## Phase 1: Setup & Harnessing
This phase builds the foundational framework for targeting and monitoring applications.

- Hooking & Target Interaction

  - [ ] Function Hooks: Implement hooking via LD_PRELOAD and investigate debugger-based trampolines for more robust injection.

  - [ ] I/O Harnessing: Develop standardized harnesses for stdin/stdout/stderr, file I/O, network sockets, and pipes.

- Target Environment Support

  - [ ] Initial Architecture (x86): Implement core functionality for the x86 architecture, establishing a modular design for future expansion to ARM, MIPS, and ARM64.

  - [ ] Libc Variants: Start with statically compiled binaries, then expand to handle dynamically linked targets using glibc, uclibc, and musl.

  - [ ] Emulation: Investigate qemu-user integration to enable cross-architecture fuzzing from within the Python environment.

- Execution Model

  - [ ] Parallelization: Explore and implement an internal, lightweight parallelization manager. Evaluate Docker for more complex, sandboxed parallel fuzzing scenarios.

## Phase 2: Test & Instrumentation
This phase involves building the core engine for generating test cases, executing the target, and monitoring its state.

- Input Generation & Corpus Management

  - [ ] Mutation Strategy: Start with true random input generation and evolve to include coverage-guided and grammar-based mutation strategies.

  - [ ] Alternative Inputs: Explore sending signals as a form of input.

  - [ ] Coverage Tracking: Use ptrace for basic instrumentation. Log basic block coverage for each input to inform future mutations and identify minimal crashing examples.

- State Logging (On "Interesting" Events)

  - [ ] Implement Smart Triggers: Develop logic to log detailed state on events (timeouts, crashes) and handle delayed effects where a previous input causes a later failure.

  - [ ] Memory Analysis: Integrate pygdb or similar tools to log heap allocations and stack information. This will likely require wrapping malloc, free, etc.

  - [ ] Execution Context: Capture the call stack (with symbol names if possible), register values, and thread/child process information at the time of an event. This requires wrapping fork, pthread_create, etc.

## Phase 3: Evaluation & Analysis
This phase focuses on analyzing the collected data to identify unique and interesting results, which can be performed asynchronously from the main fuzzing loop.

- Triage & Corpus Distillation

  - [ ] Save Interesting Runs: Define and implement logic to save only those inputs that trigger new code paths, new crash types, or user-defined "interesting" behaviors.

  - [ ] Input Minimization: Develop a process to shrink a crashing test case to the smallest possible version that still reproduces the behavior.

- Vulnerability Analysis Heuristics

  - [ ] Automated Bug Class Detection: Implement post-processing analysis to search for common vulnerability patterns:

- Memory Corruption: Detect memory addresses in output, high-entropy data in structured output, and potential double-free or use-after-free conditions.

- Tainted Input: Identify when fuzzer-generated input is passed as an argument to sensitive functions like system, sprintf, gets, etc.

# Supporting Utilities
- [ ] Hooking Helper: Create a Python utility that simplifies C-based function hooking. The tool could accept C source code and a Makefile path, then automatically build the shared object and manage the LD_PRELOAD environment variable for the target process.

## Basic Usage

Run the scaffolding entry point to start the fuzzer. The fuzzer sends random
bytes to the target's standard input on each iteration by default. Use
`--file-input` to supply the bytes via a temporary file passed as an argument
to the target:

```bash
python3 main.py --target /path/to/binary --iterations 1000 --input-size 64
```

To send input via a file instead of stdin:

```bash
python3 main.py --target /path/to/binary --iterations 1000 --file-input
```

Coverage is gathered automatically using `ptrace`. Inputs that execute new
basic blocks are stored in the corpus directory. Use `--corpus-dir` to change
where these inputs are saved:

```bash
python3 main.py --target /path/to/binary --iterations 100 --corpus-dir ./out
```

This main script is minimal and will evolve alongside the project's features.

## Fuzzing a Network Service

The fuzzer can also target network servers. Provide the host and port of the
service and whether to use TCP or UDP:

```bash
python3 main.py --target /path/to/server \
    --tcp-host 127.0.0.1 --tcp-port 9999 --iterations 100
```

For UDP services:

```bash
python3 main.py --target /path/to/server \
    --udp-host 127.0.0.1 --udp-port 9999 --iterations 100
```
