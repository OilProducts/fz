# Project: fz
A lightweight, extensible, and reasonably performant fuzzer written in Python. This project aims for near feature-parity with modern open-source fuzzers while maintaining minimal dependencies.

## Quick Setup

Install the package in editable mode (Python 3.8+):

```bash
pip install -e .
```

This installs the `fz`, `fz-corpus`, and `fz-cfg` commands.

## Quick Usage

Fuzz a binary:

```bash
fz --target /path/to/binary --iterations 100
```

Write input to a file:

```bash
fz --target /path/to/binary --file-input --iterations 100
```

Fuzz a network service:

```bash
fz --target /path/to/server --tcp 127.0.0.1 9999 --iterations 100
```

Use a YAML config:

```bash
fz --config config.yaml
```

Inspect saved samples:

```bash
fz-corpus list --corpus-dir ./corpus
```

Generate a control flow graph:

```bash
fz-cfg /usr/bin/file --svg file.svg
```

# Core Goals
Minimal Dependencies: Keep the core fuzzer lean and easy to set up.

Performant (for Python): Strive for efficient execution, acknowledging Python's
performance characteristics.

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
  - [x] ARM64 Support: Coverage instrumentation now works on aarch64 Linux systems.
  - [x] macOS Support: Basic fuzzing works on macOS using ptrace for coverage.

  - [ ] Libc Variants: Start with statically compiled binaries, then expand to handle dynamically linked targets using glibc, uclibc, and musl.

  - [x] Emulation: Basic qemu-user integration via a GDB-based collector enables cross-architecture fuzzing.

- Execution Model

  - [ ] Parallelization: Explore and implement an internal, lightweight parallelization manager. Evaluate Docker for more complex, sandboxed parallel fuzzing scenarios.

## Phase 2: Test & Instrumentation
This phase involves building the core engine for generating test cases, executing the target, and monitoring its state.

- Input Generation & Corpus Management

  - [ ] Mutation Strategy: Start with true random input generation and evolve to include coverage-guided and grammar-based mutation strategies.

  - [ ] Alternative Inputs: Explore sending signals as a form of input.

  - [ ] Coverage Tracking: Use ptrace for basic instrumentation. Log basic block transition coverage for each input to inform future mutations and identify minimal crashing examples.

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
python3 -m fz --target /path/to/binary --iterations 1000 --input-size 64 --mutations 4
```

To send input via a file instead of stdin:

```bash
python3 -m fz --target /path/to/binary --iterations 1000 --file-input
```

To fuzz continuously until interrupted, use `--run-forever`:

```bash
python3 -m fz --target /path/to/binary --run-forever
```

To run multiple fuzzing processes concurrently, use `--parallel`:

```bash
python3 -m fz --target /path/to/binary --iterations 100 --parallel 4
```

To fuzz a binary for another architecture using `qemu-user`, provide the emulator path with `--qemu-user` and specify the architecture:

```bash
python3 -m fz --target ./target_arm64 --qemu-user qemu-aarch64 --arch arm64
```

Coverage is gathered automatically using `ptrace`. The addresses recorded are
normalized to the binary's load base so identical inputs yield identical
coverage sets across runs. Inputs that execute a unique set of basic block transitions are stored in
the corpus directory. Use `--corpus-dir` to change
where these inputs are saved. Basic block transition coverage via breakpoints is always
enabled.

Each saved input is keyed by a hash of the coverage it produced. Samples are
written as JSON files containing the executed basic block transitions, the input bytes
(base64 encoded), and optionally the first N bytes of stdout/stderr from the
target. Use `--output-bytes` to set how much output to store. Because filenames
are derived from the coverage hash,
parallel fuzzing only keeps the first input for a given coverage set,
preventing duplicate samples that exercise the same code paths.

```bash
python3 -m fz --target /path/to/binary --iterations 100 --corpus-dir ./out
```

This main script is minimal and will evolve alongside the project's features.
Use `--debug` to enable verbose debug logging.
Use `--minimize` to enable delta-debugging on newly saved inputs.

## Coverage Collector Architecture

Coverage gathering is handled by subclasses of `CoverageCollector` in
`fz.coverage.collector`.  The base class manages breakpoint insertion and
provides the `collect_coverage` API.  Two implementations are currently
available:

- `LinuxCollector` &mdash; uses `/proc` and `ptrace` on Linux.
- `MacOSCollector` &mdash; relies on `vmmap` and `ptrace` on macOS.

`get_collector()` automatically instantiates the correct subclass for the host
platform.  To support another operating system, create a new subclass that
implements the `_resolve_exe` and `_get_image_base` methods and update
`get_collector()` to return it when `platform.system()` matches your OS.

## Mutation Workflow

Inputs are chosen from previously saved corpus files and mutated before being
executed. The mutator weights seeds by the amount of coverage they produced and
applies simple strategies such as bit flipping, splicing two seeds together,
and inserting or deleting bytes. Each new input can be mutated multiple times in
sequence (controlled by `--mutations`), allowing combinations of these
operations. Whenever a run yields a unique coverage set the input is added to the pool so
future mutations build on the most interesting cases.

## Fuzzing a Network Service

The fuzzer can also target network servers. Provide the host and port of the
service and whether to use TCP or UDP:

```bash
python3 -m fz --target /path/to/server --tcp 127.0.0.1 9999 --iterations 100
```

For UDP services:

```bash
python3 -m fz --target /path/to/server --udp 127.0.0.1 9999 --iterations 100
```

TCP and UDP modes are mutually exclusive, and neither can be used together with
`--file-input`. Each mode requires both a host and port.

## Using a Configuration File

All command line options can be provided in a YAML file. The keys in the file
must match the command line option names. Pass the file with `--config` and any
CLI arguments will override the values from the file.

Example `config.yaml`:

```yaml
target: /path/to/binary
iterations: 1000
input_size: 128
mutations: 2
timeout: 2
file_input: true
run_forever: true
output_bytes: 1024
```

Run the fuzzer using this configuration:

```bash
python3 -m fz --config config.yaml
```

## Corpus Analysis

Use the `fz.corpus.manager` module to inspect or add samples. The ``list``
command prints the captured stdout, stderr, and length of the input for each
entry in the corpus directory.

```bash
python3 -m fz.corpus.manager list --corpus-dir ./corpus
```

## Control Flow Graph Visualization

The `fz-cfg` script generates a Graphviz representation of a binary's possible
control flow graph using static analysis. When run without an output file the
DOT graph is printed to stdout:

```bash
fz-cfg /usr/bin/file
```

Provide `--output` to write the DOT data to a file that can be rendered with
Graphviz:

```bash
fz-cfg /usr/bin/file --output file.dot
```

To generate an SVG directly without keeping the intermediate DOT data, use
`--svg`:

```bash
fz-cfg /usr/bin/file --svg file.svg
```

## Development and Testing

Before submitting changes run the project's sanity checks:

```bash
python3 -m compileall src
python3 -m fz --file-input --corpus-dir ./corpus/ --target /usr/bin/file --iterations 1
python3 -m fz --file-input --corpus-dir ./corpus/ --target /usr/bin/file --iterations 2  # optional sanity check
pytest -q
```

These commands verify the source tree compiles, a basic fuzzing run executes, and all tests pass.

