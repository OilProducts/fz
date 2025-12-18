# ROADMAP: Cross-Arch Black-Box Fuzzing (QEMU + GDB)

Evolve fz to fuzz binaries for non-native architectures using qemu-user and runtime basic-block coverage via the GDB remote protocol (RSP). Primary testbed: a MIPS `zip` binary located at the repository root.

## Objective & Success Criteria
- Fuzz a cross-arch binary (MIPS `zip`) under qemu-user and discover at least one unique crash.
- Collect basic-block coverage without recompilation using runtime breakpoints via GDB/RSP.
- Save minimized reproducers and stable repro commands; maintain green sanity checks and tests.

## Target & Scope
- Primary target: MIPS `zip` (provided in repo root). Architecture is auto-detected from ELF headers.
- Execution: `qemu-<arch>` in user-mode with `-g <port>` to expose a GDB server per run.
- Coverage: basic-block hits collected by setting/removing software breakpoints at block entry addresses.
- Scope: file-input fuzzing only; no in-process instrumentation or source builds required.

## Architecture Overview
1) Static analysis: parse ELF and disassemble `.text` to enumerate basic-block entry addresses as module-relative offsets (handle PIE/ASLR at runtime).
2) Runtime collection: spawn qemu-user with `-g`, connect an RSP client, set batches of software breakpoints (`Z0`), continue, and record hits on stops. Remove hit breakpoints to reduce stop storms; reapply per run.
3) Fuzz loop: mutate inputs, run target under qemu-user, collect coverage, select seeds via a power schedule, detect and bucket crashes, and minimize crashing inputs.

## Planned Enhancements
User-facing CLI
- `fz`: `--emulator qemu-user` (default when arch!=host), `--arch auto|mips|mipsel|arm...`, `--gdb-port auto|<port>`, `--bbcov on|off|sampled`, `--timeout`, `--memlimit`, `--args` for target argv.
- `fz repro`: run once under qemu-user with GDB stub, collect stop reason and registers, exit with stable codes.
- `fz-corpus`: `minimize`, `crashes list`, `dict build`, and `cull` subcommands retained.

Core modules
- arch/detect.py: identify ELF arch/endianness/bits; select qemu binary name; compute PIE base handling.
- arch/static_bb.py: ELF parsing (pyelftools) + disassembly (capstone) to get BB entry offsets; persist cache per binary hash.
- coverage/rsp.py: minimal GDB RSP client (connect, read regs, set/remove breakpoints, continue, parse stop reasons).
- coverage/bbcov.py: coverage map keyed by BB id and an edge hash: `edge = (prev<<1) ^ curr`.
- runner/qemu_user.py: manage qemu process with `-g`, randomized free port, timeouts, stderr parsing for fatal signals.
- runner/crash.py: detect crashes from RSP stop reasons or qemu exit, bucket by signal + top PC, save artifacts.

Scheduling & Corpus
- Weighted power schedule favoring new coverage and low-cost seeds; dictionary-driven mutations supported.
- Parallel workers (`--jobs N`) with a shared corpus and per-worker locks; safe file operations.

## Current Status vs Plan
- Execution & emulation: Partial — `run_target()` auto-detects non-host arch and runs `qemu-<arch> -g <port>`; now correctly maps MIPS/MIPS64 (el/be) to qemu names. Dynamic port selection still missing.
- Coverage (ptrace/native): Complete — Linux and macOS collectors insert/restore breakpoints and collect BB edge coverage; covered by tests.
- Coverage (qemu-user via GDB/RSP): Partial — minimal RSP client exists; supports x86_64/arm64 PC decoding; uses raw memory writes instead of `Z0/z0`; no `qXfer:memory-map` base discovery; no MIPS handling yet.
- Static analysis (BBs/edges): Complete (ELF) / Partial (Mach-O) — disassembler selection now derives from the binary’s ELF header, including MIPS32/MIPS64 and endianness. Mach-O path still host-limited but adequate for tests.
- Crash handling & bucketing: Partial — crash/timeout categorization saved in corpus; no bucketing by signal/top PC; no GDB stop reason/register capture.
- Minimizer & repro: Partial — ddmin-style minimizer integrated in `Corpus.minimize_input`; no `fz repro` subcommand; no `fz-corpus minimize` CLI.
- Dictionary-driven mutations: Not started — no AFL-style dictionary parsing/mining.
- Coverage-guided culling: Not started — no cull pass or command; selection uses unseen-edge weighting only.
- Power schedule: Partial — seed weighting by unseen edges exists; no cost-aware/strategy modes.
- Parallel workers: Partial — multi-process fuzzing with shared corpus exists; per-worker GDB port management added defensively (collector errors are handled), but explicit port allocation and crash file locking still missing.
- Arch support modules: Partial — `arch/x86.py`, `arch/arm64.py` present; MIPS-specific arch helpers still absent (not required for current flow).
- CLI & UX: Partial — `--gdb-port`, `--file-input`, `--parallel`, `--minimize` exist; missing `--emulator`, `--arch`, `--bbcov`, and target `--args` passthrough.
- Example harness/docs for MIPS `zip`: Not started — binary exists at repo root; no example script/docs yet.
- Tests: Partial — solid coverage for ptrace collectors and utils; RSP client untested; no MIPS fixtures yet (manual validation done on repo `zip`).

## Milestones
1) Implement arch detection and qemu-user runner (no coverage; black-box exec with timeouts).
2) Add static analyzer for BBs (ELF + Capstone for MIPS) with on-disk cache.
3) Implement GDB RSP client and BB breakpoint coverage; integrate edge coverage into scheduler.
4) Crash detection and bucketing using RSP stop reasons and qemu exit parsing.
5) Minimizer and repro tooling for cross-arch runs.
6) Example harness and docs for MIPS `zip`.
7) Parallel workers, coverage sampling, and dictionary mining to improve throughput.

## Example Campaign: MIPS `zip` via qemu-user
Prereqs
- Install qemu-user for target arch, e.g., `qemu-mips` or `qemu-mipsel` in PATH.
- Optional: `pyelftools` and `capstone` Python packages for static analysis (gated; degrade to black-box without coverage).

Seeds
- Create `./corpus` with a few valid ZIP files and some truncated/corrupted variants.

Run
- `fz --target ./zip --file-input --corpus-dir ./corpus --emulator qemu-user --arch auto --iterations 0 --timeout 1500 --crash-dir ./crashes --bbcov on`
- The fuzzer auto-selects qemu binary, launches with `-g <port>`, connects via RSP, sets BB breakpoints, and collects coverage.

Triage & Repro
- On crash: bucket under `./crashes/<bucket>/id_...` using signal and PC; store GDB stop info and registers.
- Minimize: `fz-corpus minimize --target ./zip --emulator qemu-user --arch auto ./crashes/<bucket>/id_...`
- Reproduce: `fz repro ./crashes/<bucket>/minimized --target ./zip --emulator qemu-user --arch auto`

## Testing & Quality Gates
- Unit tests: arch detection from ELF headers, static BB extraction on sample MIPS fixtures, RSP message parsing, breakpoint lifecycle, crash bucketing.
- Fakes: mock RSP server to simulate breakpoint hits and crashes (no qemu required in CI).
- Sanity: existing tests stay green; cross-arch features skipped when qemu/capstone unavailable.

## Risks & Mitigations
- Overhead of breakpoint-driven coverage: use sampled BB sets; remove breakpoints after first hit; cap concurrent breakpoints.
- PIE/ASLR variability: use module-relative offsets; discover base at runtime via `qXfer:memory-map`/`auxv` when available; fallback to `/proc/<pid>/maps` from host.
- Qemu quirks across arches: gate features per arch; start with MIPS; add ARM/aarch64 after stabilization.

## Success Tracking
- Metrics: execs/sec, BB/edge coverage growth, unique crash buckets, minimized reproducers.
- Outputs: `./crashes/`, `./corpus/`, RSP logs for repro.

## Next Steps
- Implement arch detection and qemu-user runner, then add the static analyzer and RSP coverage collection.
