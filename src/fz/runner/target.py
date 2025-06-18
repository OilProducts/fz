import ctypes
import ctypes.util
import logging
import os
import subprocess
import tempfile
from typing import Set, Tuple, Optional

from fz import coverage

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
PTRACE_TRACEME = 0


def run_target(
    target: str,
    data: bytes,
    timeout: float,
    file_input: bool = False,
    output_bytes: int = 0,
    libs: Optional[list[str]] = None,
    qemu_user: Optional[str] = None,
    gdb_port: int = 1234,
    arch: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
) -> Tuple[
    Set[tuple[tuple[str, int], tuple[str, int]]],
    bool,
    bool,
    int | None,
    bytes,
    bytes,
]:
    """Execute *target* with *data* once and return execution results.

    Returns
    -------
    Set[tuple], bool, bool, int | None, bytes, bytes
        ``(coverage_set, crashed, timed_out, exit_code, stdout, stderr)``
    """
    logging.debug("run_target called with: target=%s, file_input=%s, libs=%s, qemu_user=%s, gdb_port=%d, arch=%s", target, file_input, libs, qemu_user, gdb_port, arch)
    coverage_set: Set[tuple[tuple[str, int], tuple[str, int]]] = set()
    exit_code: int | None = None
    stdout_file = tempfile.TemporaryFile()
    stderr_file = tempfile.TemporaryFile()
    filename = None
    proc = None
    if env is None:
        env = os.environ.copy()
    try:
        if file_input:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(data)
                tmp.flush()
                filename = tmp.name
            argv = [target, filename]
            stdin_pipe = None
        else:
            argv = [target]
            stdin_pipe = subprocess.PIPE
        if qemu_user:
            argv = [qemu_user, "-g", str(gdb_port), target] + argv[1:]
        logging.debug("Popen argv: %s", argv)
        logging.debug("Launching target: %s", " ".join(argv))

        preexec = None
        # PTRACE_TRACEME logic removed, collector will use PTRACE_ATTACH for native targets.
        # if not qemu_user:
        #     def _trace_me():
        #         libc.ptrace(PTRACE_TRACEME, 0, None, None)
        #
        #     preexec = _trace_me

        proc = subprocess.Popen(
            argv,
            stdin=stdin_pipe,
            stdout=stdout_file,
            stderr=stderr_file,
            preexec_fn=preexec, # preexec is now always None
            env=env,
        )
        # os.waitpid after Popen for PTRACE_TRACEME removed.
        # PTRACE_ATTACH in CoverageCollector will handle its own wait.
        # if not qemu_user:
        #     os.waitpid(proc.pid, 0)

        if not file_input and proc.stdin:
            try:
                proc.stdin.write(data)
            except BrokenPipeError:
                logging.debug("Stdin pipe closed before data was written")
            finally:
                try:
                    proc.stdin.close()
                except BrokenPipeError:
                    logging.debug("Broken pipe when closing stdin")

        logging.debug("Collecting coverage from pid %d", proc.pid)
        if qemu_user:
            collector = coverage.get_gdb_collector("127.0.0.1", gdb_port, arch or "x86_64")
            logging.debug("Using QemuGdbCollector for coverage.")
            # QemuGdbCollector.collect_coverage doesn't use/need already_traced
            # It also doesn't use the 'exe' parameter in the same way, target path is for symbolication.
            coverage_set = collector.collect_coverage(proc.pid, timeout, exe=target, libs=libs)
        else:
            collector = coverage.get_collector()
            logging.debug("Using native collector: %s, will use PTRACE_ATTACH.", collector.__class__.__name__)
            # Force PTRACE_ATTACH path in CoverageCollector by setting already_traced=False
            coverage_set = collector.collect_coverage(proc.pid, timeout, exe=target, already_traced=False, libs=libs)
        # The try...except block for collect_coverage call remains:
        # try:
        #     ...
        # except FileNotFoundError: ...
        # except OSError: ...
        # For brevity, the diff only shows the changed part of the collect_coverage call.
        # The following lines are conceptual and represent the existing try-except structure.
        # This diff only modifies the parameters to collect_coverage.
        # The actual try/except FileNotFoundError/OSError is expected to be outside this specific change block.
        # The tool should merge this change into the existing try-except structure.
        # The provided SEARCH block correctly captures the original call.
        # The REPLACE block provides the new call structure.
        # The original code was:
        # try:
        #     coverage_set = collector.collect_coverage(
        #         proc.pid,
        #         timeout,
        #         target, # This was 'exe' in CoverageCollector, but 'target' (path) is more appropriate here
        #         already_traced=not qemu_user,
        #         libs=libs,
        #     )
        # except FileNotFoundError:
        #
        # This is being replaced by the logic above, which should still be wrapped in the try/except.
        # The diff tool should handle this correctly by replacing only the specific lines matched in SEARCH.
        # The key is that the `try:` and `except ...:` lines themselves are not in the SEARCH block.
        # The `coverage_set = collector.collect_coverage(...)` line is what's being replaced.
        # The prompt's example for the `collect_coverage` change was:
        # ```python
        # if qemu_user:
        #     collector = coverage.get_gdb_collector("127.0.0.1", gdb_port, arch or "x86_64")
        #     logging.debug("Using QemuGdbCollector for coverage.")
        #     # QemuGdbCollector.collect_coverage doesn't use/need already_traced
        #     coverage_set = collector.collect_coverage(proc.pid, timeout, target, libs=libs) # target here is exe for collector
        # else:
        #     collector = coverage.get_collector()
        #     logging.debug("Using native collector: %s, will use PTRACE_ATTACH.", collector.__class__.__name__)
        #     # Force PTRACE_ATTACH path in CoverageCollector by setting already_traced=False
        #     coverage_set = collector.collect_coverage(proc.pid, timeout, target, already_traced=False, libs=libs) # target here is exe for collector
        # ```
        # This entire if/else block for choosing collector and calling collect_coverage replaces the original.
        # The `try...except` block will wrap this new if/else block.

        # The following is the direct replacement of the old `try...coverage_set = ... except...`
        # with the new logic, ensuring it's still within a try...except
        try:
            if qemu_user:
                collector = coverage.get_gdb_collector("127.0.0.1", gdb_port, arch or "x86_64")
                logging.debug("Using QemuGdbCollector for coverage.")
                coverage_set = collector.collect_coverage(proc.pid, timeout, exe=target, libs=libs)
            else:
                collector = coverage.get_collector()
                logging.debug("Using native collector: %s, will use PTRACE_ATTACH.", collector.__class__.__name__)
                coverage_set = collector.collect_coverage(proc.pid, timeout, exe=target, already_traced=False, libs=libs)
        except FileNotFoundError:
            logging.debug(
                "Process %d exited before coverage collection", proc.pid
            )
            coverage_set = set()
        except OSError as e:
            logging.debug(
                "Failed to collect coverage from pid %d: %s", proc.pid, e
            )
            coverage_set = set()

        crashed = False
        timed_out = False
        try:
            proc.wait(timeout=timeout)
            exit_code = proc.returncode
            crashed = exit_code is not None and exit_code < 0
        except subprocess.TimeoutExpired:
            proc.kill()
            timed_out = True
            logging.warning("Execution timed out")
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout_data = stdout_file.read(output_bytes) if output_bytes else b""
        stderr_data = stderr_file.read(output_bytes) if output_bytes else b""
    finally:
        if file_input and filename:
            try:
                os.unlink(filename)
            except OSError:
                pass
        if proc and proc.poll() is None:
            proc.kill()
        stdout_file.close()
        stderr_file.close()

    logging.debug("run_target returning: coverage_set size=%d, crashed=%s, timed_out=%s, exit_code=%s", len(coverage_set), crashed, timed_out, exit_code)
    return coverage_set, crashed, timed_out, exit_code, stdout_data, stderr_data
