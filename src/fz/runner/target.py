import ctypes
import ctypes.util
import logging
import os
import subprocess
import tempfile
from typing import Set, Tuple, Optional

from fz.coverage.cfg import Edge

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
    Set[Edge],
    bool,
    bool,
    int | None,
    bytes,
    bytes,
]:
    """Execute *target* with *data* once and return execution results.

    Returns
    -------
    Set[Edge], bool, bool, int | None, bytes, bytes
        ``(coverage_set, crashed, timed_out, exit_code, stdout, stderr)``
    """
    coverage_set: Set[Edge] = set()
    exit_code: int | None = None
    capture_output = output_bytes > 0
    if capture_output:
        stdout_file = tempfile.TemporaryFile()
        stderr_file = tempfile.TemporaryFile()
        stdout_param = stdout_file
        stderr_param = stderr_file
    else:
        stdout_file = None
        stderr_file = None
        stdout_param = subprocess.DEVNULL
        stderr_param = subprocess.DEVNULL
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
        logging.debug("Launching target: %s", " ".join(argv))

        preexec = None
        if not qemu_user:
            def _trace_me():
                libc.ptrace(PTRACE_TRACEME, 0, None, None)

            preexec = _trace_me

        proc = subprocess.Popen(
            argv,
            stdin=stdin_pipe,
            stdout=stdout_param,
            stderr=stderr_param,
            preexec_fn=preexec,
            env=env,
        )
        if not qemu_user:
            os.waitpid(proc.pid, 0)

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
        else:
            collector = coverage.get_collector()
        try:
            coverage_set = collector.collect_coverage(
                proc.pid,
                timeout,
                target,
                already_traced=not qemu_user,
                libs=libs,
            )
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
        if capture_output:
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout_data = stdout_file.read(output_bytes)
            stderr_data = stderr_file.read(output_bytes)
        else:
            stdout_data = b""
            stderr_data = b""
    finally:
        if file_input and filename:
            try:
                os.unlink(filename)
            except OSError:
                pass
        if proc and proc.poll() is None:
            proc.kill()
        if capture_output:
            stdout_file.close()
            stderr_file.close()

    return coverage_set, crashed, timed_out, exit_code, stdout_data, stderr_data
