import ctypes
import ctypes.util
import logging
import os
import platform
import shutil
import subprocess
import tempfile
from typing import Set, Tuple, Optional

from fz.coverage.cfg import Edge, EdgeCoverage

from fz import coverage

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
PTRACE_TRACEME = 0

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}


def _detect_arch(path: str) -> str:
    """Return the architecture for ``path`` as a normalized string."""
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic == b"\x7fELF":
        from elftools.elf.elffile import ELFFile

        with open(path, "rb") as f:
            elf = ELFFile(f)
            mach = elf.header["e_machine"]
        arch_map = {
            "EM_X86_64": "x86_64",
            "EM_386": "i386",
            "EM_AARCH64": "arm64",
            "EM_ARM": "arm",
        }
        return arch_map.get(mach, mach.lower())
    if magic in _MACHO_MAGICS:
        from macholib.MachO import MachO
        from macholib.mach_o import CPU_TYPE_NAMES

        m = MachO(path)
        if m.headers:
            cpu = m.headers[0].header.cputype
            name = CPU_TYPE_NAMES.get(cpu, "").lower()
            if name:
                return name
    return platform.machine().lower()


def _find_qemu_user(arch: str) -> Optional[str]:
    """Return the path to qemu-user for ``arch`` if available."""
    candidates = {
        "x86_64": ["qemu-x86_64"],
        "amd64": ["qemu-x86_64"],
        "i386": ["qemu-i386"],
        "arm": ["qemu-arm"],
        "arm64": ["qemu-aarch64"],
        "aarch64": ["qemu-aarch64"],
    }.get(arch, [f"qemu-{arch}"])

    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    return None


def run_target(
    target: str,
    data: bytes,
    timeout: float,
    file_input: bool = False,
    output_bytes: int = 0,
    libs: Optional[list[str]] = None,
    gdb_port: int = 1234,
    env: Optional[dict[str, str]] = None,
) -> Tuple[
    EdgeCoverage,
    bool,
    bool,
    int | None,
    bytes,
    bytes,
]:
    """Execute *target* with *data* once and return execution results.

    Returns
    -------
    EdgeCoverage, bool, bool, int | None, bytes, bytes
        ``(coverage_map, crashed, timed_out, exit_code, stdout, stderr)``
    """
    coverage_set: EdgeCoverage = {}
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
    qemu_user = None
    host_arch = platform.machine().lower()
    target_arch = _detect_arch(target)
    if target_arch != host_arch:
        qemu_user = _find_qemu_user(target_arch)
        if not qemu_user:
            raise RuntimeError(
                f"qemu-user for architecture {target_arch} not found"
            )
        logging.debug("Using qemu-user %s for %s", qemu_user, target_arch)
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
            collector = coverage.get_gdb_collector("127.0.0.1", gdb_port, target_arch)
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
            coverage_set = {}
        except OSError as e:
            logging.debug(
                "Failed to collect coverage from pid %d: %s", proc.pid, e
            )
            coverage_set = {}

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
