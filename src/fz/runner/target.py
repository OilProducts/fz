import ctypes
import ctypes.util
import logging
import os
import platform
import shutil
import socket
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
    """Return the architecture for ``path`` as a normalized string.

    Normalized values include: ``x86_64``, ``i386``, ``arm``, ``arm64``,
    ``mips``, ``mipsel``, ``mips64``, ``mips64el``.
    """
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic == b"\x7fELF":
        from elftools.elf.elffile import ELFFile

        with open(path, "rb") as f:
            elf = ELFFile(f)
            mach = elf.header["e_machine"]
            # Prefer explicit mapping where possible
            if mach == "EM_X86_64":
                return "x86_64"
            if mach in ("EM_386", "EM_486"):
                return "i386"
            if mach == "EM_AARCH64":
                return "arm64"
            if mach == "EM_ARM":
                return "arm"
            if "MIPS" in mach:
                bits = 64 if getattr(elf, "elfclass", 0) == 64 else 32
                little = getattr(elf, "little_endian", True)
                if bits == 64:
                    return "mips64el" if little else "mips64"
                return "mipsel" if little else "mips"
            # Fallback to the ELF e_machine string lowercased if unknown
            return str(mach).lower()
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
        "mips": ["qemu-mips"],
        "mipsel": ["qemu-mipsel"],
        "mips64": ["qemu-mips64"],
        "mips64el": ["qemu-mips64el"],
    }.get(arch, [f"qemu-{arch}"])

    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    return None


def _find_plugin_so() -> Optional[str]:
    """Return path to the built QEMU plugin if available."""
    here = os.path.dirname(os.path.abspath(__file__))
    cand = os.path.realpath(os.path.join(here, "..", "coverage", "plugin", "fz_bbcov.so"))
    if os.path.exists(cand):
        return cand
    cand2 = os.path.realpath(os.path.join(os.getcwd(), "src", "fz", "coverage", "plugin", "fz_bbcov.so"))
    if os.path.exists(cand2):
        return cand2
    return None


def _read_plugin_map(path: str, size: int, module: str) -> EdgeCoverage:
    cov: EdgeCoverage = {}
    try:
        with open(path, "rb") as f:
            data = f.read(size)
    except Exception:
        return cov
    if not data:
        return cov
    for i, b in enumerate(data):
        if b:
            src = (module, 0)
            dst = (module, i)
            cov[(src, dst)] = b
    return cov


def _maybe_find_ld_prefix(arch: str) -> Optional[str]:
    """Best-effort search for a QEMU_LD_PREFIX for the target arch.

    For MIPS targets, first check the system default under /usr/gnemul,
    then look for an extracted firmware root under ./firmware/**/squashfs-root
    (or similar) that contains /lib/ld-*.so.
    """
    try:
        if arch in ("mips", "mipsel", "mips64", "mips64el"):
            # system default prefix
            sys_prefix = f"/usr/gnemul/qemu-{arch}"
            if os.path.isdir(sys_prefix) and os.path.isdir(os.path.join(sys_prefix, "lib")):
                if os.path.exists(os.path.join(sys_prefix, "lib", "ld-uClibc.so.0")) or os.path.exists(os.path.join(sys_prefix, "lib", "ld-linux.so.3")):
                    return sys_prefix
            # repo firmware search
            fw_root = os.path.join(os.getcwd(), "firmware")
            if os.path.isdir(fw_root):
                for dirpath, dirnames, filenames in os.walk(fw_root):
                    if os.path.basename(dirpath) != "lib":
                        continue
                    # check common loader names
                    candidates = [
                        "ld-uClibc.so.0",
                        "ld-linux.so.3",
                    ]
                    if any(os.path.exists(os.path.join(dirpath, n)) for n in candidates):
                        return os.path.dirname(dirpath)
                    for fn in filenames:
                        if fn.startswith("ld-uClibc-") and fn.endswith(".so"):
                            return os.path.dirname(dirpath)
        # TODO: add ARM variants if needed
    except Exception:
        pass
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
    use_rsp = False
    use_binfmt = False
    rsp_port: Optional[int] = None
    collector = None
    plugin_so: Optional[str] = None
    plugin_map_path: Optional[str] = None
    plugin_map_size = 64 * 1024
    host_arch = platform.machine().lower()
    target_arch = _detect_arch(target)
    if target_arch != host_arch:
        # Prefer binfmt_misc + QEMU_GDB to launch via kernel binfmt handler.
        use_binfmt = True
        plugin_so = _find_plugin_so()
        qemu_user = _find_qemu_user(target_arch)
        if not qemu_user:
            logging.debug("No explicit qemu-user found; relying on binfmt for %s", target_arch)
        else:
            logging.debug("qemu-user available: %s (binfmt preferred)", qemu_user)
        # Enable RSP coverage only for known-good architectures
        rsp_supported = target_arch in (
            "x86_64",
            "amd64",
            "arm64",
            "aarch64",
            "mips",
            "mipsel",
            "mips64",
            "mips64el",
        )
        # Prefer plugin fast path if available; we'll launch qemu explicitly
        if plugin_so:
            use_binfmt = False
            use_rsp = False
            logging.info("Using QEMU plugin for coverage: %s", plugin_so)
        if rsp_supported and not plugin_so:
            # Pick a free TCP port per run to avoid collisions in parallel mode
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("127.0.0.1", 0))
                    s.listen(1)
                    rsp_port = s.getsockname()[1]
            except Exception:
                rsp_port = gdb_port or 1234
            try:
                collector = coverage.get_gdb_collector("localhost", rsp_port, target_arch)
                use_rsp = True
            except Exception as e:
                logging.debug("RSP collector unavailable for arch %s: %s", target_arch, e)
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
        if use_binfmt:
            # Launch target directly; kernel binfmt will invoke qemu-user.
            if use_rsp and rsp_port is not None:
                env["QEMU_GDB"] = str(rsp_port)
            if "QEMU_LD_PREFIX" not in env:
                ld_prefix = _maybe_find_ld_prefix(target_arch)
                if ld_prefix:
                    env["QEMU_LD_PREFIX"] = ld_prefix
            # argv remains as computed (target path, plus file input)
        elif qemu_user:
            qemu_argv = [qemu_user]
            # Supply -L prefix if we can locate a suitable rootfs
            ld_prefix = None
            if "QEMU_LD_PREFIX" not in env:
                ld_prefix = _maybe_find_ld_prefix(target_arch)
                if ld_prefix:
                    env["QEMU_LD_PREFIX"] = ld_prefix
            if ld_prefix:
                qemu_argv += ["-L", ld_prefix]
            if plugin_so:
                # Create shared map file for plugin bitmap
                fd, plugin_map_path = tempfile.mkstemp(prefix="fz_cov_", dir="/dev/shm" if os.path.isdir("/dev/shm") else None)
                os.close(fd)
                with open(plugin_map_path, "wb") as f:
                    f.truncate(plugin_map_size)
                qemu_argv += ["-plugin", f"{plugin_so},shm={plugin_map_path},size={plugin_map_size}"]
            elif use_rsp and rsp_port is not None:
                qemu_argv += ["-g", str(rsp_port)]
            argv = qemu_argv + [target] + argv[1:]
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
        if not qemu_user and not use_binfmt:
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
        if plugin_so and plugin_map_path:
            coverage_set = {}
        elif (use_binfmt or qemu_user) and use_rsp and collector is not None:
            try:
                coverage_set = collector.collect_coverage(
                    proc.pid,
                    timeout,
                    target,
                    already_traced=False,
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
            except Exception as e:
                logging.debug(
                    "Collector error for pid %d (arch=%s): %s",
                    proc.pid,
                    target_arch,
                    e,
                )
                coverage_set = {}
        elif not qemu_user and not use_binfmt:
            collector = coverage.get_collector()
            try:
                coverage_set = collector.collect_coverage(
                    proc.pid,
                    timeout,
                    target,
                    already_traced=True,
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
            except Exception as e:
                logging.debug(
                    "Collector error for pid %d (arch=%s): %s",
                    proc.pid,
                    target_arch,
                    e,
                )
                coverage_set = {}
        else:
            # qemu-user without RSP coverage
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
        if plugin_so and plugin_map_path:
            module = f"plugin:{os.path.basename(target)}"
            coverage_set = _read_plugin_map(plugin_map_path, plugin_map_size, module)
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
        if plugin_so and plugin_map_path:
            try:
                os.unlink(plugin_map_path)
            except Exception:
                pass

    return coverage_set, crashed, timed_out, exit_code, stdout_data, stderr_data
