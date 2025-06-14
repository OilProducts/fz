import ctypes
import ctypes.util
import logging
import os
import platform
import signal
import time
import errno

from typing import Optional, Set, Tuple

from .utils import get_basic_blocks
from .common import _ptrace, _ptrace_peek, _ptrace_poke

# Architecture specific imports
ARCH = platform.machine().lower()
if ARCH in ("aarch64", "arm64"):
    from ..arch import arm64 as arch
else:
    from ..arch import x86 as arch


PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13

BREAKPOINT = arch.BREAKPOINT
user_regs_struct = arch.user_regs_struct
get_pc = arch.get_pc
set_pc = arch.set_pc



def _get_image_base(pid: int, exe: str) -> int:
    """Return the loaded base address for ``exe`` within ``pid``.

    Parameters
    ----------
    pid:
        Identifier of the process containing ``exe``.
    exe:
        Path to the executable on disk.

    Returns
    -------
    int
        The base address or ``0`` if not found.
    """
    exe = os.path.realpath(exe)
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.rstrip().split(None, 5)
                if len(parts) < 6:
                    continue
                addr_range, perms, offset, _dev, _inode, path = parts
                if path != exe or "x" not in perms:
                    continue
                start = int(addr_range.split("-", 1)[0], 16)
                off = int(offset, 16)
                return start - off
    except FileNotFoundError:
        logging.debug("/proc/%d/maps not found", pid)
    logging.debug("Base address for %s not found in /proc/%d/maps", exe, pid)
    return 0


def collect_coverage(
    pid: int, timeout: float = 1.0, exe: Optional[str] = None, already_traced: bool = False
) -> Set[Tuple[int, int]]:
    """Collect basic block transition coverage from a Linux process.

    Parameters
    ----------
    pid:
        Identifier of the process to trace.
    timeout:
        Maximum number of seconds to wait for coverage events.
    exe:
        Path to the executable. If ``None``, the path is resolved via ``/proc``.
    already_traced:
        Set to ``True`` if the caller has already attached using ``ptrace``.

    Returns
    -------
    set[tuple[int, int]]
        The executed basic block transitions.
    """
    logging.debug("Collecting coverage for pid %d", pid)
    coverage = set()
    prev_addr = None
    word_cache = {}

    if exe is None:
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError as e:
            logging.debug("Failed to read executable path for pid %d: %s", pid, e)
            exe = None

    if exe is not None:
        exe = os.path.realpath(exe)

    if not already_traced:
        _ptrace(PTRACE_ATTACH, pid)
        os.waitpid(pid, 0)
        logging.debug("Attached to pid %d", pid)

    base = _get_image_base(pid, exe) if exe else 0
    if exe and base == 0:
        logging.debug("Base address not found for %s", exe)
    logging.debug("%s loaded at %#x", exe, base)

    logging.debug("Inserting breakpoints for block coverage on %s", exe)
    blocks = get_basic_blocks(exe)
    blocks = [base + b for b in blocks]
    breakpoints = {}
    for b in blocks:
        try:
            if ARCH in ("aarch64", "arm64"):
                word_addr = b & ~7
                offset = b & 7
                if word_addr not in word_cache:
                    orig_word = _ptrace_peek(pid, word_addr)
                    patched_word = orig_word
                    patches = set()
                else:
                    orig_word, patched_word, patches = word_cache[word_addr]
                if offset == 0:
                    patched_word = (patched_word & ~0xFFFFFFFF) | BREAKPOINT
                else:
                    patched_word = (patched_word & 0xFFFFFFFF) | (BREAKPOINT << 32)
                _ptrace_poke(pid, word_addr, patched_word)
                patches.add(offset)
                word_cache[word_addr] = (orig_word, patched_word, patches)
                breakpoints[b] = (word_addr, offset)
            else:
                orig = _ptrace_peek(pid, b)
                breakpoints[b] = orig
                _ptrace_poke(pid, b, (orig & ~0xFF) | BREAKPOINT)
            logging.debug("Breakpoint inserted at %#x", b)
        except OSError as e:
            logging.debug("Failed to insert breakpoint at %#x: %s", b, e)
            continue

    _ptrace(PTRACE_CONT, pid)
    regs = user_regs_struct()
    end_time = time.time() + timeout * 2
    while True:
        try:
            wpid, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            logging.debug("Child process %d disappeared", pid)
            break
        if wpid == 0:
            if time.time() > end_time:
                logging.debug("Coverage wait timed out")
                break
            time.sleep(0)
            continue
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            break
        if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP:
            _ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
            pc = get_pc(regs)
            addr = pc - (4 if ARCH in ("aarch64", "arm64") else 1)
            if addr in breakpoints:
                curr = addr - base
                if prev_addr is not None:
                    coverage.add((prev_addr, curr))
                prev_addr = curr
                logging.debug("Hit breakpoint at %#x", addr)
                info = breakpoints.pop(addr)
                if ARCH in ("aarch64", "arm64"):
                    word_addr, offset = info
                    orig_word, patched_word, patches = word_cache[word_addr]
                    if offset == 0:
                        patched_word = (patched_word & ~0xFFFFFFFF) | (orig_word & 0xFFFFFFFF)
                    else:
                        patched_word = (patched_word & 0xFFFFFFFF) | (orig_word & 0xFFFFFFFF00000000)
                    patches.discard(offset)
                    if not patches:
                        _ptrace_poke(pid, word_addr, orig_word)
                        del word_cache[word_addr]
                    else:
                        _ptrace_poke(pid, word_addr, patched_word)
                        word_cache[word_addr] = (orig_word, patched_word, patches)
                    set_pc(regs, addr)
                else:
                    _ptrace_poke(pid, addr, info)
                    set_pc(regs, addr)
                _ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))
                _ptrace(PTRACE_SINGLESTEP, pid)
                os.waitpid(pid, 0)
            _ptrace(PTRACE_CONT, pid)

    try:
        for addr, info in breakpoints.items():
            try:
                if ARCH in ("aarch64", "arm64"):
                    word_addr, offset = info
                    orig_word, patched_word, patches = word_cache.get(word_addr, (0, 0, set()))
                    if offset == 0:
                        patched_word = (patched_word & ~0xFFFFFFFF) | (orig_word & 0xFFFFFFFF)
                    else:
                        patched_word = (patched_word & 0xFFFFFFFF) | (orig_word & 0xFFFFFFFF00000000)
                    patches.discard(offset)
                    if not patches:
                        _ptrace_poke(pid, word_addr, orig_word)
                        word_cache.pop(word_addr, None)
                    else:
                        _ptrace_poke(pid, word_addr, patched_word)
                        word_cache[word_addr] = (orig_word, patched_word, patches)
                else:
                    _ptrace_poke(pid, addr, info)
            except OSError as e:
                if e.errno == errno.ESRCH:
                    logging.debug(
                        "Process %d disappeared while restoring breakpoints", pid
                    )
                    break
                logging.debug("Failed to restore breakpoint at %#x: %s", addr, e)
        _ptrace(PTRACE_DETACH, pid)
        logging.debug("Detached from pid %d", pid)
    except OSError as e:
        logging.debug("Failed to detach from pid %d: %s", pid, e)

    logging.debug("Collected %d basic block transitions", len(coverage))
    return coverage
