import ctypes
import ctypes.util
import logging
import os
import platform
import re
import signal
import subprocess
import time

from coverage_utils import get_basic_blocks

ARCH = platform.machine().lower()
if ARCH in ("aarch64", "arm64"):
    import arch_arm64 as arch
else:
    import arch_x86 as arch

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_PEEKTEXT = 1
PTRACE_POKETEXT = 4
PTRACE_SETREGS = 13

BREAKPOINT = arch.BREAKPOINT
user_regs_struct = arch.user_regs_struct
get_pc = arch.get_pc
set_pc = arch.set_pc

word_cache = {}


def _ptrace(request, pid, addr=0, data=0):
    logging.debug(
        "ptrace request=%d pid=%d addr=%#x data=%#x",
        request,
        pid,
        addr,
        data,
    )
    res = libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if res != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return res


def _ptrace_peek(pid, addr):
    logging.debug("peek pid=%d addr=%#x", pid, addr)
    res = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(addr), None)
    if res == -1:
        err = ctypes.get_errno()
        if err != 0:
            raise OSError(err, os.strerror(err))
    return res


def _ptrace_poke(pid, addr, data):
    logging.debug("poke pid=%d addr=%#x data=%#x", pid, addr, data)
    res = libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if res != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return res


def _get_image_base(pid, exe):
    exe = os.path.realpath(exe)
    try:
        output = subprocess.check_output(["vmmap", str(pid)], text=True)
        for line in output.splitlines():
            if "__TEXT" in line and exe in line:
                m = re.search(r"([0-9a-fA-F]+)-", line)
                if m:
                    return int(m.group(1), 16)
    except Exception as e:  # pragma: no cover - best effort for macOS
        logging.debug("Failed to determine base on macOS: %s", e)
    logging.debug("Base address for %s not found on macOS", exe)
    return 0


def collect_coverage(pid, timeout=1.0, exe=None):
    logging.debug("Collecting coverage for pid %d (macOS ptrace)", pid)
    coverage = set()
    prev_addr = None

    if exe is None:
        raise RuntimeError("Executable path required for macOS")

    exe = os.path.realpath(exe)

    _ptrace(PTRACE_ATTACH, pid)
    os.waitpid(pid, 0)
    logging.debug("Attached to pid %d", pid)

    base = _get_image_base(pid, exe)
    if base == 0:
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
                logging.debug("Failed to restore breakpoint at %#x: %s", addr, e)
        _ptrace(PTRACE_DETACH, pid)
        logging.debug("Detached from pid %d", pid)
    except OSError as e:
        logging.debug("Failed to detach from pid %d: %s", pid, e)

    logging.debug("Collected %d basic block transitions", len(coverage))
    return coverage
