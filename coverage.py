import ctypes
import ctypes.util
import logging
import os
import re
import signal
import subprocess
import time


libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_PEEKTEXT = 1
PTRACE_POKETEXT = 4
PTRACE_SETREGS = 13

class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long

_block_cache = {}


def _get_image_base(pid, exe):
    """Return the load base address of *exe* in process *pid*."""
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
        pass
    return 0


def _get_basic_blocks(exe):
    """Return a sorted list of basic block addresses for *exe*."""
    if exe in _block_cache:
        logging.debug("Using cached basic blocks for %s", exe)
        return _block_cache[exe]

    logging.debug("Parsing basic blocks from %s", exe)
    try:
        output = subprocess.check_output(["objdump", "-d", exe], text=True)
    except Exception as e:
        logging.debug("Failed to disassemble %s: %s", exe, e)
        _block_cache[exe] = []
        return _block_cache[exe]

    blocks = set()
    prev_branch = True
    branch_re = re.compile(r"\b(j\w+|call|ret|syscall)\b")
    for line in output.splitlines():
        m = re.match(r"\s*([0-9a-fA-F]+):", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if prev_branch:
            blocks.add(addr)
        prev_branch = bool(branch_re.search(line))

    _block_cache[exe] = sorted(blocks)
    logging.debug("Identified %d basic blocks in %s", len(blocks), exe)
    return _block_cache[exe]

def _ptrace(request, pid, addr=0, data=0):
    """Wrapper around libc.ptrace with basic error handling."""
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


def collect_coverage(pid, timeout=1.0):
    """Record executed basic blocks from a running process."""
    logging.debug("Collecting coverage for pid %d", pid)
    coverage = set()
    _ptrace(PTRACE_ATTACH, pid)
    os.waitpid(pid, 0)
    logging.debug("Attached to pid %d", pid)

    exe = os.readlink(f"/proc/{pid}/exe")
    base = _get_image_base(pid, exe)
    logging.debug("%s loaded at %#x", exe, base)

    logging.debug("Inserting breakpoints for block coverage on %s", exe)
    blocks = _get_basic_blocks(exe)
    blocks = [base + b for b in blocks]
    breakpoints = {}
    for b in blocks:
        try:
            orig = _ptrace_peek(pid, b)
            breakpoints[b] = orig
            _ptrace_poke(pid, b, (orig & ~0xFF) | 0xCC)
            logging.debug("Breakpoint inserted at %#x", b)
        except OSError:
            continue

    _ptrace(PTRACE_CONT, pid)
    regs = user_regs_struct()
    end_time = time.time() + timeout
    while True:
        try:
            wpid, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            break
        if wpid == 0:
            if time.time() > end_time:
                logging.debug("Coverage wait timed out")
                break
            time.sleep(0.01)
            continue
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            break
        if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP:
            _ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
            addr = regs.rip - 1
            if addr in breakpoints:
                coverage.add(addr - base)
                logging.debug("Hit breakpoint at %#x", addr)
                orig = breakpoints.pop(addr)
                _ptrace_poke(pid, addr, orig)
                regs.rip = addr
                _ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))
                _ptrace(PTRACE_SINGLESTEP, pid)
                os.waitpid(pid, 0)
            _ptrace(PTRACE_CONT, pid)

    try:
        for addr, orig in breakpoints.items():
            try:
                _ptrace_poke(pid, addr, orig)
            except OSError:
                pass
        _ptrace(PTRACE_DETACH, pid)
        logging.debug("Detached from pid %d", pid)
    except OSError:
        pass
    logging.debug("Collected %d basic blocks", len(coverage))
    return coverage
