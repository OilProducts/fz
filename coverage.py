import ctypes
import ctypes.util
import logging
import os
import platform
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

ARCH = platform.machine().lower()
IS_DARWIN = platform.system() == "Darwin"

if ARCH in ("aarch64", "arm64"):
    BREAKPOINT = 0xD4200000  # "brk #0" instruction

    class user_regs_struct(ctypes.Structure):
        _fields_ = [
            ("regs", ctypes.c_ulonglong * 31),
            ("sp", ctypes.c_ulonglong),
            ("pc", ctypes.c_ulonglong),
            ("pstate", ctypes.c_ulonglong),
        ]

    def get_pc(regs):
        return regs.pc

    def set_pc(regs, value):
        regs.pc = value
else:
    BREAKPOINT = 0xCC  # INT3

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

    def get_pc(regs):
        return regs.rip

    def set_pc(regs, value):
        regs.rip = value


libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long

_block_cache = {}
word_cache = {}


def _get_image_base(pid, exe):
    """Return the load base address of *exe* in process *pid*."""
    if not IS_DARWIN:
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
    else:  # macOS
        try:
            import lldb  # type: ignore

            dbg = lldb.SBDebugger.Create()
            dbg.SetAsync(False)
            target = dbg.CreateTarget(exe)
            err = lldb.SBError()
            process = target.AttachToProcessWithID(dbg.GetListener(), pid, err)
            if not err.Success():
                logging.debug("LLDB attach failed: %s", err.GetCString())
                lldb.SBDebugger.Destroy(dbg)
                return 0
            module = target.GetModuleAtIndex(0)
            base = module.GetObjectFileHeaderAddress().GetLoadAddress(target)
            process.Detach()
            lldb.SBDebugger.Destroy(dbg)
            return base
        except Exception as e:  # pragma: no cover - best effort for macOS
            logging.debug("Failed to determine base on macOS: %s", e)
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
    """Read a word from process *pid* at address *addr*."""
    logging.debug("peek pid=%d addr=%#x", pid, addr)
    res = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(addr), None)
    if res == -1:
        err = ctypes.get_errno()
        if err != 0:
            raise OSError(err, os.strerror(err))
    return res


def _ptrace_poke(pid, addr, data):
    """Write *data* as a word to process *pid* at address *addr*."""
    logging.debug("poke pid=%d addr=%#x data=%#x", pid, addr, data)
    res = libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if res != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return res


def collect_coverage(pid, timeout=1.0, exe=None):
    """Record executed basic blocks from a running process."""
    logging.debug("Collecting coverage for pid %d", pid)
    coverage = set()

    if exe is None:
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            exe = None

    if IS_DARWIN:
        try:
            import lldb  # type: ignore

            if exe is None:
                raise RuntimeError("Executable path required for macOS")

            dbg = lldb.SBDebugger.Create()
            dbg.SetAsync(False)
            target = dbg.CreateTarget(exe)
            err = lldb.SBError()
            process = target.AttachToProcessWithID(dbg.GetListener(), pid, err)
            if not err.Success():
                logging.debug("LLDB attach failed: %s", err.GetCString())
                lldb.SBDebugger.Destroy(dbg)
                return coverage

            base = target.GetModuleAtIndex(0).GetObjectFileHeaderAddress().GetLoadAddress(target)
            logging.debug("%s loaded at %#x", exe, base)

            blocks = _get_basic_blocks(exe)
            bps = {base + b: target.BreakpointCreateByAddress(base + b) for b in blocks}

            process.Continue()
            end_time = time.time() + timeout * 2
            while process.IsValid() and time.time() < end_time:
                state = process.GetState()
                if state in (lldb.eStateExited, lldb.eStateCrashed):
                    break
                if state == lldb.eStateStopped:
                    frame = process.GetSelectedThread().GetFrameAtIndex(0)
                    addr = frame.GetPC()
                    if addr in bps:
                        coverage.add(addr - base)
                        target.BreakpointDelete(bps[addr].GetID())
                        process.StepInstruction(False)
                    process.Continue()
                else:
                    time.sleep(0.01)

            process.Detach()
            lldb.SBDebugger.Destroy(dbg)
            logging.debug("Collected %d coverage entries", len(coverage))
            return coverage
        except Exception as e:  # pragma: no cover - best effort for macOS
            logging.debug("macOS coverage failed: %s", e)
            return set()

    _ptrace(PTRACE_ATTACH, pid)
    os.waitpid(pid, 0)
    logging.debug("Attached to pid %d", pid)

    base = _get_image_base(pid, exe) if exe else 0
    logging.debug("%s loaded at %#x", exe, base)

    logging.debug("Inserting breakpoints for block coverage on %s", exe)
    blocks = _get_basic_blocks(exe)
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
        except OSError:
            continue

    _ptrace(PTRACE_CONT, pid)
    regs = user_regs_struct()
    end_time = time.time() + timeout * 2
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
            pc = get_pc(regs)
            addr = pc - (4 if ARCH in ("aarch64", "arm64") else 1)
            if addr in breakpoints:
                coverage.add(addr - base)
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
            except OSError:
                pass
        _ptrace(PTRACE_DETACH, pid)
        logging.debug("Detached from pid %d", pid)
    except OSError:
        pass
    logging.debug("Collected %d basic blocks", len(coverage))
    return coverage
