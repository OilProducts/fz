import ctypes
import logging
import os
import platform
import signal
import time
import errno
import subprocess
import re
from elftools.elf.elffile import ELFFile
from abc import ABC, abstractmethod
from typing import Optional, Set

from .cfg import Edge

from .utils import get_basic_blocks, _load_text
from .common import (
    _ptrace,
    _ptrace_peek,
    _ptrace_poke,
    PTRACE_ATTACH,
    PTRACE_DETACH,
    PTRACE_CONT,
    PTRACE_SINGLESTEP,
    PTRACE_GETREGS,
    PTRACE_SETREGS,
    BREAKPOINT,
    user_regs_struct,
    get_pc,
    set_pc,
)

ARCH = platform.machine().lower()


class CoverageCollector(ABC):
    """Base class implementing common breakpoint coverage logic."""

    @abstractmethod
    def _resolve_exe(self, pid: int, exe: Optional[str]) -> Optional[str]:
        """Return the executable path for *pid* or raise if unavailable."""

    @abstractmethod
    def _get_image_base(self, pid: int, exe: str) -> int:
        """Return the loaded base address for *exe* in *pid*."""

    @abstractmethod
    def _find_library(self, pid: int, name: str) -> tuple[Optional[str], int]:
        """Return the path and base address for a loaded library."""

    def _wait_for_libraries(
        self, pid: int, libs: list[str], timeout: float
    ) -> list[tuple[str, int]]:
        """Wait until ``libs`` are loaded in ``pid`` and return their info."""
        modules: list[tuple[str, int]] = []
        remaining = set(libs)
        end_time = time.time() + timeout
        while remaining and time.time() < end_time:
            for lib in list(remaining):
                path, base = self._find_library(pid, lib)
                if path:
                    modules.append((path, base))
                    remaining.remove(lib)
                    logging.debug("%s loaded at %#x", path, base)
            if remaining:
                try:
                    _ptrace(PTRACE_SINGLESTEP, pid)
                    os.waitpid(pid, 0)
                except OSError as e:
                    logging.debug("Failed waiting for libraries: %s", e)
                    break
        for lib in remaining:
            logging.debug("Library %s not found in process", lib)
        return modules

    def _set_breakpoint(self, pid: int, addr: int, word_cache: dict) -> tuple:
        """Insert a breakpoint at ``addr`` and return bookkeeping info."""
        if ARCH in ("aarch64", "arm64"):
            word_addr = addr & ~7
            offset = addr & 7
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
            return (word_addr, offset)
        orig = _ptrace_peek(pid, addr)
        _ptrace_poke(pid, addr, (orig & ~0xFF) | BREAKPOINT)
        return (orig,)

    def _remove_breakpoint(self, pid: int, addr: int, info: tuple, word_cache: dict) -> None:
        """Restore the instruction replaced by a breakpoint."""
        if ARCH in ("aarch64", "arm64"):
            word_addr, offset = info[:2]
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
            orig = info[0]
            _ptrace_poke(pid, addr, orig)

    def _insert_breakpoints(self, pid: int, modules: list[tuple[str, int]], word_cache: dict) -> dict:
        """Insert breakpoints for the basic blocks of ``modules``."""
        blocks: list[tuple[str, int, int, int]] = []
        for path, mbase in modules:
            try:
                _, tbase = _load_text(path)
            except Exception as e:
                logging.debug("Failed reading text base from %s: %s", path, e)
                tbase = 0
            for b in get_basic_blocks(path):
                blocks.append((path, mbase, tbase, b))
        breakpoints = {}
        for path, mbase, tbase, off in blocks:
            addr = mbase + tbase + off
            try:
                bp_info = self._set_breakpoint(pid, addr, word_cache)
                breakpoints[addr] = (*bp_info, path, mbase + tbase)
                logging.debug("Breakpoint inserted at %#x", addr)
            except OSError as e:
                logging.debug("Failed to insert breakpoint at %#x: %s", addr, e)
        return breakpoints

    def _handle_breakpoint_hit(
        self,
        pid: int,
        addr: int,
        info: tuple,
        word_cache: dict,
        regs: user_regs_struct,
    ) -> tuple[str, int]:
        """Process a breakpoint hit and single-step over it."""
        if ARCH in ("aarch64", "arm64"):
            word_addr, offset, mod_path, mod_base = info
        else:
            orig, mod_path, mod_base = info
        curr = (mod_path, addr - mod_base)
        self._remove_breakpoint(pid, addr, info, word_cache)
        set_pc(regs, addr)
        _ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))
        _ptrace(PTRACE_SINGLESTEP, pid)
        os.waitpid(pid, 0)
        return curr

    def _trace_process(
        self,
        pid: int,
        breakpoints: dict,
        word_cache: dict,
        timeout: float,
    ) -> Set[Edge]:
        """Run the tracing loop until timeout and return collected edges."""
        coverage: Set[Edge] = set()
        prev_addr: Optional[tuple[str, int]] = None
        regs = user_regs_struct()
        _ptrace(PTRACE_CONT, pid)
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
                    info = breakpoints.pop(addr)
                    curr = self._handle_breakpoint_hit(pid, addr, info, word_cache, regs)
                    if prev_addr is not None:
                        coverage.add((prev_addr, curr))
                    prev_addr = curr
            _ptrace(PTRACE_CONT, pid)
        return coverage

    def _restore_breakpoints(self, pid: int, breakpoints: dict, word_cache: dict) -> None:
        """Restore all breakpoints and detach from the process."""
        try:
            for addr, info in breakpoints.items():
                try:
                    self._remove_breakpoint(pid, addr, info, word_cache)
                except OSError as e:
                    if e.errno == errno.ESRCH:
                        logging.debug(
                            "Process %d disappeared while restoring breakpoints",
                            pid,
                        )
                        break
                    logging.debug("Failed to restore breakpoint at %#x: %s", addr, e)
            _ptrace(PTRACE_DETACH, pid)
            logging.debug("Detached from pid %d", pid)
        except OSError as e:
            logging.debug("Failed to detach from pid %d: %s", pid, e)

    def collect_coverage(
        self,
        pid: int,
        timeout: float = 1.0,
        exe: Optional[str] = None,
        already_traced: bool = False,
        libs: Optional[list[str]] = None,
    ) -> Set[Edge]:
        """Collect basic block transition coverage from a traced process.

        Parameters
        ----------
        pid:
            Identifier of the process to trace.
        timeout:
            Maximum time in seconds to wait for coverage after the process stops.
        exe:
            Path to the executable.  If ``None``, an attempt is made to resolve it
            automatically.
        already_traced:
            Set to ``True`` if the caller has already attached via ``ptrace``.

        Returns
        -------
        set[Edge]
            The set of executed basic block transitions as
            ``((module, src), (module, dst))`` pairs.
        """
        logging.debug("Collecting coverage for pid %d", pid)
        coverage: Set[Edge] = set()
        word_cache = {}

        exe = self._resolve_exe(pid, exe)
        libs = libs or []

        if not already_traced:
            _ptrace(PTRACE_ATTACH, pid)
            os.waitpid(pid, 0)
            logging.debug("Attached to pid %d", pid)

        modules = []
        base = self._get_image_base(pid, exe) if exe else 0
        if exe:
            if base == 0:
                logging.debug("Base address not found for %s", exe)
            logging.debug("%s loaded at %#x", exe, base)
            modules.append((exe, base))

        if libs:
            modules.extend(self._wait_for_libraries(pid, libs, timeout))

        logging.debug("Inserting breakpoints for block coverage")
        breakpoints = self._insert_breakpoints(pid, modules, word_cache)

        coverage = self._trace_process(pid, breakpoints, word_cache, timeout)

        self._restore_breakpoints(pid, breakpoints, word_cache)

        logging.debug("Collected %d basic block transitions", len(coverage))
        return coverage


class LinuxCollector(CoverageCollector):
    """Coverage collector implementation for Linux."""

    def _find_loader(self, pid: int) -> tuple[Optional[str], int]:
        """Return the path and base address of the dynamic loader."""
        try:
            with open(f"/proc/{pid}/maps") as f:
                for line in f:
                    parts = line.rstrip().split(None, 5)
                    if len(parts) < 6:
                        continue
                    addr_range, perms, offset, _dev, _inode, path = parts
                    if "x" not in perms:
                        continue
                    base = os.path.basename(path)
                    if base.startswith("ld-") or base.startswith("ld.") or "ld-linux" in base:
                        start = int(addr_range.split("-", 1)[0], 16)
                        off = int(offset, 16)
                        return os.path.realpath(path), start - off
        except FileNotFoundError:
            logging.debug("/proc/%d/maps not found", pid)
        return None, 0

    def _get_symbol_offset(self, path: str, name: str) -> Optional[int]:
        try:
            with open(path, "rb") as f:
                elf = ELFFile(f)
                for sec_name in (".dynsym", ".symtab"):
                    sec = elf.get_section_by_name(sec_name)
                    if sec is None:
                        continue
                    sym = sec.get_symbol_by_name(name)
                    if sym:
                        return sym[0]["st_value"]
        except Exception as e:
            logging.debug("Failed to read %s: %s", path, e)
        return None

    def _get_r_brk(self, pid: int) -> int:
        path, base = self._find_loader(pid)
        if not path:
            return 0
        offset = self._get_symbol_offset(path, "_r_debug")
        if offset is None:
            return 0
        r_debug_addr = base + offset
        ptr_size = ctypes.sizeof(ctypes.c_void_p)
        brk_off = 16 if ptr_size == 8 else 8
        end_time = time.time() + 0.1
        while True:
            try:
                r_brk = _ptrace_peek(pid, r_debug_addr + brk_off)
            except OSError as e:
                logging.debug("Failed reading r_brk: %s", e)
                return 0
            if r_brk != 0 or time.time() >= end_time:
                return r_brk
            try:
                _ptrace(PTRACE_SINGLESTEP, pid)
                os.waitpid(pid, 0)
            except OSError:
                return 0

    def _resolve_exe(self, pid: int, exe: Optional[str]) -> Optional[str]:
        """Return the executable path for ``pid`` if not provided."""
        if exe is None:
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError as e:
                logging.debug("Failed to read executable path for pid %d: %s", pid, e)
                exe = None
        if exe is not None:
            exe = os.path.realpath(exe)
        return exe

    def _get_image_base(self, pid: int, exe: str) -> int:
        """Return the loaded base address for ``exe`` within ``pid``."""
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

    def _find_library(self, pid: int, name: str) -> tuple[Optional[str], int]:
        """Return the path and base for a loaded library matching ``name``."""
        try:
            with open(f"/proc/{pid}/maps") as f:
                for line in f:
                    parts = line.rstrip().split(None, 5)
                    if len(parts) < 6:
                        continue
                    addr_range, perms, offset, _dev, _inode, path = parts
                    if "x" not in perms:
                        continue
                    base = os.path.basename(path)
                    real_base = os.path.basename(os.path.realpath(path))
                    if (
                        base == name
                        or real_base == name
                        or base.startswith(name + ".")
                        or real_base.startswith(name + ".")
                        or path.endswith(name)
                        or os.path.realpath(path).endswith(name)
                    ):
                        start = int(addr_range.split("-", 1)[0], 16)
                        off = int(offset, 16)
                        return os.path.realpath(path), start - off
        except FileNotFoundError:
            logging.debug("/proc/%d/maps not found", pid)
        return None, 0

    def _get_entry_offset(self, exe: str) -> int:
        """Return the entry point offset for ``exe``."""
        try:
            with open(exe, "rb") as f:
                elf = ELFFile(f)
                entry = elf.header["e_entry"]
                text = elf.get_section_by_name(".text")
                base = text["sh_addr"] if text is not None else 0
                return entry - base
        except Exception as e:
            logging.debug("Failed to read entry point from %s: %s", exe, e)
        return 0

    def _wait_for_libraries(
        self, pid: int, libs: list[str], timeout: float
    ) -> list[tuple[str, int]]:
        modules: list[tuple[str, int]] = []
        remaining = set(libs)

        # Resolve the main executable and its entry point
        exe = self._resolve_exe(pid, None)
        base = self._get_image_base(pid, exe) if exe else 0
        entry_off = self._get_entry_offset(exe) if exe else 0
        tbase = 0
        if exe:
            try:
                _, tbase = _load_text(exe)
            except Exception as e:
                logging.debug("Failed reading text base from %s: %s", exe, e)

        if entry_off and base:
            entry_addr = base + tbase + entry_off
            try:
                if ARCH in ("aarch64", "arm64"):
                    word_addr = entry_addr & ~7
                    offset = entry_addr & 7
                    orig_word = _ptrace_peek(pid, word_addr)
                    patched_word = orig_word
                    if offset == 0:
                        patched_word = (patched_word & ~0xFFFFFFFF) | BREAKPOINT
                    else:
                        patched_word = (patched_word & 0xFFFFFFFF) | (BREAKPOINT << 32)
                    _ptrace_poke(pid, word_addr, patched_word)
                else:
                    orig_word = _ptrace_peek(pid, entry_addr)
                    _ptrace_poke(pid, entry_addr, (orig_word & ~0xFF) | BREAKPOINT)
            except OSError as e:
                logging.debug("Failed to set entry breakpoint: %s", e)
                return modules

            regs = user_regs_struct()
            end_time = time.time() + timeout
            hit = False
            while time.time() < end_time:
                _ptrace(PTRACE_CONT, pid)
                try:
                    wpid, status = os.waitpid(pid, 0)
                except ChildProcessError:
                    break
                if wpid != pid:
                    break
                if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP:
                    _ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
                    pc = get_pc(regs)
                    addr = pc - (4 if ARCH in ("aarch64", "arm64") else 1)
                    if addr == entry_addr:
                        hit = True
                        break
            # Restore original instruction and state
            try:
                if ARCH in ("aarch64", "arm64"):
                    if offset == 0:
                        patched_word = (patched_word & ~0xFFFFFFFF) | (orig_word & 0xFFFFFFFF)
                    else:
                        patched_word = (patched_word & 0xFFFFFFFF) | (orig_word & 0xFFFFFFFF00000000)
                    _ptrace_poke(pid, word_addr, patched_word)
                else:
                    _ptrace_poke(pid, entry_addr, orig_word)
                if hit:
                    set_pc(regs, entry_addr)
                    _ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))
                    _ptrace(PTRACE_SINGLESTEP, pid)
                    os.waitpid(pid, 0)
            except OSError as e:
                logging.debug("Failed restoring entry breakpoint: %s", e)

        # With all libraries loaded, resolve their paths and bases
        for lib in list(remaining):
            path, base = self._find_library(pid, lib)
            if path:
                modules.append((path, base))
                remaining.remove(lib)

        if remaining:
            logging.debug("Libraries not found: %s", ", ".join(remaining))

        return modules


class MacOSCollector(CoverageCollector):
    """Coverage collector implementation for macOS."""

    def _resolve_exe(self, pid: int, exe: Optional[str]) -> Optional[str]:
        """Return ``exe`` resolved to an absolute path."""
        if exe is None:
            raise RuntimeError("Executable path required for macOS")
        return os.path.realpath(exe)

    def _get_image_base(self, pid: int, exe: str) -> int:
        """Return the loaded base address for ``exe`` within ``pid``."""
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

    def _find_library(self, pid: int, name: str) -> tuple[Optional[str], int]:
        """Return the path and base for a loaded library matching ``name``."""
        try:
            output = subprocess.check_output(["vmmap", str(pid)], text=True)
            for line in output.splitlines():
                if name in line and "__TEXT" in line:
                    m = re.search(r"([0-9a-fA-F]+)-", line)
                    if m:
                        return name, int(m.group(1), 16)
        except Exception as e:  # pragma: no cover - best effort for macOS
            logging.debug("Failed to locate library %s: %s", name, e)
        return None, 0

