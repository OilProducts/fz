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

from .utils import get_basic_blocks
from .common import _ptrace, _ptrace_peek, _ptrace_poke

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
                except OSError as e:
                    logging.warning("PTRACE_SINGLESTEP failed for pid %d while waiting for libraries (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                    break
                try:
                    os.waitpid(pid, 0)
                except OSError as e:
                    logging.warning("os.waitpid failed for pid %d while waiting for libraries (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                    break
                except ChildProcessError as e: # Already handled, but good to be explicit
                    logging.debug("Child process %d disappeared while waiting for libraries: %s", pid, e)
                    break
        for lib in remaining:
            logging.debug("Library %s not found in process", lib)
        return modules

    def collect_coverage(
        self,
        pid: int,
        timeout: float = 1.0,
        exe: Optional[str] = None,
        already_traced: bool = False,
        libs: Optional[list[str]] = None,
    ) -> Set[tuple[tuple[str, int], tuple[str, int]]]:
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
        set[tuple[tuple[str, int], tuple[str, int]]]
            The set of executed basic block transitions as
            ``((module, src), (module, dst))`` pairs.
        """
        logging.debug("Collecting coverage for pid %d", pid)
        coverage: Set[tuple[tuple[str, int], tuple[str, int]]] = set()
        prev_addr: Optional[tuple[str, int]] = None
        word_cache = {}

        exe = self._resolve_exe(pid, exe)
        libs = libs or []

        if not already_traced:
            try:
                _ptrace(PTRACE_ATTACH, pid)
                logging.debug("Attached to pid %d", pid)
            except OSError as e:
                logging.error("PTRACE_ATTACH failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                # If attach fails, we probably can't continue, but let it try and fail later if needed.
                pass # Or raise an error here
            try:
                os.waitpid(pid, 0) # Wait for SIGSTOP after attach
            except OSError as e:
                logging.warning("os.waitpid after PTRACE_ATTACH failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
            except ChildProcessError as e:
                 logging.warning("Child process %d disappeared after PTRACE_ATTACH: %s", pid, e)


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
        blocks_for_module_map = {}
        for path, mbase in modules:
            current_blocks = get_basic_blocks(path)
            blocks_for_module_map[(path, mbase)] = current_blocks
            logging.debug("Found %d basic blocks for %s", len(current_blocks), path)

        breakpoints = {}
        for (path, mbase), module_blocks in blocks_for_module_map.items():
            for off in module_blocks:
                b = mbase + off
                logging.debug("Inserting breakpoint at %#x for module %s (base %#x, offset %#x)", b, path, mbase, off)
                try:
                    if ARCH in ("aarch64", "arm64"):
                    word_addr = b & ~7
                    bp_offset_in_word = b & 7
                    if word_addr not in word_cache:
                        try:
                            orig_word = _ptrace_peek(pid, word_addr)
                        except OSError as e:
                            logging.warning("Failed to peek original instruction at %#x (errno %d: %s)", word_addr, e.errno, os.strerror(e.errno))
                            continue
                        patched_word = orig_word
                        patches = set()
                    else:
                        orig_word, patched_word, patches = word_cache[word_addr]
                    if bp_offset_in_word == 0:
                        patched_word = (patched_word & ~0xFFFFFFFF) | BREAKPOINT
                    else:
                        patched_word = (patched_word & 0xFFFFFFFF) | (BREAKPOINT << 32)
                    try:
                        _ptrace_poke(pid, word_addr, patched_word)
                    except OSError as e:
                        logging.warning("Failed to poke breakpoint at %#x (errno %d: %s)", word_addr, e.errno, os.strerror(e.errno))
                        continue
                    patches.add(bp_offset_in_word)
                    word_cache[word_addr] = (orig_word, patched_word, patches)
                    breakpoints[b] = (word_addr, bp_offset_in_word, path, mbase)
                else:
                    try:
                        orig = _ptrace_peek(pid, b)
                    except OSError as e:
                        logging.warning("Failed to peek original instruction at %#x (errno %d: %s)", b, e.errno, os.strerror(e.errno))
                        continue
                    breakpoints[b] = (orig, path, mbase)
                    try:
                        _ptrace_poke(pid, b, (orig & ~0xFF) | BREAKPOINT)
                    except OSError as e:
                        logging.warning("Failed to poke breakpoint at %#x (errno %d: %s)", b, e.errno, os.strerror(e.errno))
                        continue
            except OSError as e:
                # This logging is for other OSErrors not caught by specific peek/poke errors
                logging.warning("Failed to insert breakpoint at %#x: %s", b, e)
                continue
        try:
            _ptrace(PTRACE_CONT, pid)
        except OSError as e:
            logging.error("Initial PTRACE_CONT failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
            # Attempt to detach and return if cont fails
            try:
                _ptrace(PTRACE_DETACH, pid)
            except OSError as e_detach:
                logging.error("PTRACE_DETACH also failed for pid %d (errno %d: %s)", pid, e_detach.errno, os.strerror(e_detach.errno))
            return coverage # Return whatever was collected so far, likely empty

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
                logging.debug("Process exited or signalled.")
                break
            if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP:
                try:
                    _ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
                except OSError as e:
                    logging.warning("PTRACE_GETREGS failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                    break # Difficult to continue if we can't get PC
                pc = get_pc(regs)
                addr = pc - (4 if ARCH in ("aarch64", "arm64") else 1)
                if addr in breakpoints:
                    info = breakpoints.pop(addr)
                    if ARCH in ("aarch64", "arm64"):
                        word_addr, offset, mod_path, mod_base = info
                    else:
                        orig, mod_path, mod_base = info
                    curr = (mod_path, addr - mod_base)
                    if prev_addr is not None:
                        coverage.add((prev_addr, curr))
                    prev_addr = curr
                    # Effective "Hit breakpoint" log
                    logging.debug("Hit breakpoint at %#x for module %s (offset %#x)", addr, mod_path, addr - mod_base)
                    if ARCH in ("aarch64", "arm64"):
                        orig_word, patched_word, patches = word_cache[word_addr]
                        if offset == 0:
                            patched_word = (patched_word & ~0xFFFFFFFF) | (orig_word & 0xFFFFFFFF)
                        else:
                            patched_word = (patched_word & 0xFFFFFFFF) | (orig_word & 0xFFFFFFFF00000000)
                        patches.discard(offset)
                        try:
                            if not patches:
                                _ptrace_poke(pid, word_addr, orig_word)
                                del word_cache[word_addr]
                            else:
                                _ptrace_poke(pid, word_addr, patched_word)
                                word_cache[word_addr] = (orig_word, patched_word, patches)
                        except OSError as e:
                            logging.warning("Failed to restore instruction (poke) at %#x after breakpoint hit (errno %d: %s)", word_addr, e.errno, os.strerror(e.errno))
                        set_pc(regs, addr)
                    else:
                        try:
                            _ptrace_poke(pid, addr, orig)
                        except OSError as e:
                            logging.warning("Failed to restore instruction (poke) at %#x after breakpoint hit (errno %d: %s)", addr, e.errno, os.strerror(e.errno))
                        set_pc(regs, addr)
                    try:
                        _ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))
                    except OSError as e:
                        logging.warning("PTRACE_SETREGS failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                        # Try to continue without setting PC if this fails, might lead to issues
                    try:
                        _ptrace(PTRACE_SINGLESTEP, pid)
                    except OSError as e:
                        logging.warning("PTRACE_SINGLESTEP failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                        break # If singlestep fails, we can't reliably continue
                    try:
                        os.waitpid(pid, 0) # Wait for trap after singlestep
                    except OSError as e:
                        logging.warning("os.waitpid after PTRACE_SINGLESTEP failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                        break
                    except ChildProcessError as e:
                        logging.debug("Child process %d disappeared after PTRACE_SINGLESTEP: %s", pid, e)
                        break
            try:
                _ptrace(PTRACE_CONT, pid)
            except OSError as e:
                logging.warning("PTRACE_CONT in loop failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                break # Exit loop if we can't continue the process
        logging.debug("Coverage collection loop ended. prev_addr: %s, coverage size: %d", prev_addr, len(coverage))

        try:
            for addr, info in breakpoints.items():
                try:
                    if ARCH in ("aarch64", "arm64"):
                        word_addr, offset, _mod_path, _mod_base = info
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
                        orig, _mod_path, _mod_base = info
                        _ptrace_poke(pid, addr, orig)
                except OSError as e:
                    if e.errno == errno.ESRCH:
                        logging.debug("Process %d disappeared while restoring breakpoints", pid)
                        break
                    # Simplified logging for restore, specific peek/poke handled during insertion/hit
                    logging.warning("Failed to restore breakpoint at %#x (errno %d: %s)", addr, e.errno, os.strerror(e.errno))
            try:
                _ptrace(PTRACE_DETACH, pid)
                logging.debug("Detached from pid %d", pid)
            except OSError as e:
                logging.warning("PTRACE_DETACH failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))

        logging.debug("Returning %d coverage transitions.", len(coverage))
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
                logging.warning("PTRACE_PEEKTEXT failed for pid %d at %#x while getting r_brk (errno %d: %s)", pid, r_debug_addr + brk_off, e.errno, os.strerror(e.errno))
                return 0
            if r_brk != 0 or time.time() >= end_time:
                return r_brk
            try:
                _ptrace(PTRACE_SINGLESTEP, pid)
            except OSError as e:
                logging.warning("PTRACE_SINGLESTEP failed for pid %d in _get_r_brk (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                return 0
            try:
                os.waitpid(pid, 0)
            except OSError as e:
                logging.warning("os.waitpid failed for pid %d in _get_r_brk (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                return 0
            except ChildProcessError as e:
                logging.debug("Child process %d disappeared in _get_r_brk: %s", pid, e)
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
                    if os.path.basename(path) == name or path.endswith(name):
                        start = int(addr_range.split("-", 1)[0], 16)
                        off = int(offset, 16)
                        return os.path.realpath(path), start - off
        except FileNotFoundError:
            logging.debug("/proc/%d/maps not found", pid)
        return None, 0

    def _wait_for_libraries(
        self, pid: int, libs: list[str], timeout: float
    ) -> list[tuple[str, int]]:
        modules: list[tuple[str, int]] = []
        remaining = set(libs)
        for lib in list(remaining):
            path, base = self._find_library(pid, lib)
            if path:
                modules.append((path, base))
                remaining.remove(lib)
        if not remaining:
            return modules

        r_brk = self._get_r_brk(pid)
        if r_brk == 0:
            raise RuntimeError("unable to resolve r_brk for library instrumentation")

        try:
            orig = _ptrace_peek(pid, r_brk)
        except OSError as e:
            logging.warning("PTRACE_PEEKTEXT failed for pid %d at r_brk %#x (errno %d: %s)", pid, r_brk, e.errno, os.strerror(e.errno))
            raise RuntimeError(f"failed to peek r_brk for library instrumentation (pid {pid}, addr {r_brk:#x})") from e
        try:
            _ptrace_poke(pid, r_brk, (orig & ~0xFF) | BREAKPOINT)
        except OSError as e:
            logging.warning("PTRACE_POKETEXT failed for pid %d at r_brk %#x (errno %d: %s)", pid, r_brk, e.errno, os.strerror(e.errno))
            raise RuntimeError(f"failed to set r_brk breakpoint for library instrumentation (pid {pid}, addr {r_brk:#x})") from e

        regs = user_regs_struct()
        end_time = time.time() + timeout
        while remaining and time.time() < end_time:
            try:
                _ptrace(PTRACE_CONT, pid)
            except OSError as e:
                logging.warning("PTRACE_CONT failed for pid %d in _wait_for_libraries (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                break
            try:
                wpid, status = os.waitpid(pid, 0)
            except ChildProcessError as e:
                logging.debug("Child process %d disappeared in _wait_for_libraries: %s", pid, e)
                break
            except OSError as e:
                logging.warning("os.waitpid failed for pid %d in _wait_for_libraries (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                break

            if wpid != pid:
                logging.debug("Unexpected wpid %d (expected %d) in _wait_for_libraries", wpid, pid)
                break
            if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP:
                try:
                    _ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
                except OSError as e:
                    logging.warning("PTRACE_GETREGS failed for pid %d in _wait_for_libraries (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                    break
                pc = get_pc(regs)
                addr = pc - (4 if ARCH in ("aarch64", "arm64") else 1)
                if addr == r_brk:
                    for lib in list(remaining):
                        path, base = self._find_library(pid, lib)
                        if path:
                            modules.append((path, base))
                            remaining.remove(lib)
                            logging.debug("%s loaded at %#x (via r_brk)", path, base)
                    set_pc(regs, addr)
                    try:
                        _ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))
                    except OSError as e:
                        logging.warning("PTRACE_SETREGS failed for pid %d at r_brk restore (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                        # Attempt to continue, but state might be inconsistent
                    try:
                        _ptrace_poke(pid, r_brk, orig) # Restore original instruction at r_brk
                    except OSError as e:
                        logging.warning("PTRACE_POKETEXT failed to restore original r_brk instruction for pid %d at %#x (errno %d: %s)", pid, r_brk, e.errno, os.strerror(e.errno))
                        break # Critical, can't reliably continue stepping here
                    try:
                        _ptrace(PTRACE_SINGLESTEP, pid)
                    except OSError as e:
                        logging.warning("PTRACE_SINGLESTEP failed for pid %d after r_brk hit (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                        break
                    try:
                        os.waitpid(pid, 0) # Wait for trap after singlestep
                    except OSError as e:
                        logging.warning("os.waitpid after PTRACE_SINGLESTEP (r_brk) failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                        break
                    except ChildProcessError as e:
                        logging.debug("Child process %d disappeared after PTRACE_SINGLESTEP (r_brk): %s", pid, e)
                        break
                    try:
                        _ptrace_poke(pid, r_brk, (orig & ~0xFF) | BREAKPOINT) # Re-set r_brk breakpoint
                    except OSError as e:
                        logging.warning("PTRACE_POKETEXT failed to re-set r_brk breakpoint for pid %d at %#x (errno %d: %s)", pid, r_brk, e.errno, os.strerror(e.errno))
                        break # Critical, can't ensure future library loads are caught
            else: # Process stopped for reason other than SIGTRAP at r_brk
                logging.debug("Process %d stopped in _wait_for_libraries, not at r_brk. Status: %x", pid, status)
                break

        try:
            _ptrace_poke(pid, r_brk, orig) # Ensure original instruction is restored if loop terminates early
        except OSError as e:
            logging.warning("PTRACE_POKETEXT failed to restore r_brk (cleanup) for pid %d at %#x (errno %d: %s)", pid, r_brk, e.errno, os.strerror(e.errno))

        if remaining:
            logging.debug("Libraries not loaded before timeout: %s", ", ".join(remaining))

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

