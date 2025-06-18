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

        exe_path = self._resolve_exe(pid, exe) # Renamed to avoid conflict with outer scope 'exe' in loops
        effective_libs = libs or []

        if not already_traced:
            try:
                _ptrace(PTRACE_ATTACH, pid)
                logging.debug("Attached to pid %d", pid)
            except OSError as e:
                logging.error("PTRACE_ATTACH failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                return coverage # Cannot continue if attach fails
            try:
                os.waitpid(pid, 0) # Wait for SIGSTOP after attach
            except OSError as e:
                logging.warning("os.waitpid after PTRACE_ATTACH failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                # Potentially problematic, but might recover or fail later.
            except ChildProcessError as e:
                 logging.warning("Child process %d disappeared after PTRACE_ATTACH: %s", pid, e)
                 return coverage # Cannot continue

        # Variable 'base_address' will be defined by the new entry point logic.
        # It will store the base address of the main executable.
        base_address = 0
        orig_byte_at_entry = -1 # Sentinel for cleanup check in entry point logic
        actual_entry_point = 0 # Will be determined

        # --- New entry point handling logic ---
        if exe_path: # Only proceed if we have a valid executable path
            try:
                with open(exe_path, "rb") as f:
                    elffile = ELFFile(f)
                    entry_point_offset = elffile.header.e_entry

                    # Determine the actual base address using self._get_image_base
                    # This is important because the new logic needs it before modules list is built.
                    base_address = self._get_image_base(pid, exe_path)

                    if elffile.header.e_type == 'ET_DYN': # Position Independent Executable
                        if base_address == 0: # Must have a non-zero base for PIE
                             logging.error("Executable %s is PIE (ET_DYN) but base address is 0. Cannot reliably calculate entry point.", exe_path)
                             # Not returning coverage yet, will let it fall through to general breakpointing if user wants to risk it
                             # but entry point BP part will be skipped.
                        else:
                            actual_entry_point = base_address + entry_point_offset
                            logging.info("PIE executable %s: e_entry %#x, base_address %#x, actual_entry_point %#x", exe_path, entry_point_offset, base_address, actual_entry_point)
                    elif elffile.header.e_type == 'ET_EXEC': # Non-PIE
                        actual_entry_point = entry_point_offset # e_entry is absolute VA
                        logging.info("Non-PIE executable %s: e_entry (absolute VA) is %#x. Base address from maps is %#x (may differ).", exe_path, actual_entry_point, base_address)
                        # If base_address from maps is 0 for non-PIE, it's fine if linked low.
                        # If base_address is non-zero, it's the load addr of first segment. actual_entry_point is absolute.
                    else:
                        logging.error("Unsupported ELF type %s for %s. Cannot determine entry point.", elffile.header.e_type, exe_path)
                        actual_entry_point = 0 # Mark as undetermined

                if actual_entry_point != 0: # Proceed only if entry point was determined
                    logging.debug("Setting temporary breakpoint at program entry point %#x for pid %d", actual_entry_point, pid)
                    orig_byte_at_entry = _ptrace_peek(pid, actual_entry_point)
                    _ptrace_poke(pid, actual_entry_point, (orig_byte_at_entry & ~0xFF) | BREAKPOINT)

                    logging.debug("Continuing process %d to hit temporary entry point breakpoint", pid)
                    _ptrace(PTRACE_CONT, pid, 0, 0)

                    temp_wpid, temp_status = os.waitpid(pid, 0) # Blocking wait
                    logging.info("Initial run to entry point for pid %d: wpid=%d, status=%s (raw: %d)", pid, temp_wpid, hex(temp_status), temp_status)

                    if os.WIFSTOPPED(temp_status) and os.WSTOPSIG(temp_status) == signal.SIGTRAP:
                        _ptrace(PTRACE_GETREGS, temp_wpid, 0, ctypes.addressof(regs))
                        pc = get_pc(regs)
                        expected_pc_after_bp = actual_entry_point + (4 if ARCH in ('aarch64', 'arm64') else 1)
                        # Check if PC is at or immediately after the breakpoint
                        if pc == expected_pc_after_bp or pc == actual_entry_point:
                             logging.info("Hit temporary entry point breakpoint for pid %d at PC: %#x", temp_wpid, pc)
                        else:
                             logging.warning("Hit temporary breakpoint for pid %d. PC is %#x, expected around %#x. Continuing as if at entry.",
                                          temp_wpid, pc, actual_entry_point)

                        _ptrace_poke(pid, actual_entry_point, orig_byte_at_entry) # Restore original byte
                        orig_byte_at_entry = -1 # Mark as restored
                        set_pc(regs, actual_entry_point) # Set PC back to the actual entry point
                        _ptrace(PTRACE_SETREGS, temp_wpid, 0, ctypes.addressof(regs))
                        logging.info("Successfully stopped at entry point. Now proceeding to insert main coverage breakpoints for pid %d.", pid)
                    elif os.WIFSIGNALED(temp_status):
                        term_sig = os.WTERMSIG(temp_status)
                        sig_name = signal.Signals(term_sig).name if term_sig in signal.Signals else str(term_sig)
                        logging.error("Process %d terminated by signal %s (%d) while running to entry point. Cannot collect coverage.", pid, sig_name, term_sig)
                        if orig_byte_at_entry != -1: _ptrace_poke(pid, actual_entry_point, orig_byte_at_entry)
                        return coverage
                    else:
                        logging.error("Process %d stopped/exited unexpectedly (status %s) while running to entry point. Cannot collect coverage.", pid, hex(temp_status))
                        if orig_byte_at_entry != -1: _ptrace_poke(pid, actual_entry_point, orig_byte_at_entry)
                        return coverage
                else: # actual_entry_point is 0 (e.g. unsupported ELF or PIE with base 0)
                    logging.warning("Entry point not determined or invalid for %s. Skipping temporary breakpoint.", exe_path)

            except FileNotFoundError as e:
                logging.error("ELF file %s not found for entry point detection: %s", exe_path, e)
                # base_address might not be set here, ensure it's initialized if we fall through
                if 'base_address' not in locals(): base_address = self._get_image_base(pid, exe_path) if exe_path else 0
            except OSError as e:
                logging.error("OSError during entry point handling for pid %d (errno %d: %s): %s.", pid, e.errno, os.strerror(e.errno), e)
                if orig_byte_at_entry != -1:
                    try: _ptrace_poke(pid, actual_entry_point, orig_byte_at_entry)
                    except Exception as e_cleanup: logging.debug("Cleanup poke failed: %s", e_cleanup)
                # Fall through to general breakpointing, base_address might be inaccurate or 0
                if 'base_address' not in locals(): base_address = self._get_image_base(pid, exe_path) if exe_path else 0
            except Exception as e_gen:
                logging.error("Unexpected error during entry point handling for %s (pid %d): %s", exe_path, pid, e_gen)
                if orig_byte_at_entry != -1:
                    try: _ptrace_poke(pid, actual_entry_point, orig_byte_at_entry)
                    except Exception: pass
                if 'base_address' not in locals(): base_address = self._get_image_base(pid, exe_path) if exe_path else 0
        elif not exe_path: # exe_path was None from the start
             logging.warning("exe_path is None, skipping entry point logic. Base address will be 0.")
             base_address = 0 # Ensure base_address is 0 if no exe_path
        # --- End of new entry point handling logic ---

        modules = []
        if exe_path: # Use the base_address determined (or defaulted) above
            if base_address == 0 and exe_path: # Log if base is still 0 after entry logic for a valid exe_path
                 logging.warning("Base address for main module %s is 0 before inserting final breakpoints.", exe_path)
            modules.append((exe_path, base_address))

        if effective_libs:
            # CRITICAL: Process is STOPPED here if entry point logic succeeded.
            # _wait_for_libraries (especially Linux r_brk impl) needs to run/step the process.
            # This will require careful modification of _wait_for_libraries or a change in strategy here.
            # For now, logging this potential issue.
            logging.debug("Calling _wait_for_libraries for pid %d while process is potentially stopped at entry point.", pid)
            modules.extend(self._wait_for_libraries(pid, effective_libs, timeout))

        logging.debug("Inserting breakpoints for block coverage")
        blocks_for_module_map = {}
        for path, mbase in modules:
            current_blocks = get_basic_blocks(path)
            blocks_for_module_map[(path, mbase)] = current_blocks
            logging.debug("Found %d basic blocks for %s", len(current_blocks), path)

        breakpoints = {}
        for (module_path, module_base), module_blocks in blocks_for_module_map.items():
            for offset_in_module in module_blocks:
                b = module_base + offset_in_module
                logging.debug("Inserting breakpoint at %#x for module %s (base %#x, offset %#x)", b, module_path, module_base, offset_in_module)
                try:
                    if ARCH in ("aarch64", "arm64"):
                        word_addr = b & ~7
                        bp_offset_in_word = b & 7

                        orig_word_val: int
                        patched_word_val: int
                        patches_in_word: Set[int]

                        if word_addr not in word_cache:
                            try:
                                orig_word_val = _ptrace_peek(pid, word_addr)
                                patched_word_val = orig_word_val
                                patches_in_word = set()
                            except OSError as e:
                                logging.warning("Failed to peek original instruction at %#x (errno %d: %s)", word_addr, e.errno, os.strerror(e.errno))
                                continue
                        else:
                            orig_word_val, patched_word_val, patches_in_word = word_cache[word_addr]

                        if bp_offset_in_word == 0:
                            patched_word_val = (patched_word_val & ~0xFFFFFFFF) | BREAKPOINT
                        else:
                            patched_word_val = (patched_word_val & 0xFFFFFFFF) | (BREAKPOINT << 32)

                        try:
                            _ptrace_poke(pid, word_addr, patched_word_val)
                        except OSError as e:
                            logging.warning("Failed to poke breakpoint at %#x (errno %d: %s)", word_addr, e.errno, os.strerror(e.errno))
                            continue

                        patches_in_word.add(bp_offset_in_word)
                        word_cache[word_addr] = (orig_word_val, patched_word_val, patches_in_word)
                        breakpoints[b] = (word_addr, bp_offset_in_word, module_path, module_base)
                    else: # x86
                        orig_instruction_val: int
                        try:
                            orig_instruction_val = _ptrace_peek(pid, b)
                        except OSError as e:
                            logging.warning("Failed to peek original instruction at %#x (errno %d: %s)", b, e.errno, os.strerror(e.errno))
                            continue

                        breakpoints[b] = (orig_instruction_val, module_path, module_base)

                        try:
                            _ptrace_poke(pid, b, (orig_instruction_val & ~0xFF) | BREAKPOINT)
                        except OSError as e:
                            logging.warning("Failed to poke breakpoint at %#x (errno %d: %s)", b, e.errno, os.strerror(e.errno))
                            continue
                except OSError as e: # Should not be reached if inner peeks/pokes are caught
                    logging.warning("Outer OSError when inserting breakpoint at %#x: %s (errno %d: %s)", b, e, e.errno, os.strerror(e.errno))
                    continue

        # All coverage breakpoints are now set.
        # The process was left stopped by the entry point handling logic (if successful),
        # or by _wait_for_libraries, or by the initial PTRACE_ATTACH.
        # Now, continue the process for the main coverage collection loop.
        try:
            _ptrace(PTRACE_CONT, pid)
            logging.debug("Resuming process %d for main coverage collection.", pid)
        except OSError as e:
            logging.error("PTRACE_CONT failed before main event loop for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
            # Attempt to detach and restore any breakpoints that were set
            # This cleanup is complex as breakpoints are in `breakpoints` dict and word_cache
            try:
                for bp_addr_restore, info_restore in breakpoints.items(): # Iterate over potentially set BPs
                    # Simplified restore logic here, actual restore is more complex (see end of function)
                    if ARCH in ("aarch64", "arm64"):
                        word_addr_restore, _, _, _ = info_restore
                        if word_addr_restore in word_cache:
                             _ptrace_poke(pid, word_addr_restore, word_cache[word_addr_restore][0]) # Restore original word
                    else: # x86
                         _ptrace_poke(pid, bp_addr_restore, info_restore[0]) # Restore original byte
            except Exception as e_bp_cleanup:
                logging.error("Error during breakpoint cleanup after PTRACE_CONT failure: %s", e_bp_cleanup)
            try:
                _ptrace(PTRACE_DETACH, pid)
            except OSError as e_detach:
                logging.error("PTRACE_DETACH also failed for pid %d (errno %d: %s)", pid, e_detach.errno, os.strerror(e_detach.errno))
            return coverage

        # Note: `regs` and `end_time` are already defined earlier in the function.
        while True:
            try:
                wpid, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                logging.debug("Child process %d disappeared", pid)
                break

            if wpid == 0: # Process still running
                if time.time() > end_time:
                    logging.debug("Coverage wait timed out for pid %d", pid)
                    break
                time.sleep(0) # Yield CPU
                continue

            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                logging.debug("Process %d exited or signalled. Status: %x", pid, status)
                break

            if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP:
                current_pc: int
                try:
                    _ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
                    current_pc = get_pc(regs)
                except OSError as e:
                    logging.warning("PTRACE_GETREGS failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                    break

                # PC points to instruction *after* breakpoint on x86, *on* breakpoint for ARM64 HWBK (but we use SWBK)
                # For software breakpoints (INT3 on x86, BRK on ARM), PC is incremented by trap.
                # So, breakpoint address is PC - instruction_size_of_breakpoint.
                bp_addr = current_pc - (4 if ARCH in ("aarch64", "arm64") else 1)

                if bp_addr in breakpoints:
                    info = breakpoints.pop(bp_addr)

                    mod_path_hit: str
                    mod_base_hit: int

                    if ARCH in ("aarch64", "arm64"):
                        word_addr, offset_in_word, mod_path_hit, mod_base_hit = info
                        orig_word_val, patched_word_val, patches_in_word = word_cache[word_addr]

                        # Restore part of the original word
                        if offset_in_word == 0:
                            patched_word_val = (patched_word_val & ~0xFFFFFFFF) | (orig_word_val & 0xFFFFFFFF)
                        else:
                            patched_word_val = (patched_word_val & 0xFFFFFFFF) | (orig_word_val & 0xFFFFFFFF00000000)

                        patches_in_word.discard(offset_in_word)

                        try:
                            if not patches_in_word: # Last breakpoint in this word
                                _ptrace_poke(pid, word_addr, orig_word_val)
                                del word_cache[word_addr]
                            else: # Other breakpoints still exist in this word
                                _ptrace_poke(pid, word_addr, patched_word_val)
                                word_cache[word_addr] = (orig_word_val, patched_word_val, patches_in_word)
                        except OSError as e:
                            logging.warning("Failed to restore instruction (poke) at %#x after breakpoint hit (errno %d: %s)", word_addr, e.errno, os.strerror(e.errno))

                        set_pc(regs, bp_addr) # Set PC back to the breakpoint address
                    else: # x86
                        orig_instruction_val, mod_path_hit, mod_base_hit = info
                        try:
                            _ptrace_poke(pid, bp_addr, orig_instruction_val)
                        except OSError as e:
                            logging.warning("Failed to restore instruction (poke) at %#x after breakpoint hit (errno %d: %s)", bp_addr, e.errno, os.strerror(e.errno))
                        set_pc(regs, bp_addr) # Set PC back to the breakpoint address

                    curr_addr_tuple = (mod_path_hit, bp_addr - mod_base_hit)
                    if prev_addr is not None:
                        coverage.add((prev_addr, curr_addr_tuple))
                    prev_addr = curr_addr_tuple
                    logging.debug("Hit breakpoint at %#x for module %s (offset %#x)", bp_addr, mod_path_hit, bp_addr - mod_base_hit)

                    try:
                        _ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))
                    except OSError as e:
                        logging.warning("PTRACE_SETREGS failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                        # This is problematic, may try to continue anyway or break

                    try:
                        _ptrace(PTRACE_SINGLESTEP, pid)
                    except OSError as e:
                        logging.warning("PTRACE_SINGLESTEP failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                        break

                    try:
                        os.waitpid(pid, 0) # Wait for trap after singlestep
                    except OSError as e:
                        logging.warning("os.waitpid after PTRACE_SINGLESTEP failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                        break
                    except ChildProcessError as e:
                        logging.debug("Child process %d disappeared after PTRACE_SINGLESTEP: %s", pid, e)
                        break
                else: # Stopped at a TRAP signal not from our breakpoint
                    logging.debug("Stopped at TRAP at %#x, not a known breakpoint. PC: %#x", bp_addr, current_pc)
                    # Potentially an issue, or an external trace/debug event. Continue execution.

            try: # Continue process after handling stop (or if not a SIGTRAP we manage)
                _ptrace(PTRACE_CONT, pid)
            except OSError as e:
                logging.warning("PTRACE_CONT in loop failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                break

        logging.debug("Coverage collection loop ended. prev_addr: %s, coverage size: %d", prev_addr, len(coverage))

        # Restore any remaining breakpoints
        try:
            for bp_addr_restore, info_restore in breakpoints.items():
                try:
                    if ARCH in ("aarch64", "arm64"):
                        word_addr_restore, offset_restore, _, _ = info_restore
                        # This part needs careful handling if word_cache was modified or deleted
                        if word_addr_restore in word_cache:
                            orig_word_val, patched_word_val, patches_in_word = word_cache[word_addr_restore]
                            if offset_restore == 0: # Restore original lower 32 bits
                                patched_word_val = (patched_word_val & ~0xFFFFFFFF) | (orig_word_val & 0xFFFFFFFF)
                            else: # Restore original upper 32 bits
                                patched_word_val = (patched_word_val & 0xFFFFFFFF) | (orig_word_val & 0xFFFFFFFF00000000)

                            patches_in_word.discard(offset_restore)
                            if not patches_in_word:
                                _ptrace_poke(pid, word_addr_restore, orig_word_val)
                                del word_cache[word_addr_restore] # Clean up if no patches left
                            else:
                                _ptrace_poke(pid, word_addr_restore, patched_word_val)
                                word_cache[word_addr_restore] = (orig_word_val, patched_word_val, patches_in_word)
                        # If word_addr_restore not in word_cache, it implies it was cleaned up after a hit, which is odd here.
                        # Or it was never properly cached due to an earlier error. Log if something seems off.
                        elif os.path.exists(f"/proc/{pid}"): # Check if process still exists
                             logging.warning("word_addr %#x not in word_cache during final restore for bp %#x", word_addr_restore, bp_addr_restore)

                    else: # x86
                        orig_instruction_val, _, _ = info_restore
                        _ptrace_poke(pid, bp_addr_restore, orig_instruction_val)
                except OSError as e:
                    if e.errno == errno.ESRCH: # Process disappeared
                        logging.debug("Process %d disappeared while restoring breakpoints", pid)
                        break
                    logging.warning("Failed to restore breakpoint at %#x (errno %d: %s)", bp_addr_restore, e.errno, os.strerror(e.errno))

            _ptrace(PTRACE_DETACH, pid)
            logging.debug("Detached from pid %d", pid)
        except OSError as e:
            if e.errno == errno.ESRCH:
                logging.debug("Process %d disappeared before final detach", pid)
            else:
                logging.warning("PTRACE_DETACH failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
        except Exception as e_final: # Catch any other unexpected error during cleanup
            logging.error("Unexpected error during final breakpoint restoration/detach: %s", e_final)


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
        end_time = time.time() + 0.1 # Short timeout for r_brk resolution
        while True:
            try:
                r_brk = _ptrace_peek(pid, r_debug_addr + brk_off)
            except OSError as e:
                logging.warning("PTRACE_PEEKTEXT failed for pid %d at %#x while getting r_brk (errno %d: %s)", pid, r_debug_addr + brk_off, e.errno, os.strerror(e.errno))
                return 0 # Cannot proceed if r_brk cannot be read
            if r_brk != 0 or time.time() >= end_time:
                if r_brk == 0: # Timed out and r_brk is still 0
                    logging.warning("Timed out waiting for _r_debug.r_brk to be set for pid %d", pid)
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
                exe_path = os.readlink(f"/proc/{pid}/exe")
            except OSError as e:
                logging.debug("Failed to read executable path for pid %d: %s (errno %d: %s)", pid, e, e.errno, os.strerror(e.errno))
                return None
        else:
            exe_path = exe

        if exe_path is not None:
            return os.path.realpath(exe_path)
        return None

    def _get_image_base(self, pid: int, exe: str) -> int:
        """Return the loaded base address for ``exe`` within ``pid``."""
        # exe is already realpath from _resolve_exe
        try:
            with open(f"/proc/{pid}/maps") as f:
                for line in f:
                    parts = line.rstrip().split(None, 5)
                    if len(parts) < 6:
                        continue
                    addr_range, perms, offset_str, _dev, _inode, path_in_map = parts
                    # Ensure path_in_map is resolved for comparison, similar to how 'exe' is resolved.
                    if os.path.realpath(path_in_map) != exe or "x" not in perms:
                        continue
                    start = int(addr_range.split("-", 1)[0], 16)
                    map_offset = int(offset_str, 16)
                    return start - map_offset # Base address = start_addr_in_mem - offset_in_file
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
                    addr_range, perms, offset_str, _dev, _inode, path_in_map = parts
                    if "x" not in perms: # Must be executable
                        continue

                    # Check if the basename or the full path (if name includes path chars) matches
                    if os.path.basename(path_in_map) == name or path_in_map.endswith("/" + name):
                        start = int(addr_range.split("-", 1)[0], 16)
                        map_offset = int(offset_str, 16)
                        # Library base is also start_addr_in_mem - offset_in_file
                        return os.path.realpath(path_in_map), start - map_offset
        except FileNotFoundError:
            logging.debug("/proc/%d/maps not found for _find_library", pid)
        return None, 0

    def _wait_for_libraries(
        self, pid: int, libs: list[str], timeout: float
    ) -> list[tuple[str, int]]:
        modules: list[tuple[str, int]] = []
        remaining = set(libs)

        # First, check if libraries are already loaded
        for lib_name in list(remaining):
            path, base = self._find_library(pid, lib_name)
            if path:
                modules.append((path, base))
                remaining.remove(lib_name)
                logging.debug("%s already loaded at %#x", path, base)
        if not remaining:
            return modules

        r_brk = self._get_r_brk(pid)
        if r_brk == 0:
            # _get_r_brk already logs, but we add context for this specific failure.
            logging.error("Unable to resolve r_brk for library instrumentation of pid %d; cannot trace library loads.", pid)
            # Proceed without library load tracing if r_brk is not available.
            # The initially found libraries (if any) will be returned.
            return modules


        orig_r_brk_instruction: int
        try:
            orig_r_brk_instruction = _ptrace_peek(pid, r_brk)
        except OSError as e:
            logging.warning("PTRACE_PEEKTEXT failed for pid %d at r_brk %#x (errno %d: %s)", pid, r_brk, e.errno, os.strerror(e.errno))
            # Cannot proceed with r_brk breakpointing if we can't read original instruction.
            return modules

        try:
            _ptrace_poke(pid, r_brk, (orig_r_brk_instruction & ~0xFF) | BREAKPOINT)
        except OSError as e:
            logging.warning("PTRACE_POKETEXT failed to set r_brk breakpoint for pid %d at %#x (errno %d: %s)", pid, r_brk, e.errno, os.strerror(e.errno))
            # Cannot proceed if breakpoint cannot be set.
            return modules

        regs = user_regs_struct()
        end_time = time.time() + timeout

        while remaining and time.time() < end_time:
            try:
                _ptrace(PTRACE_CONT, pid)
            except OSError as e:
                logging.warning("PTRACE_CONT failed for pid %d in _wait_for_libraries (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                break

            wpid, status = -1, -1
            try:
                wpid, status = os.waitpid(pid, 0) # Blocking wait for next event
            except ChildProcessError as e:
                logging.debug("Child process %d disappeared in _wait_for_libraries: %s", pid, e)
                break
            except OSError as e: # e.g. ECHILD if process already gone and we didn't catch ChildProcessError
                logging.warning("os.waitpid failed for pid %d in _wait_for_libraries (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                break

            if wpid != pid : # Should not happen with blocking waitpid unless error
                logging.error("Unexpected wpid %d (expected %d) or error in _wait_for_libraries. Status: %d", wpid, pid, status)
                break

            if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP:
                current_pc: int
                try:
                    _ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
                    current_pc = get_pc(regs)
                except OSError as e:
                    logging.warning("PTRACE_GETREGS failed for pid %d in _wait_for_libraries (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                    break

                bp_addr_hit = current_pc - (4 if ARCH in ("aarch64", "arm64") else 1)

                if bp_addr_hit == r_brk: # Hit the breakpoint on ld.so's _r_debug.r_brk
                    logging.debug("Hit r_brk breakpoint for pid %d at %#x", pid, r_brk)
                    # Check for newly loaded libraries
                    for lib_name_check in list(remaining):
                        path_check, base_check = self._find_library(pid, lib_name_check)
                        if path_check:
                            modules.append((path_check, base_check))
                            remaining.remove(lib_name_check)
                            logging.debug("%s loaded at %#x (detected via r_brk)", path_check, base_check)

                    if not remaining: # All libs found
                        break

                    # Restore r_brk, single step, then re-set breakpoint
                    set_pc(regs, r_brk) # Set PC back to r_brk address
                    try:
                        _ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))
                    except OSError as e:
                        logging.warning("PTRACE_SETREGS at r_brk failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                        # May be unrecoverable here
                        break
                    try:
                        _ptrace_poke(pid, r_brk, orig_r_brk_instruction)
                    except OSError as e:
                        logging.warning("PTRACE_POKETEXT failed to restore original r_brk instruction for pid %d at %#x (errno %d: %s)", pid, r_brk, e.errno, os.strerror(e.errno))
                        break
                    try:
                        _ptrace(PTRACE_SINGLESTEP, pid)
                    except OSError as e:
                        logging.warning("PTRACE_SINGLESTEP at r_brk failed for pid %d (errno %d: %s)", pid, e.errno, os.strerror(e.errno))
                        break
                    try:
                        os.waitpid(pid, 0) # Wait for trap after singlestep
                    except (OSError, ChildProcessError) as e:
                        logging.warning("waitpid after PTRACE_SINGLESTEP (r_brk) failed for pid %d: %s", pid, e)
                        break
                    try: # Re-set r_brk breakpoint
                        _ptrace_poke(pid, r_brk, (orig_r_brk_instruction & ~0xFF) | BREAKPOINT)
                    except OSError as e:
                        logging.warning("PTRACE_POKETEXT failed to re-set r_brk breakpoint for pid %d at %#x (errno %d: %s)", pid, r_brk, e.errno, os.strerror(e.errno))
                        break
                else:
                    # This should not happen if r_brk is the only breakpoint active at this stage.
                    # If it does, it implies another trace event or an issue.
                    logging.debug("Stopped at SIGTRAP at %#x (PC=%#x) in _wait_for_libraries, not r_brk. Continuing.", bp_addr_hit, current_pc)
                    # No PTRACE_CONT here, will be handled by the loop's PTRACE_CONT

            elif os.WIFEXITED(status) or os.WIFSIGNALED(status):
                logging.debug("Process %d exited/signalled in _wait_for_libraries. Status: %x", pid, status)
                break
            # else: process stopped for other reasons, loop will PTRACE_CONT

        # Cleanup: always try to restore original instruction at r_brk if we set a breakpoint there
        try:
            _ptrace_poke(pid, r_brk, orig_r_brk_instruction)
            logging.debug("Restored original instruction at r_brk %#x for pid %d", r_brk, pid)
        except OSError as e:
            # Log if process still exists, otherwise it's expected if process died
            if e.errno != errno.ESRCH:
                 logging.warning("PTRACE_POKETEXT failed to restore r_brk (cleanup) for pid %d at %#x (errno %d: %s)", pid, r_brk, e.errno, os.strerror(e.errno))

        if remaining:
            logging.warning("Libraries not loaded before timeout for pid %d: %s", pid, ", ".join(remaining))

        return modules


class MacOSCollector(CoverageCollector):
    """Coverage collector implementation for macOS."""

    def _resolve_exe(self, pid: int, exe: Optional[str]) -> Optional[str]:
        """Return ``exe`` resolved to an absolute path."""
        if exe is None: # On macOS, exe path is usually required upfront.
            # Attempt to get it via proc_pidpath, though it's less common to rely on this solely.
            try:
                buffer = ctypes.create_string_buffer(1024) # MAXPATHLEN
                res = libc.proc_pidpath(pid, buffer, ctypes.sizeof(buffer))
                if res > 0:
                    return os.path.realpath(buffer.value.decode())
                else:
                    logging.warning("proc_pidpath failed for pid %d (errno %d: %s)", pid, ctypes.get_errno(), os.strerror(ctypes.get_errno()))
                    raise RuntimeError(f"Executable path required for macOS and could not be resolved for pid {pid}")
            except AttributeError: # libc.proc_pidpath might not exist on older macOS or non-macOS ctypes.CDLL(None)
                 raise RuntimeError(f"Executable path required for macOS (pid {pid}, proc_pidpath not available)")

        return os.path.realpath(exe)


    def _get_image_base(self, pid: int, exe: str) -> int:
        """Return the loaded base address for ``exe`` within ``pid``."""
        # exe is already realpath from _resolve_exe
        try:
            # Using vmmap for macOS, adjust if different tools/methods are preferred
            output = subprocess.check_output(["vmmap", str(pid)], text=True, stderr=subprocess.PIPE)
            # Example vmmap output line for main executable:
            # __TEXT                 0000000100000000-0000000100004000 [   16K] r-x/r-x SM=COW          /path/to/executable
            # We need the start address of the __TEXT segment.
            for line in output.splitlines():
                if "__TEXT" in line and exe in line: # Ensure it's the main executable's __TEXT segment
                    # A more robust regex might be needed depending on vmmap variations
                    m = re.search(r"([0-9a-fA-F]+)-", line)
                    if m:
                        return int(m.group(1), 16)
        except subprocess.CalledProcessError as e:
            logging.debug("vmmap failed for pid %d: %s. Stderr: %s", pid, e, e.stderr)
        except FileNotFoundError: # vmmap not found
            logging.error("vmmap command not found, cannot determine image base on macOS.")
        except Exception as e:  # Catch other potential errors like regex issues
            logging.debug("Failed to determine image base on macOS for pid %d, exe %s: %s", pid, exe, e)

        logging.warning("Base address for %s not found on macOS for pid %d", exe, pid)
        return 0

    def _find_library(self, pid: int, name: str) -> tuple[Optional[str], int]:
        """Return the path and base for a loaded library matching ``name``."""
        try:
            output = subprocess.check_output(["vmmap", str(pid)], text=True, stderr=subprocess.PIPE)
            # Similar to _get_image_base, parse vmmap output.
            # Libraries might also be in __TEXT segments or dedicated library paths.
            # Example:
            # __TEXT                 00000001000d0000-00000001000d4000 [   16K] r-x/r-x SM=COW          /usr/lib/libSystem.B.dylib
            for line in output.splitlines():
                # Check if the library name is in the path part of the line
                if name in line and "__TEXT" in line: # A simple check, might need refinement
                    path_in_map_match = re.search(r"\s([\S]+)$", line) # Get the path at the end of the line
                    if path_in_map_match:
                        path_in_map = path_in_map_match.group(1)
                        if os.path.basename(path_in_map) == name or path_in_map.endswith("/" + name):
                            addr_match = re.search(r"([0-9a-fA-F]+)-", line)
                            if addr_match:
                                base_addr = int(addr_match.group(1), 16)
                                # On macOS, the base address reported by vmmap for __TEXT is usually the actual base.
                                return os.path.realpath(path_in_map), base_addr
        except subprocess.CalledProcessError as e:
            logging.debug("vmmap failed during _find_library for pid %d: %s. Stderr: %s", pid, e, e.stderr)
        except FileNotFoundError:
             logging.error("vmmap command not found, cannot find libraries on macOS.")
        except Exception as e:
            logging.debug("Failed to locate library %s for pid %d on macOS: %s", name, pid, e)
        return None, 0
