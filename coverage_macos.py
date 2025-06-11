import logging
import os
import time

from coverage_utils import get_basic_blocks


def _get_image_base(pid, exe):
    exe = os.path.realpath(exe)
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
    logging.debug("Base address for %s not found on macOS", exe)
    return 0


def collect_coverage(pid, timeout=1.0, exe=None):
    logging.debug("Collecting coverage for pid %d (macOS)", pid)
    coverage = set()

    if exe is None:
        raise RuntimeError("Executable path required for macOS")

    exe = os.path.realpath(exe)

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
            return coverage

        base = target.GetModuleAtIndex(0).GetObjectFileHeaderAddress().GetLoadAddress(target)
        if base == 0:
            logging.debug("Base address not found for %s", exe)
        logging.debug("%s loaded at %#x", exe, base)

        blocks = get_basic_blocks(exe)
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
                time.sleep(0)

        process.Detach()
        lldb.SBDebugger.Destroy(dbg)
        logging.debug("Collected %d coverage entries", len(coverage))
        return coverage
    except Exception as e:  # pragma: no cover - best effort for macOS
        logging.debug("macOS coverage failed: %s", e)
        return set()
