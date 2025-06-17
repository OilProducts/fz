import ctypes
import os
import signal
import pytest

from fz.coverage.collector import (
    LinuxCollector,
    MacOSCollector,
    PTRACE_GETREGS,
    PTRACE_SETREGS,
)
from fz.coverage import collector as collector_module
from fz.coverage.utils import get_basic_blocks
from fz.arch import x86 as arch


def _mock_environment(monkeypatch, blocks):
    state = {"i": 0}

    def fake_ptrace(request, pid, addr=0, data=0):
        if request == PTRACE_GETREGS:
            ctypes.cast(data, ctypes.POINTER(arch.user_regs_struct)).contents.rip = blocks[state["i"]] + 1
        elif request == PTRACE_SETREGS:
            state["i"] += 1
        return 0

    monkeypatch.setattr(collector_module, "_ptrace", fake_ptrace)
    monkeypatch.setattr(collector_module, "_ptrace_peek", lambda pid, addr: 0)
    monkeypatch.setattr(collector_module, "_ptrace_poke", lambda pid, addr, data: 0)
    monkeypatch.setattr(os, "waitpid", lambda pid, opts: next(events))

    def fake_wait_libs(self, pid, libs, timeout):
        modules = []
        for lib in libs:
            path, base = self._find_library(pid, lib)
            if path:
                modules.append((path, base))
        return modules

    monkeypatch.setattr(collector_module.CoverageCollector, "_wait_for_libraries", fake_wait_libs)


def test_linux_collector(monkeypatch, tiny_binary):
    exe = str(tiny_binary)
    blocks = get_basic_blocks(exe)
    collector = LinuxCollector()

    global events
    events = iter([
        (1234, (signal.SIGTRAP << 8) | 0x7F),
        (1234, 0),
        (1234, (signal.SIGTRAP << 8) | 0x7F),
        (1234, 0),
        (1234, 0),
    ])

    _mock_environment(monkeypatch, blocks)
    monkeypatch.setattr(LinuxCollector, "_get_image_base", lambda self, pid, exe: 0)

    edges = collector.collect_coverage(1234, exe=exe, already_traced=True)
    assert edges == {((exe, blocks[0]), (exe, blocks[1]))}


def test_macos_collector(monkeypatch, tiny_binary):
    exe = str(tiny_binary)
    blocks = get_basic_blocks(exe)
    collector = MacOSCollector()

    global events
    events = iter([
        (1234, (signal.SIGTRAP << 8) | 0x7F),
        (1234, 0),
        (1234, (signal.SIGTRAP << 8) | 0x7F),
        (1234, 0),
        (1234, 0),
    ])

    _mock_environment(monkeypatch, blocks)
    monkeypatch.setattr(MacOSCollector, "_get_image_base", lambda self, pid, exe: 0)

    edges = collector.collect_coverage(1234, exe=exe, already_traced=True)
    assert edges == {((exe, blocks[0]), (exe, blocks[1]))}

    with pytest.raises(RuntimeError):
        collector.collect_coverage(1234, exe=None, already_traced=True)


def test_qemu_gdb_collector(monkeypatch, tiny_binary):
    from fz.coverage.gdb_collector import QemuGdbCollector
    from unittest.mock import MagicMock

    exe_name = "test_exe"
    mock_blocks = [0x1000, 0x1010, 0x1020]
    step_back = 1 # Assuming x86 for simplicity in this mock

    mock_gdb_remote_instance = MagicMock()
    mock_gdb_remote_instance.arch = "x86_64" # Or whatever arch the collector defaults to / is set to
    mock_gdb_remote_instance.arch_mod = arch # x86
    mock_gdb_remote_instance.BREAKPOINT = arch.BREAKPOINT


    # Simulate GDB remote interactions
    # Initial continue, then 3 breakpoint hits, then timeout
    gdb_events = []
    # First BP hit
    gdb_events.append("S05") # TRAP
    # Second BP hit
    gdb_events.append("S05") # TRAP
    # Third BP hit
    gdb_events.append("S05") # TRAP
    # Loop termination signal (e.g. timeout or different signal)
    gdb_events.append("W00") # Process exited


    mock_gdb_remote_instance._recv_packet.side_effect = gdb_events

    # Mock read_registers to return PC values for each breakpoint hit
    # PC = breakpoint_addr + step_back
    reg_values = []
    # PC for mock_blocks[0]
    regs0 = bytearray(32*8) # Dummy register file size for x86_64
    pc0 = mock_blocks[0] + step_back
    regs0[16*8:17*8] = pc0.to_bytes(8, 'little')
    reg_values.append(bytes(regs0))
    # PC for mock_blocks[1]
    regs1 = bytearray(32*8)
    pc1 = mock_blocks[1] + step_back
    regs1[16*8:17*8] = pc1.to_bytes(8, 'little')
    reg_values.append(bytes(regs1))
    # PC for mock_blocks[2]
    regs2 = bytearray(32*8)
    pc2 = mock_blocks[2] + step_back
    regs2[16*8:17*8] = pc2.to_bytes(8, 'little')
    reg_values.append(bytes(regs2))

    mock_gdb_remote_instance.read_registers.side_effect = reg_values

    # Mock read_memory to return dummy original bytes
    mock_gdb_remote_instance.read_memory.return_value = b"\x00" # Dummy 1-byte instruction for x86

    # Mock GDBRemote class to return our instance
    MockGDBRemote = MagicMock(return_value=mock_gdb_remote_instance)
    monkeypatch.setattr("fz.coverage.gdb_collector.GDBRemote", MockGDBRemote)

    # Mock get_basic_blocks
    monkeypatch.setattr("fz.coverage.gdb_collector.get_basic_blocks", lambda exe: mock_blocks)

    collector = QemuGdbCollector(arch="x86_64") # Ensure arch matches step_back logic
    coverage_set = collector.collect_coverage(pid=0, timeout=0.1, exe=exe_name)

    # Assertions
    MockGDBRemote.assert_called_once_with("127.0.0.1", 1234) # Default host/port

    # Check breakpoints were set
    assert mock_gdb_remote_instance.read_memory.call_count == len(mock_blocks)
    assert mock_gdb_remote_instance.write_memory.call_count == (len(mock_blocks) * 2) + len(mock_blocks) # set BP, restore orig, re-set BP for each hit + final restore

    # Check continue calls: initial + after each step
    assert mock_gdb_remote_instance.continue_.call_count == len(mock_blocks) + 1 # initial, after each bp, final during cleanup

    # Check step calls
    assert mock_gdb_remote_instance.step.call_count == len(mock_blocks)

    # Check registers were read for each trap
    assert mock_gdb_remote_instance.read_registers.call_count == len(mock_blocks)

    # Check _recv_packet calls
    assert mock_gdb_remote_instance._recv_packet.call_count == len(gdb_events)

    # Check close was called
    mock_gdb_remote_instance.close.assert_called_once()

    # Verify coverage set
    expected_coverage = {
        ((exe_name, mock_blocks[0]), (exe_name, mock_blocks[1])),
        ((exe_name, mock_blocks[1]), (exe_name, mock_blocks[2])),
    }
    assert coverage_set == expected_coverage


def test_collect_coverage_with_library(monkeypatch, tiny_binary):
    exe = str(tiny_binary)
    blocks = get_basic_blocks(exe)
    collector = LinuxCollector()

    global events
    events = iter([
        (1234, (signal.SIGTRAP << 8) | 0x7F),
        (1234, 0),
        (1234, (signal.SIGTRAP << 8) | 0x7F),
        (1234, 0),
        (1234, 0),
    ])

    _mock_environment(monkeypatch, blocks)
    monkeypatch.setattr(LinuxCollector, "_get_image_base", lambda self, pid, exe: 0)

    called = {}

    def fake_find_library(self, pid, name):
        called["name"] = name
        return exe, 0

    monkeypatch.setattr(LinuxCollector, "_find_library", fake_find_library)

    edges = collector.collect_coverage(1234, exe=exe, libs=["libmagic.so"], already_traced=True)
    assert called["name"] == "libmagic.so"
    assert edges == {((exe, blocks[0]), (exe, blocks[1]))}
