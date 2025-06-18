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
from fz.coverage.utils import get_basic_blocks, get_text_base
from fz.arch import x86 as arch


def _mock_environment(monkeypatch, blocks, text_base=0):
    state = {"i": 0}

    def fake_ptrace(request, pid, addr=0, data=0):
        if request == PTRACE_GETREGS:
            ctypes.cast(data, ctypes.POINTER(arch.user_regs_struct)).contents.rip = text_base + blocks[state["i"]] + 1
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

    text_base = get_text_base(exe)
    _mock_environment(monkeypatch, blocks, text_base)
    monkeypatch.setattr(LinuxCollector, "_get_image_base", lambda self, pid, exe: 0)

    edges = collector.collect_coverage(1234, exe=exe, already_traced=True)
    expected = {((exe, text_base + blocks[0]), (exe, text_base + blocks[1]))}
    assert edges == expected


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

    text_base = get_text_base(exe)
    _mock_environment(monkeypatch, blocks, text_base)
    monkeypatch.setattr(MacOSCollector, "_get_image_base", lambda self, pid, exe: 0)

    edges = collector.collect_coverage(1234, exe=exe, already_traced=True)
    expected = {((exe, text_base + blocks[0]), (exe, text_base + blocks[1]))}
    assert edges == expected

    with pytest.raises(RuntimeError):
        collector.collect_coverage(1234, exe=None, already_traced=True)


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

    text_base = get_text_base(exe)
    _mock_environment(monkeypatch, blocks, text_base)
    monkeypatch.setattr(LinuxCollector, "_get_image_base", lambda self, pid, exe: 0)

    called = {}

    def fake_find_library(self, pid, name):
        called["name"] = name
        return exe, 0

    monkeypatch.setattr(LinuxCollector, "_find_library", fake_find_library)

    edges = collector.collect_coverage(1234, exe=exe, libs=["libmagic.so"], already_traced=True)
    assert called["name"] == "libmagic.so"
    expected = {((exe, text_base + blocks[0]), (exe, text_base + blocks[1]))}
    assert edges == expected
