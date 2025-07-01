"""Coverage collector factory and utilities.

This module exposes helper functions and classes used throughout the
``fz.coverage`` package.  The :func:`get_collector` convenience function
returns an appropriate :class:`CoverageCollector` implementation for the
current platform.
"""
import platform

from .collector import CoverageCollector, LinuxCollector, MacOSCollector
from .gdb_collector import QemuGdbCollector
from .cfg import ControlFlowGraph, EdgeCoverage
from .utils import get_possible_edges
from .visualize import main as visualize_cfg


def get_collector() -> CoverageCollector:
    """Return a :class:`CoverageCollector` instance for the host system."""
    if platform.system() == "Darwin":
        return MacOSCollector()
    return LinuxCollector()


def get_gdb_collector(host: str = "127.0.0.1", port: int = 1234, arch: str = "x86_64") -> CoverageCollector:
    """Return a :class:`QemuGdbCollector` instance."""
    return QemuGdbCollector(host, port, arch)

__all__ = [
    "CoverageCollector",
    "get_collector",
    "ControlFlowGraph",
    "EdgeCoverage",
    "get_possible_edges",
    "visualize_cfg",
    "QemuGdbCollector",
    "get_gdb_collector",
]

