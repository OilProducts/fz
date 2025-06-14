"""Coverage collector factory and utilities.

This module exposes helper functions and classes used throughout the
``fz.coverage`` package.  The :func:`get_collector` convenience function
returns an appropriate :class:`CoverageCollector` implementation for the
current platform.
"""
import platform

from .collector import CoverageCollector, LinuxCollector, MacOSCollector
from .cfg import ControlFlowGraph
from .utils import get_possible_edges
from .visualize import main as visualize_cfg


def get_collector() -> CoverageCollector:
    """Return a :class:`CoverageCollector` instance for the host system."""
    if platform.system() == "Darwin":
        return MacOSCollector()
    return LinuxCollector()

__all__ = [
    "CoverageCollector",
    "get_collector",
    "ControlFlowGraph",
    "get_possible_edges",
    "visualize_cfg",
]

