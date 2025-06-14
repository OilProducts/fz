"""Coverage collector factory and utilities."""
import platform

from .collector import CoverageCollector, LinuxCollector, MacOSCollector
from .cfg import ControlFlowGraph
from .utils import get_possible_edges
from .visualize import main as visualize_cfg


def get_collector() -> CoverageCollector:
    """Return a :class:`CoverageCollector` for the current platform."""
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

