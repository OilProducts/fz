"""Platform-dispatching coverage collection."""
import platform

if platform.system() == "Darwin":
    from .macos import collect_coverage  # noqa: F401
else:
    from .linux import collect_coverage  # noqa: F401

from .cfg import ControlFlowGraph  # noqa: F401
from .utils import get_possible_edges  # noqa: F401

__all__ = ["collect_coverage", "ControlFlowGraph", "get_possible_edges"]
