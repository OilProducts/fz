"""Platform-dispatching coverage collection."""
import platform

if platform.system() == "Darwin":
    from coverage_macos import collect_coverage  # noqa: F401
else:
    from coverage_linux import collect_coverage  # noqa: F401

__all__ = ["collect_coverage"]
