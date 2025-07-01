import os
import sys
from typing import Optional, Tuple

from ...runner.target import run_target

class PreloadHarness:
    """Run a target with LD_PRELOAD to intercept functions."""

    def __init__(self, library: str):
        self.library = os.path.abspath(library)

    def run(
        self,
        target: str,
        data: bytes,
        timeout: float,
        output_bytes: int = 0,
        libs: Optional[list[str]] = None,
    ) -> Tuple[dict[tuple, int], bool, bool, int | None, bytes, bytes]:
        """Execute *target* under LD_PRELOAD and collect coverage.

        Returns
        -------
        tuple
            ``(coverage_map, crashed, timed_out, exit_code, stdout, stderr)``
        """
        env = os.environ.copy()
        var = "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"
        env[var] = self.library
        return run_target(
            target,
            data,
            timeout,
            file_input=False,
            output_bytes=output_bytes,
            libs=libs,
            env=env,
        )

