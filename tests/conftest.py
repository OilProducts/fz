import subprocess
from pathlib import Path
import pytest


@pytest.fixture(scope="session")
def tiny_binary(tmp_path_factory):
    """Compile the small C coverage fixture and return its path."""
    src = Path(__file__).parent / "coverage" / "fixture.c"
    out_dir = tmp_path_factory.mktemp("bin")
    exe = out_dir / "fixture"
    subprocess.check_call(["cc", str(src), "-o", str(exe)])
    exe.chmod(0o755)
    return exe
