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


@pytest.fixture(scope="session")
def macho_binary(tmp_path_factory):
    """Compile the fixture as a Mach-O object and return its path."""
    src = Path(__file__).parent / "coverage" / "fixture.c"
    out_dir = tmp_path_factory.mktemp("macho")
    obj = out_dir / "fixture.o"
    subprocess.check_call([
        "clang",
        "--target=x86_64-apple-darwin",
        "-c",
        str(src),
        "-o",
        str(obj),
    ])
    obj.chmod(0o755)
    return obj
