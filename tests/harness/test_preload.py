import subprocess
from pathlib import Path
from fz.harness.preload import PreloadHarness

TARGET4 = Path(__file__).resolve().parents[2] / "examples" / "target4" / "target4.c"


def build_target(tmp_path: Path) -> Path:
    out = tmp_path / "target4"
    subprocess.check_call([
        "cc",
        "-O0",
        "-g",
        "-fno-stack-protector",
        "-z",
        "execstack",
        "-pthread",
        str(TARGET4),
        "-o",
        str(out),
    ])
    out.chmod(0o755)
    return out


def build_stub(root: Path) -> Path:
    preload_dir = root / "src" / "fz" / "harness" / "preload"
    subprocess.check_call(["make", "clean", "all"], cwd=preload_dir)
    return preload_dir / "build" / "libnet_stub.so"


def test_preload_harness(tmp_path):
    root = Path(__file__).resolve().parents[2]
    lib = build_stub(root)
    harness = PreloadHarness(str(lib))
    cov, crashed, to, out, err = harness.run(str(target), b"ping", 1.0, output_bytes=10)
    assert not to
    assert isinstance(cov, set)
    cov, crashed, to, out, err = harness.run(str(target), b"OVERFLOW:AAAA", 1.0)
    assert crashed

