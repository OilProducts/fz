import subprocess
from pathlib import Path
from fz.harness.preload import PreloadHarness

SRC = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(s, NULL, 0);
    listen(s, 1);
    int c = accept(s, NULL, NULL);
    char buf[64];
    ssize_t n = recv(c, buf, sizeof(buf)-1, 0);
    if (n <= 0) return 0;
    buf[n] = '\0';
    if (strcmp(buf, "crash") == 0) {
        char *p = NULL;
        *p = 1;
    }
    send(c, "ok", 2, 0);
    close(c);
    close(s);
    return 0;
}
"""


def build(tmp_path: Path, name: str, source: str, flags=None) -> Path:
    src_path = tmp_path / f"{name}.c"
    src_path.write_text(source)
    out = tmp_path / name
    cmd = ["cc", "-shared", "-fPIC", "-o", str(out), str(src_path)] if flags == "so" else ["cc", str(src_path), "-o", str(out)]
    subprocess.check_call(cmd)
    out.chmod(0o755)
    return out


def test_preload_harness(tmp_path):
    root = Path(__file__).resolve().parents[2]
    stub_src = (root / "src" / "fz" / "harness" / "preload" / "net_stub.c").read_text()
    lib = build(tmp_path, "stub.so", stub_src, "so")
    target = build(tmp_path, "srv", SRC)
    harness = PreloadHarness(str(lib))
    cov, crashed, to, out, err = harness.run(str(target), b"ping", 1.0, output_bytes=10)
    assert not to
    assert isinstance(cov, set)
    cov, crashed, to, out, err = harness.run(str(target), b"crash", 1.0)
    assert crashed

