import tempfile
import os
import fz.coverage as coverage
from fz.runner.target import run_target


def test_run_target_no_tempfile(monkeypatch):
    calls = {"count": 0}
    orig_tmpfile = tempfile.TemporaryFile

    def fake_tmpfile(*args, **kwargs):
        calls["count"] += 1
        return orig_tmpfile(*args, **kwargs)

    monkeypatch.setattr(tempfile, "TemporaryFile", fake_tmpfile)

    class DummyCollector:
        def collect_coverage(self, *args, **kwargs):
            return set()

    monkeypatch.setattr(coverage, "get_collector", lambda: DummyCollector())

    cov, crashed, to, rc, out, err = run_target("/usr/bin/true", b"", 1.0, output_bytes=0)
    assert cov == set()
    assert calls["count"] == 0
    assert out == b""
    assert err == b""
