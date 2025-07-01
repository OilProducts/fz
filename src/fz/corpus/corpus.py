import hashlib
import os
import logging
import json
import base64
import tempfile
import subprocess
from typing import Optional

from .utils import decode_coverage

from fz.runner.target import run_target


class Corpus:
    """Store inputs that exhibit unique coverage."""

    def __init__(self, directory: str = "corpus", output_bytes: int = 0):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)
        self.coverage = set()
        self.coverage_hashes = set()
        self.output_bytes = output_bytes
        self._load_existing()

    def _coverage_hash(self, coverage) -> str:
        """Return a stable hash for *coverage*."""
        hash_input = ",".join(str(c) for c in sorted(coverage)).encode()
        return hashlib.sha1(hash_input).hexdigest()

    def _load_existing(self) -> None:
        """Populate coverage sets from the existing corpus."""
        if not os.path.isdir(self.directory):
            return
        for root, _, files in os.walk(self.directory):
            for name in files:
                if not name.endswith(".json"):
                    continue
                path = os.path.join(root, name)
                try:
                    with open(path) as f:
                        record = json.load(f)
                    edges = decode_coverage(record.get("coverage", []))
                except Exception:
                    continue
                self.coverage.update(edges)
                self.coverage_hashes.add(self._coverage_hash(edges))

    def save_input(
        self,
        data: bytes,
        coverage,
        category: str = "interesting",
        stdout: bytes = b"",
        stderr: bytes = b"",
        exit_code: int | None = None,
    ):
        """Persist *data* and associated *coverage*.

        Coverage is deduplicated using a hash of the coverage set regardless of
        *category*.  Saved files are JSON formatted and compatible with the
        existing corpus structure.
        """

        record = {
            "coverage": sorted(coverage),
            "data": base64.b64encode(data).decode("ascii"),
        }
        if exit_code is not None:
            record["exit_code"] = exit_code
        if stdout and self.output_bytes > 0:
            record["stdout"] = base64.b64encode(stdout[: self.output_bytes]).decode("ascii")
        if stderr and self.output_bytes > 0:
            record["stderr"] = base64.b64encode(stderr[: self.output_bytes]).decode("ascii")
        if category != "interesting":
            record["type"] = category

        hash_input = ",".join(str(c) for c in record["coverage"]).encode()
        cov_hash = hashlib.sha1(hash_input).hexdigest()
        filename = cov_hash
        category_dir = os.path.join(self.directory, category)
        os.makedirs(category_dir, exist_ok=True)
        path = os.path.join(category_dir, f"{filename}.json")

        existing = [
            os.path.join(self.directory, sub, f"{cov_hash}.json")
            for sub in ("interesting", "crash", "timeout")
        ] + [
            os.path.join(self.directory, f"{sub}-{cov_hash}.json")
            for sub in ("interesting", "crash", "timeout")
        ]

        if cov_hash in self.coverage_hashes or any(os.path.exists(p) for p in existing):
            logging.debug("Input with identical coverage already stored")
            self.coverage.update(coverage)
            return False, None

        self.coverage.update(coverage)
        self.coverage_hashes.add(cov_hash)

        with open(path, "w") as f:
            json.dump(record, f)
        logging.info("Saved %s input to %s", category, path)
        return True, path

    def minimize_input(
        self,
        path: str,
        target: str,
        timeout: float = 1.0,
        file_input: bool = False,
        network=None,
        libs: Optional[list[str]] = None,
    ) -> str:
        """Minimize the crashing input saved at *path*.

        Parameters
        ----------
        path:
            File path of the saved crashing input.
        target:
            Target binary to execute for validation.
        timeout:
            Seconds to wait for each execution.
        file_input:
            Pass input via temporary file if ``True``.
        network:
            Optional network harness for service targets.
        libs:
            Additional libraries to instrument during execution.

        Returns
        -------
        str
            Path to the minimized crashing input.
        """
        try:
            mode = "r" if path.endswith(".json") else "rb"
            record = {}
            with open(path, mode) as f:
                if path.endswith(".json"):
                    record = json.load(f)
                    data = base64.b64decode(record.get("data", ""))
                else:
                    data = f.read()
        except OSError as e:
            logging.debug("Failed to read %s for minimization: %s", path, e)
            return path

        def test_input(inp: bytes) -> bool:
            """Run *inp* and store any coverage discovered.

            Returns ``True`` if the candidate still crashes or times out.
            """
            if network:
                cov, crashed, timed_out, exit_code, stdout, stderr = network.run(
                    target, inp, timeout, libs=libs
                )
            else:
                cov, crashed, timed_out, exit_code, stdout, stderr = run_target(
                    target,
                    inp,
                    timeout,
                    file_input=file_input,
                    output_bytes=0,
                    libs=libs,
                    env=None,
                )

            # Save any coverage discovered while minimizing
            self.save_input(inp, cov, "interesting", stdout, stderr, exit_code)
            return crashed or timed_out

        minimal = data
        iterations = 0
        n = 2

        while len(minimal) >= 2:
            chunk = len(minimal) // n
            if chunk == 0:
                break
            found = False
            for i in range(0, len(minimal), chunk):
                candidate = minimal[:i] + minimal[i + chunk :]
                if not candidate:
                    continue
                iterations += 1
                if test_input(candidate):
                    minimal = candidate
                    n = max(n - 1, 2)
                    found = True
                    break
            if not found:
                if n == len(minimal):
                    break
                n = min(n * 2, len(minimal))

        logging.info("Minimization loop executed %d iterations", iterations)

        if minimal == data:
            logging.info("Input already minimal")
            return path

        min_path = path + ".min"
        if path.endswith(".json"):
            record["data"] = base64.b64encode(minimal).decode("ascii")
            with open(min_path, "w") as f:
                json.dump(record, f)
        else:
            with open(min_path, "wb") as f:
                f.write(minimal)
        logging.info("Minimized input saved to %s", min_path)
        return min_path


def corpus_stats(directory: str) -> tuple[int, int]:
    """Return the number of corpus entries and unique edges in *directory*."""
    entries = 0
    edges = set()
    if not os.path.isdir(directory):
        return entries, 0
    for name in os.listdir(directory):
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path) as f:
                record = json.load(f)
            edges.update(decode_coverage(record.get("coverage", [])))
            entries += 1
        except Exception:
            continue
    return entries, len(edges)
