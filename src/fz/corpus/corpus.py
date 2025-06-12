import hashlib
import os
import logging
import json
import base64
import time
import tempfile
import subprocess

from fz.runner.target import run_target


class Corpus:
    """Store inputs that produce new coverage."""

    def __init__(self, directory: str = "corpus", output_bytes: int = 0):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)
        self.coverage = set()
        self.coverage_hashes = set()
        self.output_bytes = output_bytes

    def save_input(
        self,
        data: bytes,
        coverage,
        category: str = "interesting",
        stdout: bytes = b"",
        stderr: bytes = b"",
    ):
        """Persist *data* and associated *coverage*.

        If *category* is "interesting", coverage is deduplicated using a hash of
        the coverage set.  For other categories (e.g. "crash" or "timeout") a
        timestamped file name is used.  The saved file is JSON formatted and
        compatible with the existing corpus structure.
        """

        record = {
            "coverage": sorted(coverage),
            "data": base64.b64encode(data).decode("ascii"),
        }
        if stdout and self.output_bytes > 0:
            record["stdout"] = base64.b64encode(stdout[: self.output_bytes]).decode("ascii")
        if stderr and self.output_bytes > 0:
            record["stderr"] = base64.b64encode(stderr[: self.output_bytes]).decode("ascii")
        if category != "interesting":
            record["type"] = category

        if category == "interesting":
            cov_hash = hashlib.sha1(
                ",".join(str(c) for c in record["coverage"]).encode()
            ).hexdigest()
            path = os.path.join(self.directory, cov_hash + ".json")

            if cov_hash in self.coverage_hashes or os.path.exists(path):
                logging.debug("Input with identical coverage already stored")
                self.coverage.update(coverage)
                return False, None

            if not coverage - self.coverage:
                logging.debug("Input did not yield new coverage")
                self.coverage.update(coverage)
                return False, None

            self.coverage.update(coverage)
            self.coverage_hashes.add(cov_hash)
        else:
            filename = f"{category}-{int(time.time() * 1000)}.json"
            path = os.path.join(self.directory, filename)

        with open(path, "w") as f:
            json.dump(record, f)
        logging.info("Saved %s input to %s", category, path)
        return True, path

    def minimize_input(self, path: str, target: str, timeout: float = 1.0,
                        file_input: bool = False, network=None) -> str:
        """Minimize the crashing input saved at *path*.

        The returned path points to the minimized input which is stored
        alongside the original file.
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

        def reproduces_crash(inp: bytes) -> bool:
            if network:
                _cov, crashed, timed_out, _stdout, _stderr = network.run(
                    target, inp, timeout
                )
                return crashed or timed_out

            cov, crashed, timed_out, _stdout, _stderr = run_target(
                target,
                inp,
                timeout,
                file_input=file_input,
                output_bytes=0,
            )
            return crashed or timed_out

        minimal = data
        step = len(minimal) // 2
        iterations = 0
        while step > 0 and len(minimal) > 1:
            iterations += 1
            reduced = minimal[: len(minimal) - step]
            if reproduces_crash(reduced):
                minimal = reduced
            else:
                step //= 2
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
