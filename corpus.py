import hashlib
import os
import logging
import json
import base64
import time
import tempfile
import subprocess


class Corpus:
    """Store inputs that produce new coverage."""

    def __init__(self, directory="corpus"):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)
        self.coverage = set()
        self.coverage_hashes = set()

    def save_if_interesting(self, data, coverage):
        """Persist input if it triggers previously unseen coverage."""
        cov_hash = hashlib.sha1(
            ",".join(str(c) for c in sorted(coverage)).encode()
        ).hexdigest()
        path = os.path.join(self.directory, cov_hash + ".json")

        if cov_hash in self.coverage_hashes or os.path.exists(path):
            logging.debug("Input with identical coverage already stored")
            self.coverage.update(coverage)
            return False

        if not coverage - self.coverage:
            logging.debug("Input did not yield new coverage")
            self.coverage.update(coverage)
            return False

        self.coverage.update(coverage)
        self.coverage_hashes.add(cov_hash)
        record = {
            "coverage": sorted(coverage),
            "data": base64.b64encode(data).decode("ascii"),
        }
        with open(path, "w") as f:
            json.dump(record, f)
        logging.info("Saved interesting input to %s", path)
        return True

    def _save_failure(self, data: bytes, prefix: str) -> str:
        """Save a crashing or timing-out input and return its path."""
        os.makedirs(self.directory, exist_ok=True)
        filename = f"{prefix}-{int(time.time() * 1000)}.bin"
        path = os.path.join(self.directory, filename)
        with open(path, "wb") as f:
            f.write(data)
        logging.info("Saved %s input to %s", prefix, path)
        return path

    def minimize_input(self, path: str, target: str, timeout: float = 1.0,
                        file_input: bool = False, network=None) -> str:
        """Minimize the crashing input saved at *path*.

        The returned path points to the minimized input which is stored
        alongside the original file.
        """
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            logging.debug("Failed to read %s for minimization: %s", path, e)
            return path

        def reproduces_crash(inp: bytes) -> bool:
            if network:
                _cov, crashed, timed_out = network.run(target, inp, timeout)
                return crashed or timed_out
            if file_input:
                tmp = tempfile.NamedTemporaryFile(delete=False)
                try:
                    tmp.write(inp)
                    tmp.flush()
                    argv = [target, tmp.name]
                    proc = subprocess.Popen(
                        argv,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    try:
                        proc.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        return True
                    return proc.returncode not in (0, None)
                finally:
                    try:
                        os.unlink(tmp.name)
                    except OSError:
                        pass
            proc = subprocess.Popen(
                [target],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if proc.stdin:
                try:
                    proc.stdin.write(inp)
                except BrokenPipeError:
                    pass
                finally:
                    try:
                        proc.stdin.close()
                    except BrokenPipeError:
                        pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                return True
            return proc.returncode not in (0, None)

        minimal = data
        step = len(minimal) // 2
        while step > 0 and len(minimal) > 1:
            reduced = minimal[: len(minimal) - step]
            if reproduces_crash(reduced):
                minimal = reduced
            else:
                step //= 2

        if minimal == data:
            logging.info("Input already minimal")
            return path

        min_path = path + ".min"
        with open(min_path, "wb") as f:
            f.write(minimal)
        logging.info("Minimized input saved to %s", min_path)
        return min_path
