import hashlib
import os
import logging
import json
import base64


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
