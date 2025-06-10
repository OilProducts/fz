import hashlib
import json
import os
import logging


class Corpus:
    """Store inputs that produce new coverage along with execution traces."""

    def __init__(self, directory="corpus"):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)
        self.coverage = set()
        self._load_existing()

    def _load_existing(self):
        """Load coverage information from an existing corpus directory."""
        for name in os.listdir(self.directory):
            if not name.endswith(".json"):
                continue
            path = os.path.join(self.directory, name)
            try:
                with open(path) as f:
                    meta = json.load(f)
                self.coverage.update(meta.get("blocks", []))
            except (OSError, json.JSONDecodeError) as e:
                logging.warning("Failed to load %s: %s", path, e)
        if self.coverage:
            logging.info(
                "Loaded %d coverage entries from existing corpus", len(self.coverage)
            )

    def save_if_interesting(self, data, coverage, trace=None):
        """Persist input and trace if it triggers previously unseen coverage."""
        if not coverage - self.coverage:
            logging.debug("Input did not yield new coverage")
            return False
        self.coverage.update(coverage)
        fname = hashlib.sha1(data).hexdigest()
        bin_path = os.path.join(self.directory, fname + ".bin")
        with open(bin_path, "wb") as f:
            f.write(data)
        meta = {"blocks": trace if trace is not None else sorted(coverage)}
        meta_path = os.path.join(self.directory, fname + ".json")
        with open(meta_path, "w") as f:
            json.dump(meta, f)
        logging.debug("Saved interesting input to %s and %s", bin_path, meta_path)
        return True
