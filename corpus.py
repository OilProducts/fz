import hashlib
import os
import logging


class Corpus:
    """Store inputs that produce new coverage."""

    def __init__(self, directory="corpus"):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)
        self.coverage = set()

    def save_if_interesting(self, data, coverage):
        """Persist input if it triggers previously unseen coverage."""
        if not coverage - self.coverage:
            logging.debug("Input did not yield new coverage")
            return False
        self.coverage.update(coverage)
        fname = hashlib.sha1(data).hexdigest()
        path = os.path.join(self.directory, fname)
        with open(path, "wb") as f:
            f.write(data)
        logging.debug("Saved interesting input to %s", path)
        return True
