import base64
import json
import os
import random
from typing import List, Set


class Mutator:
    """Basic mutation engine backed by saved corpus inputs."""

    def __init__(
        self, corpus_dir: str = "corpus", input_size: int = 256, max_mutations: int = 1
    ) -> None:
        self.corpus_dir = corpus_dir
        self.input_size = input_size
        self.max_mutations = max(1, int(max_mutations))
        self.seeds: List[bytes] = []
        self.weights: List[int] = []
        self._load_corpus()

    def _load_corpus(self) -> None:
        """Load saved inputs from the corpus directory."""
        if not os.path.isdir(self.corpus_dir):
            return
        for name in os.listdir(self.corpus_dir):
            path = os.path.join(self.corpus_dir, name)
            try:
                with open(path, "r") as f:
                    record = json.load(f)
                data = base64.b64decode(record.get("data", ""))
                coverage = record.get("coverage", [])
                self.seeds.append(data)
                self.weights.append(max(1, len(coverage)))
            except Exception:
                continue
        if not self.seeds:
            # Ensure at least one seed exists to mutate
            self.seeds.append(os.urandom(self.input_size))
            self.weights.append(1)
        # Always include an empty seed for minimal mutations
        if b"" not in self.seeds:
            self.seeds.append(b"")
            self.weights.append(1)

    # ---- mutation helpers ----
    def _choose_seed(self) -> bytes:
        return random.choices(self.seeds, weights=self.weights, k=1)[0]

    def _bitflip(self, data: bytearray) -> bytearray:
        idx = random.randrange(len(data))
        data[idx] ^= 1 << random.randrange(8)
        return data

    def _splice(self, data: bytearray) -> bytearray:
        # Only splice with non-empty seeds to avoid zero-length ranges
        candidates = [s for s in self.seeds if s]
        if len(candidates) < 2:
            return self._bitflip(data)
        other = random.choice(candidates)
        pivot1 = random.randrange(len(data))
        pivot2 = random.randrange(len(other))
        return data[:pivot1] + other[pivot2:]

    def _insert(self, data: bytearray) -> bytearray:
        idx = random.randrange(len(data) + 1)
        data = data[:idx] + bytes([random.randrange(256)]) + data[idx:]
        return data

    def _delete(self, data: bytearray) -> bytearray:
        if len(data) <= 1:
            return self._bitflip(data)
        idx = random.randrange(len(data))
        return data[:idx] + data[idx + 1 :]

    def mutate(self, seed: bytes) -> bytes:
        """Return a mutated variant of *seed*."""
        data = bytearray(seed)
        if not data:
            data.extend(os.urandom(1))
        strategies = ["bitflip", "splice", "insert", "delete"]
        steps = random.randint(1, self.max_mutations)
        for _ in range(steps):
            strategy = random.choice(strategies)
            if strategy == "bitflip":
                data = self._bitflip(data)
            elif strategy == "splice":
                data = self._splice(data)
            elif strategy == "insert":
                data = self._insert(data)
            else:  # delete
                data = self._delete(data)

        if len(data) > self.input_size:
            data = data[: self.input_size]
        if not data:
            data.extend(os.urandom(1))
        return bytes(data)

    def next_input(self) -> bytes:
        """Return a new input for the fuzzer."""
        seed = self._choose_seed()
        return self.mutate(seed)

    def record_result(self, data: bytes, coverage: Set[int], interesting: bool) -> None:
        """Update seed pool based on the result of a fuzz iteration."""
        if interesting:
            self.seeds.append(data)
            self.weights.append(max(1, len(coverage)))

