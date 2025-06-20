import os
from fz.corpus.mutator import Mutator


def test_empty_corpus_uses_null_seed(tmp_path):
    m = Mutator(corpus_dir=str(tmp_path), input_size=8)
    assert m.seeds == [b""]
    assert m.seed_edges == [[]]
    assert m.weights == [1]
