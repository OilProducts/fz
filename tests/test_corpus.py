import os
from fz.corpus.corpus import Corpus


def test_crash_only_saved_on_new_coverage(tmp_path):
    corpus = Corpus(str(tmp_path))
    cov1 = {(1, 2, 3, 4)}
    saved, path = corpus.save_input(b"A", cov1, "crash")
    assert saved
    assert os.path.exists(path)
    assert len(os.listdir(tmp_path)) == 1

    saved, path = corpus.save_input(b"B", cov1, "crash")
    assert not saved
    assert path is None
    assert len(os.listdir(tmp_path)) == 1

    cov2 = {(1, 2, 3, 4), (5, 6, 7, 8)}
    saved, path = corpus.save_input(b"C", cov2, "crash")
    assert saved
    assert os.path.exists(path)
    assert len(os.listdir(tmp_path)) == 2
