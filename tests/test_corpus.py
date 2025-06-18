import os
from fz.corpus.corpus import Corpus


def test_crash_saved_on_unique_coverage(tmp_path):
    corpus = Corpus(str(tmp_path))
    cov1 = {(1, 2, 3, 4)}
    saved, path = corpus.save_input(b"A", cov1, "crash")
    assert saved
    assert os.path.exists(path)
    assert os.path.basename(path).startswith("crash-")
    assert len(os.listdir(tmp_path)) == 1

    # Duplicate coverage should not be saved
    saved, path = corpus.save_input(b"B", cov1, "crash")
    assert not saved
    assert path is None
    assert len(os.listdir(tmp_path)) == 1

    # New combination introduces an additional edge
    cov2 = {(1, 2, 3, 4), (5, 6, 7, 8)}
    saved, path = corpus.save_input(b"C", cov2, "crash")
    assert saved
    assert os.path.exists(path)
    assert os.path.basename(path).startswith("crash-")
    assert len(os.listdir(tmp_path)) == 2

    # Unique set composed of previously seen edges should also be saved
    cov3 = {(5, 6, 7, 8)}
    saved, path = corpus.save_input(b"D", cov3, "crash")
    assert saved
    assert os.path.exists(path)
    assert os.path.basename(path).startswith("crash-")
    assert len(os.listdir(tmp_path)) == 3


def test_interesting_prefix(tmp_path):
    corpus = Corpus(str(tmp_path))
    cov = {(1, 2, 3, 4)}
    saved, path = corpus.save_input(b"A", cov, "interesting")
    assert saved
    assert os.path.basename(path).startswith("interesting-")
