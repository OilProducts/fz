import os
from fz.corpus.corpus import Corpus
from fz.corpus import decode_coverage


def test_crash_saved_on_unique_coverage(tmp_path):
    corpus = Corpus(str(tmp_path))
    cov1 = {(('mod', 1), ('mod', 2))}
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
    cov2 = {(('mod', 1), ('mod', 2)), (('mod', 3), ('mod', 4))}
    saved, path = corpus.save_input(b"C", cov2, "crash")
    assert saved
    assert os.path.exists(path)
    assert os.path.basename(path).startswith("crash-")
    assert len(os.listdir(tmp_path)) == 2

    # Unique set composed of previously seen edges should also be saved
    cov3 = {(('mod', 3), ('mod', 4))}
    saved, path = corpus.save_input(b"D", cov3, "crash")
    assert saved
    assert os.path.exists(path)
    assert os.path.basename(path).startswith("crash-")
    assert len(os.listdir(tmp_path)) == 3


def test_interesting_prefix(tmp_path):
    corpus = Corpus(str(tmp_path))
    cov = {(('mod', 1), ('mod', 2))}
    saved, path = corpus.save_input(b"A", cov, "interesting")
    assert saved
    assert os.path.basename(path).startswith("interesting-")


def test_load_existing_coverage(tmp_path):
    corpus = Corpus(str(tmp_path))
    cov = {(('mod', 1), ('mod', 2))}
    saved, path = corpus.save_input(b"A", cov)
    assert saved

    # New instance should load existing coverage and avoid duplicates
    corpus2 = Corpus(str(tmp_path))
    saved, path = corpus2.save_input(b"B", cov)
    assert not saved
    assert path is None


def test_decode_coverage_helper():
    cov_list = [[["mod", 1], ["mod", 2]], [["mod", 3], ["mod", 4]]]
    edges = decode_coverage(cov_list)
    assert edges == {
        (("mod", 1), ("mod", 2)),
        (("mod", 3), ("mod", 4)),
    }

