from fz.corpus.corpus import Corpus
from fz.corpus.mutator import Mutator
from fz.coverage import ControlFlowGraph


def test_empty_corpus_uses_null_seed(tmp_path):
    m = Mutator(corpus_dir=str(tmp_path), input_size=8)
    assert m.seeds == [b""]
    assert m.seed_edges == [[]]
    assert m.weights == [1]


def test_weights_update_on_new_edges(tmp_path):
    cfg = ControlFlowGraph()
    corpus_dir = str(tmp_path)
    corpus = Corpus(corpus_dir)

    cov1 = {(('mod', 1), ('mod', 2)), (('mod', 2), ('mod', 3))}
    cov2 = {(('mod', 3), ('mod', 4))}

    corpus.save_input(b'A', cov1)
    corpus.save_input(b'B', cov2)

    m = Mutator(corpus_dir=corpus_dir, input_size=8, cfg=cfg)

    assert sorted(m.weights) == [1, 1, 2]

    cfg.add_edges(cov1)
    m.record_result(b'A', cov1, interesting=False)
    assert sorted(m.weights) == [1, 1, 2]

    new_cov = {(('mod', 4), ('mod', 5))}
    cfg.add_edges(new_cov)
    m.record_result(b'C', new_cov, interesting=True)

    assert all(w == 1 for w in m.weights)


def test_non_empty_seed_tracking(tmp_path):
    corpus_dir = str(tmp_path)
    corpus = Corpus(corpus_dir)

    cov = {(('mod', 1), ('mod', 2))}
    corpus.save_input(b'A', cov)

    m = Mutator(corpus_dir=corpus_dir, input_size=8)

    assert b"" in m.seeds
    assert m.non_empty_seeds == [b"A"]

    m.record_result(b"B", cov, interesting=True)
    assert b"B" in m.non_empty_seeds
    m.record_result(b"C", cov, interesting=False)
    assert b"C" not in m.non_empty_seeds


def test_seed_directory_inputs(tmp_path):
    corpus_dir = tmp_path / "corpus"
    seed_dir = tmp_path / "seeds"
    corpus_dir.mkdir()
    seed_dir.mkdir()
    (seed_dir / "one").write_bytes(b"A")
    (seed_dir / "two").write_bytes(b"BB")

    m = Mutator(corpus_dir=str(corpus_dir), input_size=8, seed_dir=str(seed_dir))

    assert b"A" in m.seeds
    assert b"BB" in m.seeds
    assert b"" in m.seeds
