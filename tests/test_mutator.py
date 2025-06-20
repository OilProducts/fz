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
