import os
from fz.coverage import utils


def test_basic_blocks_and_edges_cached(tiny_binary):
    exe = str(tiny_binary)
    blocks1 = utils.get_basic_blocks(exe)
    assert blocks1, "no blocks parsed"
    blocks2 = utils.get_basic_blocks(exe)
    assert blocks1 is blocks2
    assert exe in utils._block_cache

    edges1 = utils.get_possible_edges(exe)
    assert edges1
    edges2 = utils.get_possible_edges(exe)
    assert edges1 is edges2
    assert exe in utils._edge_cache


def test_load_text_macho(macho_binary):
    data, addr = utils._load_text(str(macho_binary))
    assert data
    assert addr == 0

    blocks = utils.get_basic_blocks(str(macho_binary))
    assert blocks
    edges = utils.get_possible_edges(str(macho_binary))
    assert edges
