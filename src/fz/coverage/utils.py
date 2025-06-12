import logging
import os
import re
import subprocess

_block_cache = {}


def get_basic_blocks(exe: str):
    """Return a sorted list of basic block addresses for *exe*."""
    exe = os.path.realpath(exe)
    if exe in _block_cache:
        logging.debug("Using cached basic blocks for %s", exe)
        return _block_cache[exe]

    logging.debug("Parsing basic blocks from %s", exe)
    try:
        output = subprocess.check_output(["objdump", "-d", exe], text=True)
    except Exception as e:
        logging.debug("Failed to disassemble %s: %s", exe, e)
        _block_cache[exe] = []
        return _block_cache[exe]

    blocks = set()
    prev_branch = True
    branch_re = re.compile(r"\b(j\w+|call|ret|syscall)\b")
    for line in output.splitlines():
        m = re.match(r"\s*([0-9a-fA-F]+):", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if prev_branch:
            blocks.add(addr)
        prev_branch = bool(branch_re.search(line))

    _block_cache[exe] = sorted(blocks)
    logging.debug("Identified %d basic blocks in %s", len(blocks), exe)
    return _block_cache[exe]
