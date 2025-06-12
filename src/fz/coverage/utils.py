import logging
import os
import re
import subprocess

_block_cache = {}
_edge_cache = {}


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


def get_possible_edges(exe: str):
    """Return a set of possible control flow edges for *exe* via objdump."""
    exe = os.path.realpath(exe)
    if exe in _edge_cache:
        logging.debug("Using cached CFG edges for %s", exe)
        return _edge_cache[exe]

    try:
        output = subprocess.check_output(["objdump", "-d", exe], text=True)
    except Exception as e:
        logging.debug("Failed to disassemble %s for CFG: %s", exe, e)
        _edge_cache[exe] = set()
        return _edge_cache[exe]

    edges = set()
    prev_addr = None
    prev_type = None  # None, 'cond', 'uncond'

    # Regex to parse instruction lines: address: bytes  mnemonic operands
    ins_re = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)*([a-zA-Z.]+)\s*(.*)$")
    for line in output.splitlines():
        m = ins_re.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        mnemonic = m.group(2)
        ops = m.group(3)

        if prev_addr is not None:
            if prev_type != "uncond":
                edges.add((prev_addr, addr))

        # Determine branch type
        branch_type = None
        if mnemonic.startswith("j"):
            branch_type = "cond" if mnemonic != "jmp" else "uncond"
        elif mnemonic.startswith("ret"):
            branch_type = "uncond"
        elif mnemonic.startswith("call"):
            branch_type = "call"

        if branch_type:
            m2 = re.search(r"([0-9a-fA-F]+)", ops)
            if m2:
                target = int(m2.group(1), 16)
                edges.add((addr, target))

        prev_addr = addr
        prev_type = branch_type

    _edge_cache[exe] = edges
    logging.debug("Static CFG for %s contains %d edges", exe, len(edges))
    return edges
