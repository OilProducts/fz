import logging
import os
import platform

from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_64, CS_MODE_ARM
from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_OP_IMM
from elftools.elf.elffile import ELFFile

_block_cache = {}
_edge_cache = {}


def _load_text(exe: str):
    """Return (text_bytes, vaddr) for the .text section of *exe*."""
    with open(exe, "rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        if text is None:
            raise ValueError(".text section not found")
        return text.data(), text["sh_addr"]


def _get_disassembler():
    arch = platform.machine().lower()
    if arch in ("aarch64", "arm64"):
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def get_basic_blocks(exe: str):
    """Return a sorted list of basic block addresses for *exe*."""
    exe = os.path.realpath(exe)
    if exe in _block_cache:
        logging.debug("Using cached basic blocks for %s", exe)
        return _block_cache[exe]

    logging.debug("Parsing basic blocks from %s", exe)
    try:
        text, base = _load_text(exe)
    except Exception as e:
        logging.debug("Failed to read .text from %s: %s", exe, e)
        _block_cache[exe] = []
        return _block_cache[exe]

    md = _get_disassembler()
    blocks = set()
    prev_branch = True
    for insn in md.disasm(text, base):
        if prev_branch:
            blocks.add(insn.address)
        is_branch = (
            CS_GRP_JUMP in insn.groups
            or CS_GRP_RET in insn.groups
            or CS_GRP_CALL in insn.groups
        )
        prev_branch = is_branch

    _block_cache[exe] = sorted(blocks)
    logging.debug("Identified %d basic blocks in %s", len(blocks), exe)
    return _block_cache[exe]


def get_possible_edges(exe: str):
    """Return a set of possible control flow edges for *exe* using capstone."""
    exe = os.path.realpath(exe)
    if exe in _edge_cache:
        logging.debug("Using cached CFG edges for %s", exe)
        return _edge_cache[exe]

    try:
        text, base = _load_text(exe)
    except Exception as e:
        logging.debug("Failed to read .text from %s: %s", exe, e)
        _edge_cache[exe] = set()
        return _edge_cache[exe]

    md = _get_disassembler()
    edges = set()
    prev_addr = None
    prev_type = None  # None, 'cond', 'uncond'

    for insn in md.disasm(text, base):
        addr = insn.address

        if prev_addr is not None and prev_type != "uncond":
            edges.add((prev_addr, addr))

        branch_type = None
        if CS_GRP_JUMP in insn.groups:
            if insn.mnemonic in ("jmp", "b", "br"):
                branch_type = "uncond"
            else:
                branch_type = "cond"
        elif CS_GRP_RET in insn.groups:
            branch_type = "uncond"
        elif CS_GRP_CALL in insn.groups:
            branch_type = "call"

        if branch_type:
            for op in insn.operands:
                if op.type == CS_OP_IMM:
                    edges.add((addr, op.imm))
                    break

        prev_addr = addr
        prev_type = branch_type

    _edge_cache[exe] = edges
    logging.debug("Static CFG for %s contains %d edges", exe, len(edges))
    return edges
