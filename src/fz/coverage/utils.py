import logging
import os
import platform

from typing import List, Set
from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_64, CS_MODE_ARM
from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_OP_IMM
from elftools.elf.elffile import ELFFile
from macholib.MachO import MachO
from macholib.mach_o import CPU_TYPE_NAMES

from .cfg import Edge

_block_cache = {}
_edge_cache = {}


def _load_text(exe: str) -> tuple[bytes, int]:
    """Return the contents and virtual address of the ``.text`` section.

    Parameters
    ----------
    exe:
        Path to the executable to inspect.

    Returns
    -------
    tuple[bytes, int]
        A tuple ``(data, address)`` containing the raw section bytes and the
        section's load address.
    """
    with open(exe, "rb") as f:
        magic = f.read(4)

    if magic == b"\x7fELF":
        with open(exe, "rb") as f:
            elf = ELFFile(f)
            text = elf.get_section_by_name(".text")
            if text is None:
                raise ValueError(".text section not found")
            return text.data(), text["sh_addr"]

    MACHO_MAGICS = {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }
    if magic in MACHO_MAGICS:
        return _load_text_macho(exe)

    raise ValueError("unsupported binary format")


def _load_text_macho(exe: str) -> tuple[bytes, int]:
    """Return the ``__TEXT,__text`` section bytes and load address."""
    arch = platform.machine().lower()
    target = "ARM64" if arch in ("arm64", "aarch64") else "x86_64"
    cpu_type = next(k for k, v in CPU_TYPE_NAMES.items() if v == target)

    m = MachO(exe)
    with open(exe, "rb") as f:
        for header in m.headers:
            if header.header.cputype != cpu_type:
                continue
            for load_cmd, cmd, data in header.commands:
                name = load_cmd.get_cmd_name()
                if name in ("LC_SEGMENT", "LC_SEGMENT_64"):
                    for sec in data:
                        seg = sec.segname.rstrip(b"\x00").decode()
                        sect = sec.sectname.rstrip(b"\x00").decode()
                        if seg == "__TEXT" and sect == "__text":
                            f.seek(sec.offset)
                            return f.read(sec.size), sec.addr
    raise ValueError("__TEXT,__text section not found")


def _get_disassembler():
    """Return a Capstone disassembler configured for the host architecture."""
    arch = platform.machine().lower()
    if arch in ("aarch64", "arm64"):
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def get_basic_blocks(exe: str) -> List[int]:
    """Return a sorted list of basic block addresses for ``exe``.

    Parameters
    ----------
    exe:
        Path to the executable to analyze.

    Returns
    -------
    list[int]
        A list of starting addresses for each basic block discovered in
        ``exe``.
    """
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



def get_possible_edges(exe: str) -> Set[Edge]:
    """Return a set of possible control flow edges for ``exe``.

    The edges are determined using a light-weight disassembly of the ``.text``
    section via Capstone and represent potential branch targets.

    Parameters
    ----------
    exe:
        Path to the executable to analyze.

    Returns
    -------
    set[Edge]
        All edges ``((module, src), (module, dst))`` that may be taken at runtime.
    """
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
            edges.add(((exe, prev_addr - base), (exe, addr - base)))

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
                    edges.add(((exe, addr - base), (exe, op.imm - base)))
                    break

        prev_addr = addr
        prev_type = branch_type

    _edge_cache[exe] = edges
    logging.debug("Static CFG for %s contains %d edges", exe, len(edges))
    return edges
