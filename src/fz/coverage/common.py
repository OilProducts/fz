import ctypes
import ctypes.util
import logging
import os

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long

PTRACE_PEEKTEXT = 1
PTRACE_POKETEXT = 4


def _ptrace(request: int, pid: int, addr: int = 0, data: int = 0) -> int:
    """Invoke ``ptrace`` and raise :class:`OSError` on failure.

    Parameters
    ----------
    request:
        The ``ptrace`` request number.
    pid:
        Process identifier of the traced process.
    addr:
        Address argument passed to ``ptrace``.
    data:
        Data argument passed to ``ptrace``.

    Returns
    -------
    int
        The raw return value from ``ptrace``.
    """
    logging.debug(
        "ptrace request=%d pid=%d addr=%#x data=%#x",
        request,
        pid,
        addr,
        data,
    )
    res = libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if res != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return res


def _ptrace_peek(pid: int, addr: int) -> int:
    """Read a word from ``pid`` at ``addr`` via ``ptrace``.

    Parameters
    ----------
    pid:
        Process identifier of the traced process.
    addr:
        Address to read from within the traced process.

    Returns
    -------
    int
        The value read from ``addr``.
    """
    logging.debug("peek pid=%d addr=%#x", pid, addr)
    res = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(addr), None)
    if res == -1:
        err = ctypes.get_errno()
        if err != 0:
            raise OSError(err, os.strerror(err))
    return res


def _ptrace_poke(pid: int, addr: int, data: int) -> int:
    """Write a word to ``pid`` at ``addr`` via ``ptrace``.

    Parameters
    ----------
    pid:
        Process identifier of the traced process.
    addr:
        Address to write to.
    data:
        Value to write.

    Returns
    -------
    int
        The raw return value from ``ptrace``.
    """
    logging.debug("poke pid=%d addr=%#x data=%#x", pid, addr, data)
    res = libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if res != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return res
