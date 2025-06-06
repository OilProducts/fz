import ctypes
import ctypes.util
import os

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12

class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long

def _ptrace(request, pid, addr=0, data=0):
    res = libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if res != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return res


def collect_coverage(pid):
    """Attach to an existing process and record executed instruction pointers."""
    coverage = set()
    _ptrace(PTRACE_ATTACH, pid)
    os.waitpid(pid, 0)
    regs = user_regs_struct()
    while True:
        try:
            _ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
            coverage.add(regs.rip)
        except OSError:
            break
        try:
            _ptrace(PTRACE_SINGLESTEP, pid)
        except OSError:
            break
        wpid, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            break
    try:
        _ptrace(PTRACE_DETACH, pid)
    except OSError:
        pass
    return coverage
