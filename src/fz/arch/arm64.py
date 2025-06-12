import ctypes

BREAKPOINT = 0xD4200000  # "brk #0" instruction


class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("regs", ctypes.c_ulonglong * 31),
        ("sp", ctypes.c_ulonglong),
        ("pc", ctypes.c_ulonglong),
        ("pstate", ctypes.c_ulonglong),
    ]


def get_pc(regs: "user_regs_struct") -> int:
    return regs.pc


def set_pc(regs: "user_regs_struct", value: int) -> None:
    regs.pc = value
