import logging
import socket
import time
from typing import Optional, Set

from .collector import CoverageCollector
from .utils import get_basic_blocks
from ..arch import arm64 as arm64_arch
from ..arch import x86 as x86_arch

ARCHS = {
    "x86_64": x86_arch,
    "amd64": x86_arch,
    "aarch64": arm64_arch,
    "arm64": arm64_arch,
}


class GDBRemote:
    """Minimal GDB remote protocol client."""

    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port))
        self.sock.settimeout(1.0)
        # initial stop packet
        self._recv_packet()

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def _checksum(self, payload: str) -> str:
        return f"{sum(payload.encode()) & 0xFF:02x}"

    def _send_packet(self, payload: str) -> str:
        pkt = f"${payload}#{self._checksum(payload)}".encode()
        self.sock.sendall(pkt)
        ack = self.sock.recv(1)
        if ack != b"+":
            logging.debug("Unexpected ACK: %s", ack)
        return self._recv_packet()

    def _recv_packet(self) -> str:
        data = b""
        while True:
            c = self.sock.recv(1)
            if not c:
                raise RuntimeError("GDB connection closed")
            if c == b"$":
                data = b""
                continue
            if c == b"#":
                cs = self.sock.recv(2)
                self.sock.sendall(b"+")
                return data.decode()
            data += c

    # public helpers
    def read_memory(self, addr: int, length: int) -> bytes:
        resp = self._send_packet(f"m{addr:x},{length:x}")
        if resp.startswith("E"):
            raise RuntimeError(f"read memory failed: {resp}")
        return bytes.fromhex(resp)

    def write_memory(self, addr: int, data: bytes) -> None:
        payload = f"M{addr:x},{len(data):x}:{data.hex()}"
        resp = self._send_packet(payload)
        if resp != "OK":
            raise RuntimeError(f"write memory failed: {resp}")

    def set_breakpoint(self, addr: int) -> None:
        resp = self._send_packet(f"Z0,{addr:x},1")
        if resp != "OK":
            raise RuntimeError(f"set breakpoint failed: {resp}")

    def remove_breakpoint(self, addr: int) -> None:
        resp = self._send_packet(f"z0,{addr:x},1")
        if resp != "OK":
            logging.debug("remove breakpoint failed: %s", resp)

    def continue_(self) -> str:
        return self._send_packet("c")

    def step(self) -> str:
        return self._send_packet("s")

    def read_registers(self) -> bytes:
        data = self._send_packet("g")
        if data.startswith("E"):
            raise RuntimeError(f"read registers failed: {data}")
        return bytes.fromhex(data)


class QemuGdbCollector(CoverageCollector):
    """Coverage collector that talks to a QEMU `-g` instance."""

    def __init__(self, host: str = "127.0.0.1", port: int = 1234, arch: str = "x86_64"):
        self.host = host
        self.port = port
        self.arch = arch
        if arch not in ARCHS:
            raise RuntimeError(f"Unsupported arch: {arch}")
        self.arch_mod = ARCHS[arch]
        self.BREAKPOINT = self.arch_mod.BREAKPOINT

    def _resolve_exe(self, pid: int, exe: Optional[str]) -> Optional[str]:
        return exe

    def _get_image_base(self, pid: int, exe: str) -> int:
        return 0

    def _find_library(self, pid: int, name: str):
        return None, 0

    def collect_coverage(
        self,
        pid: int,
        timeout: float = 1.0,
        exe: Optional[str] = None,
        already_traced: bool = False,
        libs: Optional[list[str]] = None,
    ) -> Set[tuple[tuple[str, int], tuple[str, int]]]:
        if exe is None:
            raise RuntimeError("Executable path required")
        gdb = GDBRemote(self.host, self.port)
        blocks = get_basic_blocks(exe)
        base = 0
        breakpoints = {}
        bp_size = 4 if self.arch.startswith("aarch64") or self.arch == "arm64" else 1
        for off in blocks:
            addr = base + off
            try:
                orig = gdb.read_memory(addr, bp_size)
                gdb.write_memory(addr, self.BREAKPOINT.to_bytes(bp_size, "little"))
                breakpoints[addr] = orig
            except Exception as e:
                logging.debug("Failed to set breakpoint at %#x: %s", addr, e)
        gdb.continue_()
        end_time = time.time() + timeout * 2
        coverage: Set[tuple[tuple[str, int], tuple[str, int]]] = set()
        prev = None
        while time.time() < end_time:
            reason = gdb._recv_packet()
            if not reason.startswith("S"):
                break
            regs = gdb.read_registers()
            if self.arch.startswith("aarch64") or self.arch == "arm64":
                pc = int.from_bytes(regs[32*8:33*8], "little")
                step_back = 4
            else:
                pc = int.from_bytes(regs[16*8:17*8], "little")
                step_back = 1
            addr = pc - step_back
            if addr not in breakpoints:
                break
            curr = (exe, addr - base)
            if prev is not None:
                coverage.add((prev, curr))
            prev = curr
            orig = breakpoints[addr]
            gdb.write_memory(addr, orig)
            gdb.step()
            gdb.write_memory(addr, self.BREAKPOINT.to_bytes(bp_size, "little"))
            gdb.continue_()
        for addr, orig in breakpoints.items():
            try:
                gdb.write_memory(addr, orig)
            except Exception:
                pass
        gdb.continue_()
        gdb.close()
        return coverage
