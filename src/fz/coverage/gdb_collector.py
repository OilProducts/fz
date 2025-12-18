import logging
import socket
import time
import xml.etree.ElementTree as ET
from typing import Optional, Set

from .cfg import Edge

from .collector import CoverageCollector
from .utils import get_basic_blocks
from .common import BREAKPOINT

_SUPPORTED_ARCHS = {
    "x86_64",
    "amd64",
    "aarch64",
    "arm64",
    "mips",
    "mipsel",
    "mips64",
    "mips64el",
}


class GDBRemote:
    """Minimal GDB remote protocol client."""

    def __init__(self, host: str, port: int):
        # retry loop to allow qemu-user gdbstub to come up
        deadline = time.time() + 5.0
        last_err = None
        addrlist = []
        try:
            addrlist = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except Exception:
            addrlist = []
        # Fallbacks to try both families explicitly
        fallback = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', port)),
            (socket.AF_INET6, socket.SOCK_STREAM, 0, '', ('::1', port, 0, 0)),
        ]
        tried = addrlist + fallback
        while True:
            for family, socktype, proto, cname, addr in tried:
                try:
                    s = socket.socket(family, socktype, proto)
                    s.settimeout(1.0)
                    s.connect(addr)
                    self.sock = s
                    tried = []
                    break
                except OSError as e:
                    last_err = e
                    continue
            if not tried:
                break
            if time.time() >= deadline:
                raise last_err or ConnectionRefusedError(111, 'Connection refused')
            time.sleep(0.05)
        self.sock.settimeout(1.0)
        self.no_ack = False
        # Query last signal to synchronize
        try:
            _ = self._send_packet("?")
        except Exception:
            pass
        # Try to switch to no-ack mode to avoid per-packet acks
        try:
            resp = self._send_packet("QStartNoAckMode")
            if resp == "OK":
                self.no_ack = True
        except Exception:
            pass

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
        if not getattr(self, "no_ack", False):
            try:
                _ = self.sock.recv(1)
            except Exception:
                pass
        # Rely on _recv_packet for reply status
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
                if not getattr(self, "no_ack", False):
                    try:
                        self.sock.sendall(b"+")
                    except Exception:
                        pass
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

    # qXfer helpers
    def qxfer_read(self, obj: str, annex: str = "", chunk: int = 4096) -> Optional[str]:
        """Read a qXfer object (like memory-map or features) and return text or None."""
        off = 0
        out = []
        while True:
            req = f"qXfer:{obj}:read:{annex}:{off:x},{chunk:x}"
            resp = self._send_packet(req)
            if not resp:
                return None
            typ, data = resp[0], resp[1:]
            out.append(data)
            off += len(data)
            if typ == "l":
                break
            if typ != "m":
                return None
        return "".join(out)

    def set_sw_breakpoint(self, addr: int, kind: int) -> bool:
        resp = self._send_packet(f"Z0,{addr:x},{kind:x}")
        return resp == "OK"

    def remove_sw_breakpoint(self, addr: int, kind: int) -> bool:
        resp = self._send_packet(f"z0,{addr:x},{kind:x}")
        return resp == "OK"

    def get_pc_via_features(self) -> Optional[int]:
        """Return PC value by discovering PC register number from features and reading it.

        This uses qXfer:features:read:target.xml and the 'p' command.
        """
        xml = self.qxfer_read("features", "target.xml")
        if not xml:
            return None
        try:
            root = ET.fromstring(xml)
        except Exception:
            return None
        regnum = 0
        pc_num = None
        for feat in root.findall("feature"):
            for reg in feat.findall("reg"):
                name = reg.get("name", "")
                if name == "pc":
                    pc_num = int(reg.get("regnum", str(regnum)))
                    break
                regnum += 1
            if pc_num is not None:
                break
        if pc_num is None:
            return None
        val = self._send_packet(f"p{pc_num:x}")
        if val.startswith("E"):
            return None
        try:
            return int(val, 16)
        except ValueError:
            return None


class QemuGdbCollector(CoverageCollector):
    """Coverage collector that talks to a QEMU `-g` instance."""

    def __init__(self, host: str = "127.0.0.1", port: int = 1234, arch: str = "x86_64"):
        self.host = host
        self.port = port
        self.arch = arch
        if arch not in _SUPPORTED_ARCHS:
            raise RuntimeError(f"Unsupported arch: {arch}")
        self.bp_kind = 1 if arch in ("x86_64", "amd64") else 4

    def _resolve_exe(self, pid: int, exe: Optional[str]) -> Optional[str]:
        return exe

    def _get_image_base(self, pid: int, exe: str) -> int:
        # For stability across qemu-user builds, avoid qXfer memory-map here.
        # We will rely on section VMAs for ET_EXEC and default to 0 otherwise.
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
    ) -> dict[Edge, int]:
        if exe is None:
            raise RuntimeError("Executable path required")
        gdb = GDBRemote(self.host, self.port)
        self._gdb = gdb
        try:
            blocks = get_basic_blocks(exe)
            # Sampling to reduce RSP overhead on large binaries, but always
            # prioritize the entry block vicinity to guarantee early hits.
            SAMPLE_MAX = 2048
            # Compute entry-relative offset if possible
            entry_off = 0
            try:
                from elftools.elf.elffile import ELFFile
                with open(exe, "rb") as f:
                    elf = ELFFile(f)
                    entry = elf.header.get("e_entry", 0)
                    text = elf.get_section_by_name(".text")
                    tbase_hint = text["sh_addr"] if text is not None else 0
                    if entry and tbase_hint:
                        entry_off = max(0, entry - tbase_hint)
            except Exception:
                pass
            pri = []
            if entry_off:
                pri.append(entry_off)
                # Also try a couple of nearby addresses to catch alignment
                for delta in (4, 8, 12, 16):
                    pri.append(entry_off + delta)
            # Dedup while preserving order: prioritize pri, then sample rest
            pri_set = []
            seen = set()
            for b in pri:
                if b in seen:
                    continue
                pri_set.append(b)
                seen.add(b)
            rest = [b for b in blocks if b not in seen]
            if len(pri_set) < SAMPLE_MAX and len(rest) > (SAMPLE_MAX - len(pri_set)):
                step = max(1, len(rest) // (SAMPLE_MAX - len(pri_set)))
                rest = rest[::step][: (SAMPLE_MAX - len(pri_set))]
            blocks = pri_set + rest
            # Compute absolute addresses for breakpoints
            base = self._get_image_base(pid, exe)
            # Derive text section VMA and entry point for context
            entry = 0
            tbase = 0
            try:
                from elftools.elf.elffile import ELFFile  # local import
                with open(exe, "rb") as f:
                    elf = ELFFile(f)
                    entry = elf.header.get("e_entry", 0)
                    text = elf.get_section_by_name(".text")
                    if text is not None:
                        tbase = text["sh_addr"] or 0
            except Exception:
                pass
            # Prefer section VMA for ET_EXEC; otherwise fall back to dynamic base
            mod_base = tbase or base
            logging.debug(
                "GDB RSP resolve: base=%#x tbase=%#x entry=%#x => mod_base=%#x",
                base,
                tbase,
                entry,
                mod_base,
            )

            breakpoints = {}
            for off in blocks:
                addr = mod_base + off
                if gdb.set_sw_breakpoint(addr, self.bp_kind):
                    breakpoints[addr] = True
                else:
                    logging.debug("Failed to set breakpoint at %#x", addr)
            logging.info(
                "GDB RSP set %d/%d breakpoints (mod_base=%#x)",
                len(breakpoints),
                len(blocks),
                mod_base,
            )

            # Start execution and trace stops; process the first stop reply
            reason = None
            try:
                reason = gdb.continue_()
            except Exception as e:
                logging.debug("RSP continue error: %s", e)
                reason = None
            end_time = time.time() + max(timeout, 0.1) * 2
            coverage: dict[Edge, int] = {}
            prev = None
            stop_count = 0
            while time.time() < end_time:
                if reason is None:
                    try:
                        reason = gdb._recv_packet()
                    except TimeoutError:
                        continue
                    except Exception as e:
                        # Connection closed or other transient; stop collecting
                        logging.debug("RSP recv error: %s", e)
                        break
                if not (reason.startswith("S") or reason.startswith("T")):
                    if reason.startswith("W") and len(reason) >= 3:
                        try:
                            code = int(reason[1:3], 16)
                        except Exception:
                            code = None
                        if code is not None:
                            logging.info("Target exited with status %d (RSP %s)", code, reason[:16])
                        else:
                            logging.info("Target exited (RSP %s)", reason[:16])
                    else:
                        logging.debug("RSP non-stop packet: %s", reason[:64])
                    break
                # Try to get PC from stop reply; fall back to features
                pc = None
                if ";pc:" in reason:
                    try:
                        # parse like '...;pc:XXXXXXXX;...'
                        for part in reason.split(";"):
                            if part.startswith("pc:"):
                                pc = int(part.split(":", 1)[1], 16)
                                break
                    except Exception:
                        pc = None
                if pc is None:
                    pc = gdb.get_pc_via_features()
                if pc is None and self.arch.startswith("mips"):
                    # Fallback: read full register dump and extract PC by index
                    try:
                        regs = gdb.read_registers()
                        reg_bytes = 8 if "64" in self.arch else 4
                        pc_index = 37  # MIPS: 32 GPRs + lo + hi + sr + badvaddr + cause + pc
                        start = reg_bytes * pc_index
                        if len(regs) >= start + reg_bytes:
                            endian = "little" if self.arch.endswith("el") else "big"
                            pc = int.from_bytes(regs[start : start + reg_bytes], endian)
                    except Exception:
                        pc = None
                if pc is None:
                    logging.debug("RSP stop without PC: %s", reason[:64])
                    break
                # Determine which address hit: some stubs report PC at the
                # breakpoint address; others after the trap. Try both.
                hit_addr = None
                for cand in (pc, pc - self.bp_kind):
                    if cand in breakpoints:
                        hit_addr = cand
                        break
                if hit_addr is None:
                    logging.debug("RSP stop pc=%#x did not match any breakpoint", pc)
                    try:
                        reason = gdb.continue_()
                    except Exception:
                        reason = None
                    continue
                curr = (exe, hit_addr - mod_base)
                if stop_count == 0:
                    logging.info(
                        "RSP first hit: pc=%#x hit_addr=%#x curr_off=%#x", pc, hit_addr, hit_addr - mod_base
                    )
                if prev is not None:
                    edge = (prev, curr)
                    coverage[edge] = coverage.get(edge, 0) + 1
                prev = curr
                stop_count += 1

                # Step over the breakpoint
                gdb.remove_sw_breakpoint(hit_addr, self.bp_kind)
                try:
                    _ = gdb.step()
                except Exception:
                    break
                gdb.set_sw_breakpoint(hit_addr, self.bp_kind)
                try:
                    reason = gdb.continue_()
                except Exception as e:
                    logging.debug("RSP continue error: %s", e)
                    reason = None

            # Cleanup breakpoints
            for addr in list(breakpoints.keys()):
                try:
                    gdb.remove_sw_breakpoint(addr, self.bp_kind)
                except Exception:
                    pass
            return coverage
        finally:
            try:
                gdb.continue_()
            except Exception:
                pass
            gdb.close()
