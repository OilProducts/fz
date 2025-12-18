import logging
import socket
import subprocess
import time
import tempfile

from fz import coverage
import ctypes
import ctypes.util
import os
import signal

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
PTRACE_TRACEME = 0


class NetworkHarness:
    """Launch a network service target and interact with it over TCP/UDP."""

    def __init__(self, host="127.0.0.1", port=0, udp=False):
        self.host = host
        self.port = port
        self.udp = udp

    def run(self, target, data, timeout, output_bytes=0, libs=None):
        """Start the target, send bytes over the network, and collect coverage.

        Parameters
        ----------
        target:
            Executable path for the network service.
        data:
            Bytes to send after connecting.
        timeout:
            Seconds to wait for the service before killing it.
        output_bytes:
            Maximum amount of stdout/stderr to capture.
        libs:
            Optional list of library names to instrument for coverage.

        Returns
        -------
        tuple
            ``(coverage_map, crashed, timed_out, exit_code, stdout, stderr)``
        """
        logging.debug("Launching network target: %s", target)
        stdout_file = tempfile.TemporaryFile()
        stderr_file = tempfile.TemporaryFile()

        def _trace_me():
            libc.ptrace(PTRACE_TRACEME, 0, None, None)

        proc = subprocess.Popen(
            [target], stdout=stdout_file, stderr=stderr_file, preexec_fn=_trace_me
        )
        os.waitpid(proc.pid, 0)
        sock_type = socket.SOCK_DGRAM if self.udp else socket.SOCK_STREAM
        sock = socket.socket(socket.AF_INET, sock_type)

        start = time.time()
        while True:
            try:
                sock.connect((self.host, self.port))
                logging.debug("Connected to %s:%d", self.host, self.port)
                break
            except (ConnectionRefusedError, OSError):
                if time.time() - start > timeout:
                    proc.kill()
                    raise RuntimeError("Could not connect to target service")
                time.sleep(0.1)
                logging.debug("Retrying connection...")

        crashed = False
        timed_out = False
        exit_code = None
        try:
            logging.debug("Sending %d bytes", len(data))
            sock.sendall(data)
            sock.close()
            collector = coverage.get_collector()
            try:
                coverage_set = collector.collect_coverage(
                    proc.pid, timeout, already_traced=True, libs=libs
                )
            except Exception as e:
                logging.debug("Collector error for pid %d: %s", proc.pid, e)
                coverage_set = {}
            logging.debug("Collected %d coverage entries", len(coverage_set))
            try:
                proc.wait(timeout=timeout)
                exit_code = proc.returncode
                crashed = exit_code is not None and exit_code < 0
            except subprocess.TimeoutExpired:
                proc.kill()
                timed_out = True
                logging.warning("Execution timed out")
        finally:
            if proc.poll() is None:
                proc.kill()
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout_data = stdout_file.read(output_bytes) if output_bytes else b""
        stderr_data = stderr_file.read(output_bytes) if output_bytes else b""
        stdout_file.close()
        stderr_file.close()
        logging.debug("Network run complete with %d coverage entries", len(coverage_set))
        return coverage_set, crashed, timed_out, exit_code, stdout_data, stderr_data
