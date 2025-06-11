import logging
import socket
import subprocess
import time
import tempfile

import coverage


class NetworkHarness:
    """Launch a network service target and interact with it over TCP/UDP."""

    def __init__(self, host="127.0.0.1", port=0, udp=False):
        self.host = host
        self.port = port
        self.udp = udp

    def run(self, target, data, timeout, output_bytes=0):
        """Start the target, send bytes over the network, and collect coverage.

        Returns a tuple of (coverage_set, crashed, timed_out, stdout, stderr).
        """
        logging.debug("Launching network target: %s", target)
        stdout_file = tempfile.TemporaryFile()
        stderr_file = tempfile.TemporaryFile()
        proc = subprocess.Popen([target], stdout=stdout_file, stderr=stderr_file)
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
        try:
            logging.debug("Sending %d bytes", len(data))
            sock.sendall(data)
            sock.close()
            coverage_set = coverage.collect_coverage(proc.pid, timeout)
            logging.debug("Collected %d coverage entries", len(coverage_set))
            try:
                proc.wait(timeout=timeout)
                crashed = proc.returncode not in (0, None)
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
        return coverage_set, crashed, timed_out, stdout_data, stderr_data
