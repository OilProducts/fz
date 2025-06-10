import logging
import socket
import subprocess
import time

import coverage


class NetworkHarness:
    """Launch a network service target and interact with it over TCP/UDP."""

    def __init__(self, host="127.0.0.1", port=0, udp=False, block_coverage=False):
        self.host = host
        self.port = port
        self.udp = udp
        self.block_coverage = block_coverage

    def run(self, target, data, timeout):
        """Start the target, send bytes over the network, and collect coverage."""
        logging.debug("Launching network target: %s", target)
        proc = subprocess.Popen([target])
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

        try:
            logging.debug("Sending %d bytes", len(data))
            sock.sendall(data)
            sock.close()
            coverage_set = coverage.collect_coverage(proc.pid, self.block_coverage)
            logging.debug("Collected %d coverage entries", len(coverage_set))
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                logging.warning("Execution timed out")
        finally:
            if proc.poll() is None:
                proc.kill()
        logging.debug("Network run complete with %d coverage entries", len(coverage_set))
        return coverage_set
