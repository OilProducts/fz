import argparse
import logging
import os
import subprocess
import tempfile

import coverage
from corpus import Corpus
from network_harness import NetworkHarness

class Fuzzer:
    """Base fuzzer scaffold with simple coverage tracking."""

    def __init__(self, corpus_dir="corpus"):
        self.corpus = Corpus(corpus_dir)

    def _run_once(self, target, data, timeout, file_input=False, network=None):
        """Execute target once and record coverage."""
        coverage_set = set()
        if network:
            coverage_set = network.run(target, data, timeout)
            self.corpus.save_if_interesting(data, coverage_set)
            return
        try:
            if file_input:
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(data)
                    tmp.flush()
                    filename = tmp.name
                argv = [target, filename]
            else:
                argv = [target]

            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if not file_input else None,
            )

            if not file_input and proc.stdin:
                proc.stdin.write(data)
                proc.stdin.close()

            coverage_set = coverage.collect_coverage(proc.pid)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                logging.warning("Execution timed out")
        finally:
            if file_input:
                os.unlink(filename)

        self.corpus.save_if_interesting(data, coverage_set)

    def run(self, args):
        mode = "file" if args.file_input else "stdin"
        harness = None
        if args.tcp_host and args.tcp_port:
            harness = NetworkHarness(args.tcp_host, args.tcp_port, udp=False)
            mode = "tcp"
        elif args.udp_host and args.udp_port:
            harness = NetworkHarness(args.udp_host, args.udp_port, udp=True)
            mode = "udp"
        logging.info("Running %s fuzzer", mode)
        logging.info("Target: %s", args.target)
        logging.info("Iterations: %d", args.iterations)

        for i in range(args.iterations):
            data = os.urandom(args.input_size)
            logging.debug("Iteration %d sending %d bytes", i, len(data))
            self._run_once(args.target, data, args.timeout, args.file_input, harness)


def parse_args():
    parser = argparse.ArgumentParser(description="fz - a lightweight Python fuzzer")
    parser.add_argument("--target", required=True, help="Path to target binary or script")
    parser.add_argument("--iterations", type=int, default=1, help="Number of test iterations to run")
    parser.add_argument(
        "--input-size",
        type=int,
        default=256,
        help="Number of random bytes to send to the target's stdin",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Seconds to wait for the target before killing it",
    )
    parser.add_argument(
        "--corpus-dir",
        default="corpus",
        help="Directory to store interesting test cases",
    )

    subparsers = parser.add_subparsers(dest="mode", help="Input method")

    file_p = subparsers.add_parser(
        "file", help="Write input to a temporary file and pass its path to the target"
    )
    file_p.set_defaults(file_input=True)

    tcp_p = subparsers.add_parser("tcp", help="Send input over TCP to a service")
    tcp_p.add_argument("tcp_host", help="Host to connect to via TCP")
    tcp_p.add_argument("tcp_port", type=int, help="Port for TCP connection")

    udp_p = subparsers.add_parser("udp", help="Send input over UDP to a service")
    udp_p.add_argument("udp_host", help="Host to send UDP packets to")
    udp_p.add_argument("udp_port", type=int, help="Port for UDP packets")

    args = parser.parse_args()

    if getattr(args, "mode", None) != "file":
        args.file_input = False

    if args.mode != "tcp":
        args.tcp_host = None
        args.tcp_port = None

    if args.mode != "udp":
        args.udp_host = None
        args.udp_port = None

    return args


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    args = parse_args()
    fuzzer = Fuzzer(args.corpus_dir)
    fuzzer.run(args)


if __name__ == "__main__":
    main()
