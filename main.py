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
        "--file-input",
        action="store_true",
        help="Write input to a temporary file and pass its path to the target",
    )
    parser.add_argument(
        "--corpus-dir",
        default="corpus",
        help="Directory to store interesting test cases",
    )
    parser.add_argument("--tcp-host", help="Host to connect to via TCP")
    parser.add_argument("--tcp-port", type=int, help="Port for TCP connection")
    parser.add_argument("--udp-host", help="Host to send UDP packets to")
    parser.add_argument("--udp-port", type=int, help="Port for UDP packets")
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    args = parse_args()
    fuzzer = Fuzzer(args.corpus_dir)
    fuzzer.run(args)


if __name__ == "__main__":
    main()
