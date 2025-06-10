import argparse
import logging
import os
import subprocess
import tempfile
import time

try:
    import yaml
except ImportError:  # pragma: no cover - optional dependency
    yaml = None

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
            logging.debug("Network run returned %d coverage entries", len(coverage_set))
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

            logging.debug("Launching target: %s", " ".join(argv))
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if not file_input else None,
            )

            if not file_input and proc.stdin:
                try:
                    proc.stdin.write(data)
                except BrokenPipeError:
                    logging.debug("Stdin pipe closed before data was written")
                finally:
                    try:
                        proc.stdin.close()
                    except BrokenPipeError:
                        logging.debug("Broken pipe when closing stdin")

            logging.debug("Collecting coverage from pid %d", proc.pid)
            try:
                coverage_set = coverage.collect_coverage(proc.pid, timeout)
            except FileNotFoundError:
                logging.debug(
                    "Process %d exited before coverage collection", proc.pid
                )
                coverage_set = set()
            except OSError as e:
                logging.debug(
                    "Failed to collect coverage from pid %d: %s", proc.pid, e
                )
                coverage_set = set()
            logging.debug("Collected %d coverage entries", len(coverage_set))
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
        if args.tcp:
            host, port = args.tcp
            harness = NetworkHarness(host, int(port), udp=False)
            mode = "tcp"
        elif args.udp:
            host, port = args.udp
            harness = NetworkHarness(host, int(port), udp=True)
            mode = "udp"
        logging.info("Running %s fuzzer", mode)
        logging.info("Target: %s", args.target)
        iter_desc = "infinite" if args.run_forever else str(args.iterations)
        logging.info("Iterations: %s", iter_desc)

        start_time = time.time()
        i = 0
        try:
            while True:
                data = os.urandom(args.input_size)
                logging.debug("Iteration %d sending %d bytes", i, len(data))
                self._run_once(args.target, data, args.timeout, args.file_input, harness)
                i += 1
                if not args.run_forever and i >= args.iterations:
                    break
        except KeyboardInterrupt:
            logging.info("Fuzzing interrupted by user")
        duration = time.time() - start_time
        if duration > 0:
            rate = i / duration
            logging.info(
                "Executed %d iterations in %.2f seconds (%.2f/sec)",
                i,
                duration,
                rate,
            )
        else:
            logging.info("Executed %d iterations", i)


def parse_args():
    # First parse only the --config argument so we can load defaults from file
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--config", help="Path to YAML config file")
    config_args, _ = config_parser.parse_known_args()

    config_data = {}
    if config_args.config:
        if not yaml:
            raise RuntimeError("PyYAML is required for configuration files")
        with open(config_args.config) as f:
            config_data = yaml.safe_load(f) or {}

    parser = argparse.ArgumentParser(
        description="fz - a lightweight Python fuzzer", parents=[config_parser]
    )
    parser.add_argument("--target", required=True, help="Path to target binary or script")
    parser.add_argument("--iterations", type=int, default=1, help="Number of test iterations to run")
    parser.add_argument(
        "--run-forever",
        action="store_true",
        help="Run indefinitely until interrupted",
    )
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
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--file-input",
        action="store_true",
        help="Write input to a temporary file and pass its path to the target",
    )
    mode_group.add_argument(
        "--tcp",
        nargs=2,
        metavar=("HOST", "PORT"),
        help="Send input over TCP to HOST and PORT",
    )
    mode_group.add_argument(
        "--udp",
        nargs=2,
        metavar=("HOST", "PORT"),
        help="Send input over UDP to HOST and PORT",
    )
    parser.add_argument(
        "--corpus-dir",
        default="corpus",
        help="Directory to store interesting test cases",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    # Verify config keys match existing parser options and set them as defaults
    if config_data:
        valid_dests = {action.dest for action in parser._actions}
        unknown_keys = set(config_data) - valid_dests
        if unknown_keys:
            raise ValueError(
                f"Unknown config options: {', '.join(sorted(unknown_keys))}"
            )
        for action in parser._actions:
            if action.dest in config_data:
                action.required = False
        parser.set_defaults(**config_data)

    return parser.parse_args()


def main():
    args = parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s")
    fuzzer = Fuzzer(args.corpus_dir)
    fuzzer.run(args)


if __name__ == "__main__":
    main()
