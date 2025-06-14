import argparse
import logging
import os
import subprocess
import tempfile
import time
import ctypes
import ctypes.util
import signal

try:
    import yaml
except ImportError:  # pragma: no cover - optional dependency
    yaml = None

from fz import coverage
from fz.coverage import ControlFlowGraph, get_possible_edges
from fz.corpus.corpus import Corpus
from fz.harness.network import NetworkHarness
from fz.runner.target import run_target

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
PTRACE_TRACEME = 0

class Fuzzer:
    """Base fuzzer scaffold with simple coverage tracking."""

    def __init__(self, corpus_dir: str = "corpus", output_bytes: int = 0):
        self.corpus = Corpus(corpus_dir, output_bytes)
        self.cfg = ControlFlowGraph()

    def _run_once(self, target, data, timeout, file_input=False, network=None):
        """Execute target once and record coverage."""
        coverage_set = set()
        if network:
            coverage_set, crashed, timed_out, stdout_data, stderr_data = network.run(
                target, data, timeout, self.corpus.output_bytes
            )
            logging.debug(
                "Network run returned %d coverage entries", len(coverage_set)
            )
        else:
            coverage_set, crashed, timed_out, stdout_data, stderr_data = run_target(
                target,
                data,
                timeout,
                file_input=file_input,
                output_bytes=self.corpus.output_bytes,
            )
            logging.debug(
                "Run returned %d coverage entries", len(coverage_set)
            )

        if crashed or timed_out:
            prefix = "crash" if crashed else "timeout"
            saved, orig = self.corpus.save_input(
                data,
                coverage_set,
                prefix,
                stdout_data,
                stderr_data,
            )
            if saved:
                self.corpus.minimize_input(
                    orig,
                    target,
                    timeout,
                    file_input=file_input if not network else False,
                    network=network if network else None,
                )

        interesting, path = self.corpus.save_input(
            data, coverage_set, "interesting", stdout_data, stderr_data
        )
        if interesting:
            self.corpus.minimize_input(
                path,
                target,
                timeout,
                file_input=file_input if not network else False,
                network=network if network else None,
            )
        self.cfg.add_edges(coverage_set)
        return interesting, coverage_set

    def _fuzz_loop(self, args, result_queue=None):
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

        possible = get_possible_edges(args.target)
        if possible:
            logging.debug("Loaded %d static CFG edges", len(possible))
            self.cfg.add_possible_edges(possible)

        start_time = time.time()
        i = 0
        saved = 0
        from fz.corpus.mutator import Mutator
        mutator = Mutator(args.corpus_dir, args.input_size, args.mutations, cfg=self.cfg)
        try:
            while True:
                data = mutator.next_input()
                logging.debug("Iteration %d sending %d bytes", i, len(data))
                interesting, coverage_set = self._run_once(
                    args.target, data, args.timeout, args.file_input, harness
                )
                mutator.record_result(data, coverage_set, interesting)
                if interesting:
                    saved += 1
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
        stats = {
            "iterations": i,
            "saved": saved,
            "duration": duration,
            "edges": self.cfg.num_edges(),
        }
        if result_queue is not None:
            result_queue.put(stats)
        return stats

    def run(self, args):
        if args.parallel > 1:
            import multiprocessing
            from fz.corpus.corpus import corpus_stats

            ctx = multiprocessing.get_context("spawn")
            result_queue = ctx.SimpleQueue()

            processes = []
            start_time = time.time()
            from fz.worker import worker

            for _ in range(args.parallel):
                p = ctx.Process(target=worker, args=(args, result_queue))
                p.start()
                processes.append(p)

            results = []
            for _ in processes:
                results.append(result_queue.get())
            for p in processes:
                p.join()

            duration = time.time() - start_time
            total_iters = sum(r["iterations"] for r in results)
            total_saved = sum(r["saved"] for r in results)
            if duration > 0:
                rate = total_iters / duration
                logging.info(
                    "Executed %d iterations in %.2f seconds (%.2f/sec)",
                    total_iters,
                    duration,
                    rate,
                )
            else:
                logging.info("Executed %d iterations", total_iters)
            samples, edges = corpus_stats(args.corpus_dir)
            logging.info("Corpus entries: %d (+%d new)", samples, total_saved)
            logging.info("Unique coverage edges: %d", edges)
            return

        self._fuzz_loop(args)
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
        "--mutations",
        type=int,
        default=1,
        help="Maximum number of mutation steps applied to each input",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Seconds to wait for the target before killing it",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="Number of parallel fuzzing processes",
    )
    parser.add_argument(
        "--output-bytes",
        type=int,
        default=0,
        help="Number of stdout/stderr bytes to save with corpus samples",
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
    fuzzer = Fuzzer(args.corpus_dir, args.output_bytes)
    fuzzer.run(args)


if __name__ == "__main__":
    main()
