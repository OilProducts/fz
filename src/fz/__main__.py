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
from fz.harness import PreloadHarness
from fz.runner.target import run_target

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
PTRACE_TRACEME = 0

class Fuzzer:
    """Base fuzzer scaffold with simple coverage tracking."""

    def __init__(self, corpus_dir: str = "corpus", output_bytes: int = 0, minimize: bool = False):
        self.corpus = Corpus(corpus_dir, output_bytes)
        self.cfg = ControlFlowGraph()
        self.minimize = minimize

    def _run_once(self, target, data, timeout, file_input=False, network=None, libs=None, qemu_user=None, gdb_port=1234, arch=None):
        """Execute target once and record coverage."""
        coverage_set = set()
        if network:
            coverage_set, crashed, timed_out, exit_code, stdout_data, stderr_data = network.run(
                target, data, timeout, self.corpus.output_bytes, libs=libs
            )
            logging.debug(
                "Network run returned %d coverage entries", len(coverage_set)
            )
        else:
            coverage_set, crashed, timed_out, exit_code, stdout_data, stderr_data = run_target(
                target,
                data,
                timeout,
                file_input=file_input,
                output_bytes=self.corpus.output_bytes,
                libs=libs,
                qemu_user=qemu_user,
                gdb_port=gdb_port,
                arch=arch,
                env=None,
            )
            logging.debug(
                "Run returned %d coverage entries", len(coverage_set)
            )

        category = "interesting"
        if crashed:
            category = "crash"
        elif timed_out:
            category = "timeout"

        saved, path = self.corpus.save_input(
            data,
            coverage_set,
            category,
            stdout_data,
            stderr_data,
            exit_code=exit_code,
        )
        if saved and self.minimize:
            self.corpus.minimize_input(
                path,
                target,
                timeout,
                file_input=file_input if not network else False,
                network=network if network else None,
                libs=libs,
            )
        self.cfg.add_edges(coverage_set)
        return saved, coverage_set

    def _fuzz_loop(self, args, iter_counter=None, saved_counter=None):

        mode = "file" if args.file_input else "stdin"
        harness = None
        if args.preload:
            from fz.harness import PreloadHarness
            harness = PreloadHarness(args.preload)
        if args.tcp:
            host, port = args.tcp
            harness = NetworkHarness(host, int(port), udp=False)
            mode = "tcp"
        elif args.udp:
            host, port = args.udp
            harness = NetworkHarness(host, int(port), udp=True)
            mode = "udp"
        elif args.preload:
            mode = "preload"
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
                    args.target,
                    data,
                    args.timeout,
                    args.file_input,
                    harness,
                    args.instrument_libs,
                    qemu_user=args.qemu_user,
                    gdb_port=args.gdb_port,
                    arch=args.arch,
                )
                mutator.record_result(data, coverage_set, interesting)
                if interesting:
                    saved += 1
                    if saved_counter is not None:
                        with saved_counter.get_lock():
                            saved_counter.value += 1
                if iter_counter is not None:
                    with iter_counter.get_lock():
                        iter_counter.value += 1
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

        return stats

    def run(self, args):
        possible_edges = get_possible_edges(args.target)
        total_edges = len(possible_edges)

        if args.parallel > 1:
            import multiprocessing
            from fz.corpus.corpus import corpus_stats
            ctx = multiprocessing.get_context()
            iter_counter = ctx.Value('i', 0)
            saved_counter = ctx.Value('i', 0)

            processes = []
            start_time = time.time()

            for _ in range(args.parallel):
                p = ctx.Process(target=_worker, args=(args, iter_counter, saved_counter))
                p.start()
                processes.append(p)

            try:
                make_table = None
                try:
                    from rich.live import Live
                    from rich.table import Table

                    def make_table(iters, saves, rate, samples, edges):
                        table = Table()
                        table.add_column("Iterations", justify="right")
                        table.add_column("Saved", justify="right")
                        table.add_column("Rate", justify="right")
                        table.add_column("Corpus", justify="right")
                        table.add_column("Edges", justify="right")
                        table.add_row(
                            str(iters),
                            str(saves),
                            f"{rate:.2f}/sec",
                            str(samples),
                            str(edges),
                        )
                        return table
                except Exception:
                    Live = None

                def snapshot():
                    elapsed = time.time() - start_time
                    iters = iter_counter.value
                    saves = saved_counter.value
                    rate = iters / elapsed if elapsed > 0 else 0.0
                    samples, covered = corpus_stats(args.corpus_dir)
                    edges = f"{covered}/{total_edges}" if total_edges else str(covered)
                    if make_table is None:
                        return (
                            f"iters={iters} saved={saves} rate={rate:.2f}/sec "
                            f"corpus={samples} edges={edges}"
                        )
                    return make_table(iters, saves, rate, samples, edges)

                if Live:
                    with Live(snapshot(), refresh_per_second=1) as live:
                        while any(p.is_alive() for p in processes):
                            live.update(snapshot())
                            time.sleep(1)
                else:
                    while any(p.is_alive() for p in processes):
                        print(snapshot(), end="\r", flush=True)
                        time.sleep(1)
            finally:
                for p in processes:
                    p.join()

            duration = time.time() - start_time
            total_iters = iter_counter.value
            total_saved = saved_counter.value

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
            samples, covered = corpus_stats(args.corpus_dir)
            logging.info("Corpus entries: %d (+%d new)", samples, total_saved)
            edge_info = f"{covered}/{total_edges}" if total_edges else str(covered)
            logging.info("Unique coverage edges: %s", edge_info)

            return

        stats = self._fuzz_loop(args)
        from fz.corpus.corpus import corpus_stats

        samples, covered = corpus_stats(args.corpus_dir)
        total_edges = len(possible_edges)
        logging.info("Corpus entries: %d (+%d new)", samples, stats.get("saved", 0))
        edge_info = f"{covered}/{total_edges}" if total_edges else str(covered)
        logging.info("Unique coverage edges: %s", edge_info)


def _worker(args, iter_counter=None, saved_counter=None):
    if not logging.getLogger().hasHandlers():
        level = logging.DEBUG if getattr(args, "debug", False) else logging.INFO
        logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s")
    fuzzer = Fuzzer(args.corpus_dir, args.output_bytes, args.minimize)
    fuzzer._fuzz_loop(args, iter_counter, saved_counter)

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
    parser.add_argument(
        "--instrument-libs",
        nargs="+",
        metavar="LIB",
        default=[],
        help="Names of shared libraries to instrument for coverage",
    )
    parser.add_argument(
        "--qemu-user",
        help="Path to qemu-user binary for emulation",
    )
    parser.add_argument(
        "--gdb-port",
        type=int,
        default=1234,
        help="GDB port for qemu-user",
    )
    parser.add_argument(
        "--arch",
        default="x86_64",
        help="Target architecture when using qemu-user",
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
        "--preload",
        metavar="LIB",
        help="Path to LD_PRELOAD library for harnessing",
    )
    parser.add_argument(
        "--corpus-dir",
        default="corpus",
        help="Directory to store interesting test cases",
    )
    parser.add_argument(
        "--minimize",
        action="store_true",
        help="Minimize saved crashing and interesting inputs",
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
    fuzzer = Fuzzer(args.corpus_dir, args.output_bytes, args.minimize)
    fuzzer.run(args)


if __name__ == "__main__":
    main()
