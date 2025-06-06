import argparse
import logging
import os
import subprocess
import tempfile

class Fuzzer:
    """Base fuzzer scaffold."""

    def __init__(self):
        pass

    def _run_once(self, target, data, timeout, file_input=False):
        """Execute target with the provided input data."""
        try:
            if file_input:
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(data)
                    tmp.flush()
                    filename = tmp.name
                try:
                    result = subprocess.run(
                        [target, filename], capture_output=True, timeout=timeout
                    )
                finally:
                    os.unlink(filename)
            else:
                result = subprocess.run(
                    [target], input=data, capture_output=True, timeout=timeout
                )
            logging.debug("Return code: %d", result.returncode)
        except subprocess.TimeoutExpired:
            logging.warning("Execution timed out")

    def run(self, args):
        mode = "file" if args.file_input else "stdin"
        logging.info("Running %s fuzzer", mode)
        logging.info("Target: %s", args.target)
        logging.info("Iterations: %d", args.iterations)

        for i in range(args.iterations):
            data = os.urandom(args.input_size)
            logging.debug("Iteration %d sending %d bytes", i, len(data))
            self._run_once(args.target, data, args.timeout, args.file_input)


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
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    args = parse_args()
    fuzzer = Fuzzer()
    fuzzer.run(args)


if __name__ == "__main__":
    main()
