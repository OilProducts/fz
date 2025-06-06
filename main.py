import argparse
import logging

class Fuzzer:
    """Base fuzzer scaffold."""

    def __init__(self):
        pass

    def run(self, args):
        logging.info("Running fuzzer stub")
        logging.info("Target: %s", args.target)
        logging.info("Iterations: %d", args.iterations)


def parse_args():
    parser = argparse.ArgumentParser(description="fz - a lightweight Python fuzzer")
    parser.add_argument("--target", required=True, help="Path to target binary or script")
    parser.add_argument("--iterations", type=int, default=1, help="Number of test iterations to run")
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    args = parse_args()
    fuzzer = Fuzzer()
    fuzzer.run(args)


if __name__ == "__main__":
    main()
