import argparse
from .utils import get_possible_edges
from .cfg import ControlFlowGraph


def main() -> None:
    parser = argparse.ArgumentParser(description="Visualize the control flow graph of a binary")
    parser.add_argument("binary", help="Path to the binary to analyze")
    parser.add_argument("--output", "-o", help="Write DOT graph to file instead of stdout")
    args = parser.parse_args()

    edges = get_possible_edges(args.binary)
    cfg = ControlFlowGraph()
    cfg.add_possible_edges(edges)
    dot = cfg.to_dot()

    if args.output:
        with open(args.output, "w") as f:
            f.write(dot)
    else:
        print(dot)


if __name__ == "__main__":
    main()
