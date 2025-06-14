import argparse
import subprocess
from .utils import get_possible_edges
from .cfg import ControlFlowGraph


def main() -> None:
    """Entry point for the ``fz.coverage.visualize`` CLI."""
    parser = argparse.ArgumentParser(description="Visualize the control flow graph of a binary")
    parser.add_argument("binary", help="Path to the binary to analyze")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--output", "-o", help="Write DOT graph to file instead of stdout")
    group.add_argument("--svg", help="Render graph directly to an SVG file")
    args = parser.parse_args()

    edges = get_possible_edges(args.binary)
    cfg = ControlFlowGraph()
    cfg.add_possible_edges(edges)
    dot = cfg.to_dot()

    if args.svg:
        result = subprocess.run([
            "dot",
            "-Tsvg",
        ], input=dot.encode(), stdout=subprocess.PIPE, check=True)
        with open(args.svg, "wb") as f:
            f.write(result.stdout)
    elif args.output:
        with open(args.output, "w") as f:
            f.write(dot)
    else:
        print(dot)


if __name__ == "__main__":
    main()
