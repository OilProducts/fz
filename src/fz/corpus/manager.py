import argparse
import base64
import json
import os
import time
from typing import Iterable


"""Corpus management utilities.

This script replaces the old ``fz-corpus-analyzer`` entry point. It
provides subcommands to inspect existing samples and to add new ones
manually.
"""


def _iter_samples(directory: str) -> Iterable[str]:
    """Yield full paths to JSON corpus entries in *directory*."""
    if not os.path.isdir(directory):
        return []
    for root, _, files in os.walk(directory):
        for name in sorted(files):
            if name.endswith('.json'):
                yield os.path.join(root, name)


def _decode_field(value: str) -> str:
    data = base64.b64decode(value)
    try:
        return data.decode('utf-8', 'replace')
    except Exception:
        return data.hex()


def _analyze(args) -> None:
    for path in _iter_samples(args.corpus_dir):
        with open(path) as f:
            record = json.load(f)

        basename = os.path.basename(path)

        if "data" in record:
            length = len(base64.b64decode(record["data"]))
            print(f"{basename} LENGTH: {length}")

        for key in ("stdout", "stderr"):
            if key in record:
                decoded = _decode_field(record[key]).rstrip()
                print(f"{basename} {key.upper()}: {decoded}")


def _add(args) -> None:
    manual_dir = os.path.join(args.corpus_dir, "manual")
    os.makedirs(manual_dir, exist_ok=True)
    with open(args.file, "rb") as f:
        data = f.read()
    record = {
        "data": base64.b64encode(data).decode("ascii"),
        "coverage": [],
        "type": "manual",
    }
    name = f"{int(time.time() * 1000)}.json"
    path = os.path.join(manual_dir, name)
    with open(path, "w") as f:
        json.dump(record, f)
    print(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage corpus samples")
    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("list", help="List stored corpus samples")
    analyze.add_argument(
        "--corpus-dir", default="corpus", help="Directory containing corpus entries"
    )
    analyze.set_defaults(func=_analyze)

    add = subparsers.add_parser("add", help="Add a file as a corpus sample")
    add.add_argument("file", help="Path of file to add")
    add.add_argument(
        "--corpus-dir", default="corpus", help="Directory containing corpus entries"
    )
    add.set_defaults(func=_add)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        args = parser.parse_args(["list"])  # default to list

    args.func(args)
if __name__ == "__main__":
    main()
