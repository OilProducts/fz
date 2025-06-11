import argparse
import base64
import json
import os
from typing import Iterable


"""Simple utility to inspect saved corpus samples."""


def _iter_samples(directory: str) -> Iterable[str]:
    """Yield full paths to JSON corpus entries in *directory*."""
    if not os.path.isdir(directory):
        return []
    for name in sorted(os.listdir(directory)):
        if name.endswith('.json'):
            yield os.path.join(directory, name)


def _decode_field(value: str) -> str:
    data = base64.b64decode(value)
    try:
        return data.decode('utf-8', 'replace')
    except Exception:
        return data.hex()


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze stored corpus samples")
    parser.add_argument(
        "--corpus-dir",
        default="corpus",
        help="Directory containing saved corpus entries",
    )
    args = parser.parse_args()

    for path in _iter_samples(args.corpus_dir):
        with open(path) as f:
            record = json.load(f)
        for key in ("stdout", "stderr"):
            if key in record:
                print(f"== {key.upper()} from {os.path.basename(path)} ==")
                print(_decode_field(record[key]))
                print()


if __name__ == "__main__":
    main()
