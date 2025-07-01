from typing import Iterable

from fz.coverage.cfg import Edge, EdgeCoverage


def decode_coverage(coverage: Iterable) -> EdgeCoverage:
    """Return ``coverage`` decoded as an :class:`EdgeCoverage` mapping."""
    edges: EdgeCoverage = {}
    for c in coverage or []:
        if (
            isinstance(c, (list, tuple))
            and len(c) >= 2
            and all(isinstance(x, (list, tuple)) and len(x) == 2 for x in c[:2])
        ):
            edge = (tuple(c[0]), tuple(c[1]))
            count = 1
            if len(c) >= 3 and isinstance(c[2], int):
                count = c[2]
            edges[edge] = count
    return edges
