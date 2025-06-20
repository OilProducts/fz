from typing import Iterable, Set

from fz.coverage.cfg import Edge


def decode_coverage(coverage: Iterable) -> Set[Edge]:
    """Return ``coverage`` decoded as a set of edges."""
    edges: Set[Edge] = set()
    for c in coverage or []:
        if (
            isinstance(c, (list, tuple))
            and len(c) == 2
            and all(isinstance(x, (list, tuple)) and len(x) == 2 for x in c)
        ):
            edges.add((tuple(c[0]), tuple(c[1])))
    return edges
