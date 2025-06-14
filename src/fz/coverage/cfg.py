import os
from typing import Dict, Iterable, Set, Tuple


Address = Tuple[str, int]
Edge = Tuple[Address, Address]


class ControlFlowGraph:
    """Simple directed graph built from basic block transitions."""

    def __init__(self) -> None:
        """Create an empty control flow graph."""
        # adjacency list mapping ``src`` -> ``{dst1, dst2, ...}``
        self.adj: Dict[Address, Set[Address]] = {}
        # execution count of each edge ``(src, dst)``
        self.edge_counts: Dict[Edge, int] = {}
        # edges discovered via static analysis
        self.possible_edges: Set[Edge] = set()

    def add_edges(self, edges: Iterable[Edge]) -> None:
        """Add executed edges to the graph and increment their counters.

        Parameters
        ----------
        edges:
            Iterable of ``(src, dst)`` edges that were observed during
            execution.
        """
        for src, dst in edges:
            self.adj.setdefault(src, set()).add(dst)
            key = (src, dst)
            self.edge_counts[key] = self.edge_counts.get(key, 0) + 1

    def add_possible_edges(self, edges: Iterable[Edge]) -> None:
        """Record statically discovered edges without incrementing counts.

        Parameters
        ----------
        edges:
            Iterable of possible ``(src, dst)`` transitions.
        """
        for src, dst in edges:
            self.adj.setdefault(src, set()).add(dst)
            self.possible_edges.add((src, dst))

    def edge_count(self, edge: Edge) -> int:
        """Return how many times ``edge`` was observed."""
        return self.edge_counts.get(edge, 0)

    def new_edge_count(self, edges: Iterable[Edge]) -> int:
        """Return how many edges in ``edges`` are new to the graph."""
        return sum(1 for e in edges if e not in self.edge_counts)

    def num_edges(self) -> int:
        """Return the number of unique executed edges."""
        return len(self.edge_counts)

    def num_nodes(self) -> int:
        """Return the number of unique nodes in the graph."""
        return len(self.adj)

    def to_dot(self) -> str:
        """Return the graph in Graphviz dot format."""
        lines = ["digraph cfg {"]
        for src, dsts in self.adj.items():
            for dst in dsts:
                edge = (src, dst)
                attrs = []
                if edge not in self.edge_counts:
                    if edge in self.possible_edges:
                        attrs.append("style=dashed")
                if edge in self.edge_counts:
                    count = self.edge_counts[edge]
                    attrs.append(f"label=\"{count}\"")
                attr_str = "" if not attrs else " [" + ",".join(attrs) + "]"
                src_mod, src_off = src
                dst_mod, dst_off = dst
                src_label = f"{os.path.basename(src_mod)}:{src_off:#x}"
                dst_label = f"{os.path.basename(dst_mod)}:{dst_off:#x}"
                lines.append(
                    f"    \"{src_label}\" -> \"{dst_label}\"{attr_str};"
                )
        lines.append("}")
        return "\n".join(lines)
