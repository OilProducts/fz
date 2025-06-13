class ControlFlowGraph:
    """Simple directed graph built from basic block transitions."""

    def __init__(self) -> None:
        # adjacency list mapping src -> {dst1, dst2, ...}
        self.adj = {}
        # execution count of each edge (src, dst)
        self.edge_counts = {}
        # edges discovered via static analysis
        self.possible_edges = set()

    def add_edges(self, edges):
        """Add a sequence of (src, dst) edges to the graph."""
        for src, dst in edges:
            self.adj.setdefault(src, set()).add(dst)
            key = (src, dst)
            self.edge_counts[key] = self.edge_counts.get(key, 0) + 1

    def add_possible_edges(self, edges):
        """Record statically discovered edges without incrementing counts."""
        for src, dst in edges:
            self.adj.setdefault(src, set()).add(dst)
            self.possible_edges.add((src, dst))

    def edge_count(self, edge):
        return self.edge_counts.get(edge, 0)

    def new_edge_count(self, edges):
        """Return how many edges in *edges* are new to the graph."""
        return sum(1 for e in edges if e not in self.edge_counts)

    def num_edges(self):
        return len(self.edge_counts)

    def num_nodes(self):
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
                lines.append(f"    \"{src:#x}\" -> \"{dst:#x}\"{attr_str};")
        lines.append("}")
        return "\n".join(lines)
