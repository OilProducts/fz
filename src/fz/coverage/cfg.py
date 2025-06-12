class ControlFlowGraph:
    """Simple directed graph built from basic block transitions."""

    def __init__(self) -> None:
        # adjacency list mapping src -> {dst1, dst2, ...}
        self.adj = {}
        # execution count of each edge (src, dst)
        self.edge_counts = {}

    def add_edges(self, edges):
        """Add a sequence of (src, dst) edges to the graph."""
        for src, dst in edges:
            self.adj.setdefault(src, set()).add(dst)
            key = (src, dst)
            self.edge_counts[key] = self.edge_counts.get(key, 0) + 1

    def edge_count(self, edge):
        return self.edge_counts.get(edge, 0)

    def new_edge_count(self, edges):
        """Return how many edges in *edges* are new to the graph."""
        return sum(1 for e in edges if e not in self.edge_counts)

    def num_edges(self):
        return len(self.edge_counts)

    def num_nodes(self):
        return len(self.adj)
