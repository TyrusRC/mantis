"""Context graph reachability semantics."""
from __future__ import annotations


def test_no_call_path_is_unknown_not_unreachable():
    from mantis.context_graph import ContextGraph, GraphEdge, GraphNode
    g = ContextGraph()
    for name in ("handler", "helper"):
        g.nodes[f"a.py:{name}"] = GraphNode(id=f"a.py:{name}", kind="function", name=name,
                                            file="a.py", line=1, end_line=3)
    g.edges.append(GraphEdge(source="a.py:helper", target="a.py:handler",
                             relation="calls", confidence="EXTRACTED"))
    g._index_edges()
    # A caller chain that never meets a route only means the graph found no path.
    assert g.reaches_entry_point("handler", "a.py") == "unknown"
