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


def test_to_dict_is_the_integration_seam():
    """Other agents consume the graph via to_dict()/write_json() — the schema
    must carry nodes, edges and entry points so reachability can be recomputed
    without importing mantis."""
    import json
    from mantis.context_graph import ContextGraph, GraphEdge, GraphNode

    g = ContextGraph(indexed_files=2)
    g.nodes["a.py:route"] = GraphNode(id="a.py:route", kind="route", name="route",
                                      file="a.py", line=1, end_line=4)
    g.nodes["a.py:sink"] = GraphNode(id="a.py:sink", kind="function", name="sink",
                                     file="a.py", line=5, end_line=8)
    g.edges.append(GraphEdge(source="a.py:route", target="a.py:sink",
                             relation="calls", confidence="EXTRACTED"))

    d = g.to_dict()
    assert d["schema"] == "mantis-context-graph/1"
    assert d["indexed_files"] == 2
    assert d["entry_points"] == ["a.py:route"]
    assert {n["id"] for n in d["nodes"]} == {"a.py:route", "a.py:sink"}
    assert d["edges"] == [{"source": "a.py:route", "target": "a.py:sink",
                           "relation": "calls", "confidence": "EXTRACTED"}]
    # round-trips as JSON (what write_json emits)
    assert json.loads(json.dumps(d)) == d


def test_write_json_emits_a_file(tmp_path):
    from mantis.context_graph import ContextGraph, GraphNode
    import json

    g = ContextGraph(indexed_files=1)
    g.nodes["a.py:h"] = GraphNode(id="a.py:h", kind="route", name="h",
                                  file="a.py", line=1, end_line=2)
    out = tmp_path / "graph.json"
    g.write_json(out)
    loaded = json.loads(out.read_text())
    assert loaded["entry_points"] == ["a.py:h"]
