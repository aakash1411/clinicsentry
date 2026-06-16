"""Targeted tests for :class:`PropagationGraph` — kills mutmut survivors."""

from __future__ import annotations

from clinicsentry.phi.propagation import PropagationGraph
from clinicsentry.types import PHITag


def _make_tag(tag_id: str = "t1") -> PHITag:
    return PHITag(
        tag_id=tag_id,
        phi_type="MRN",
        source="regex",
        redacted_value="[REDACTED:MRN]",
        confidence=0.95,
    )


def test_propagate_appends_dst_unconditionally() -> None:
    """``dst`` must always be appended, regardless of path state."""
    g = PropagationGraph()
    tag = _make_tag()
    g.register(tag)
    g.propagate("t1", "a", "b")
    g.propagate("t1", "b", "c")
    assert tag.propagation_path == ["a", "b", "c"]


def test_propagate_skips_src_when_equal_to_last() -> None:
    """When ``src`` equals the last node, only ``dst`` is appended.

    Kills mutants flipping ``not path or path[-1] != src`` to ``path or ...``,
    ``path[-1] == src``, or ``not path and path[-1] != src``.
    """
    g = PropagationGraph()
    tag = _make_tag()
    g.register(tag)
    g.propagate("t1", "a", "b")  # path: [a, b]
    g.propagate("t1", "b", "c")  # path: [a, b, c]  (b == last so b not re-appended)
    g.propagate("t1", "c", "d")  # path: [a, b, c, d]
    assert tag.propagation_path == ["a", "b", "c", "d"]


def test_propagate_adds_src_when_not_equal_to_last() -> None:
    """When ``src`` differs from the last node, both ``src`` and ``dst`` append."""
    g = PropagationGraph()
    tag = _make_tag()
    g.register(tag)
    g.propagate("t1", "a", "b")  # path: [a, b]
    g.propagate("t1", "x", "y")  # x != b, so path: [a, b, x, y]
    assert tag.propagation_path == ["a", "b", "x", "y"]


def test_propagate_first_call_seeds_both_endpoints() -> None:
    """First propagation on an empty path adds both src and dst (``not path`` branch)."""
    g = PropagationGraph()
    tag = _make_tag()
    g.register(tag)
    g.propagate("t1", "a", "b")
    assert tag.propagation_path == ["a", "b"]


def test_propagate_unknown_tag_is_noop() -> None:
    """Propagation against an unregistered tag must not create edges."""
    g = PropagationGraph()
    g.propagate("missing", "a", "b")
    assert g.edges == {}


def test_to_dict_emits_expected_keys() -> None:
    """``to_dict`` must emit exactly the keys ``tags`` and ``edges``.

    Kills mutants that rename string literals to ``XXtagsXX`` / ``XXedgesXX``.
    """
    g = PropagationGraph()
    tag = _make_tag()
    g.register(tag)
    g.propagate("t1", "a", "b")
    payload = g.to_dict()
    assert set(payload.keys()) == {"tags", "edges"}
    assert "t1" in payload["tags"]  # type: ignore[index]
    assert payload["edges"]["t1"] == [("a", "b")]  # type: ignore[index]


def test_to_dict_edges_are_tuples_per_tag() -> None:
    """Edges must be preserved as ordered list of (src, dst) tuples per tag."""
    g = PropagationGraph()
    g.register(_make_tag("t1"))
    g.register(_make_tag("t2"))
    g.propagate("t1", "a", "b")
    g.propagate("t1", "b", "c")
    g.propagate("t2", "x", "y")
    payload = g.to_dict()
    assert payload["edges"]["t1"] == [("a", "b"), ("b", "c")]  # type: ignore[index]
    assert payload["edges"]["t2"] == [("x", "y")]  # type: ignore[index]
