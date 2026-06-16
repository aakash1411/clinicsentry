"""PHI propagation graph (Module 1)."""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field

from clinicsentry.types import PHITag

__all__ = [
    "PropagationGraph",
]


@dataclass
class PropagationGraph:
    """Tracks PHI tags as they flow across agent and tool boundaries.

    Edges represent observed propagations from one node (agent/tool/llm) to
    another carrying a specific tag. Stored as adjacency lists keyed by tag id.
    Mutations are thread-safe — adapters may run interceptors concurrently.
    """

    tags: dict[str, PHITag] = field(default_factory=dict)
    edges: dict[str, list[tuple[str, str]]] = field(default_factory=lambda: defaultdict(list))
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def register(self, tag: PHITag) -> None:
        """Add (or refresh) a tag in the graph."""
        with self._lock:
            self.tags[tag.tag_id] = tag

    def propagate(self, tag_id: str, src: str, dst: str) -> None:
        """Record that ``tag_id`` was forwarded from ``src`` to ``dst``."""
        with self._lock:
            if tag_id not in self.tags:
                return
            self.edges[tag_id].append((src, dst))
            path = self.tags[tag_id].propagation_path
            if not path or path[-1] != src:
                path.append(src)
            path.append(dst)

    def to_dict(self) -> dict[str, object]:
        """Serialize for inclusion in regulatory reports."""
        with self._lock:
            return {
                "tags": {tid: t.to_dict() for tid, t in self.tags.items()},
                "edges": {tid: list(es) for tid, es in self.edges.items()},
            }
