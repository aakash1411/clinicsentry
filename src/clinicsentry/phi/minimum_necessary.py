"""HIPAA § 164.502(b) Minimum Necessary Standard enforcement (README §6).

The decorator filters tool inputs to the declared whitelist before the tool's
body runs. It supports both sync and async callables. ``allowed_fields`` are
dotted paths into the first dict-like positional argument or any keyword
argument whose value is a dict.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Iterable
from typing import Any, TypeVar

__all__ = [
    "minimum_necessary",
]

F = TypeVar("F", bound=Callable[..., Any])


def _filter_dict(data: dict[str, Any], allowed: Iterable[str]) -> dict[str, Any]:
    """Return a deep-copied dict containing only ``allowed`` dotted paths."""
    allowed_set = {a.lstrip(".") for a in allowed}
    out: dict[str, Any] = {}
    for path in allowed_set:
        parts = path.split(".")
        src: Any = data
        for p in parts:
            if isinstance(src, dict) and p in src:
                src = src[p]
            else:
                src = _MISSING
                break
        if src is _MISSING:
            continue
        # Materialize into nested dict structure under ``out``.
        cursor: dict[str, Any] = out
        for p in parts[:-1]:
            cursor = cursor.setdefault(p, {})
        cursor[parts[-1]] = src
    return out


_MISSING = object()


def minimum_necessary(
    allowed_fields: list[str],
    purpose: str = "",
) -> Callable[[F], F]:
    """Decorator: strip arguments to the minimum necessary set.

    Example::

        @minimum_necessary(["patient.mrn", "encounter.date"], purpose="scheduling")
        async def schedule_appointment_tool(patient_fhir_resource: dict) -> dict: ...
    """

    def decorate(func: F) -> F:
        is_coro = inspect.iscoroutinefunction(func)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            new_args, new_kwargs = _strip_args(args, kwargs, allowed_fields)
            return func(*new_args, **new_kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            new_args, new_kwargs = _strip_args(args, kwargs, allowed_fields)
            return await func(*new_args, **new_kwargs)

        chosen: Any = async_wrapper if is_coro else sync_wrapper
        chosen.__minimum_necessary__ = {
            "allowed_fields": list(allowed_fields),
            "purpose": purpose,
        }
        return chosen  # type: ignore[no-any-return]

    return decorate


def _strip_args(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    allowed: list[str],
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """Return (args, kwargs) with the first dict found filtered to ``allowed``."""
    new_args = list(args)
    for i, a in enumerate(new_args):
        if isinstance(a, dict):
            new_args[i] = _filter_dict(a, allowed)
            return tuple(new_args), kwargs
    new_kwargs = dict(kwargs)
    for k, v in list(new_kwargs.items()):
        if isinstance(v, dict):
            new_kwargs[k] = _filter_dict(v, allowed)
            break
    return tuple(new_args), new_kwargs
