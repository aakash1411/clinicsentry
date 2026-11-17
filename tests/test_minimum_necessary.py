"""Minimum Necessary decorator (HIPAA § 164.502(b))."""

from __future__ import annotations

import asyncio
from typing import Any

from clinicsentry.phi.minimum_necessary import minimum_necessary

RECORD = {
    "patient": {"mrn": "MRN-1", "name": "Jane", "ssn": "123-45-6789"},
    "encounter": {"date": "2026-01-01", "notes": "free text"},
    "billing": {"card": "4111"},
}


def test_sync_positional_dict_is_filtered() -> None:
    @minimum_necessary(["patient.mrn", "encounter.date"], purpose="scheduling")
    def tool(record: dict[str, Any]) -> dict[str, Any]:
        return record

    assert tool(RECORD) == {"patient": {"mrn": "MRN-1"}, "encounter": {"date": "2026-01-01"}}
    assert tool.__minimum_necessary__ == {  # type: ignore[attr-defined]
        "allowed_fields": ["patient.mrn", "encounter.date"],
        "purpose": "scheduling",
    }


def test_async_tool_is_filtered_and_stays_coroutine() -> None:
    @minimum_necessary(["patient.mrn"])
    async def tool(record: dict[str, Any]) -> dict[str, Any]:
        return record

    assert asyncio.iscoroutinefunction(tool)
    assert asyncio.run(tool(RECORD)) == {"patient": {"mrn": "MRN-1"}}


def test_missing_paths_and_non_dict_intermediates_are_skipped() -> None:
    @minimum_necessary(["patient.dob", "patient.mrn.value", "absent", ".billing.card"])
    def tool(record: dict[str, Any]) -> dict[str, Any]:
        return record

    assert tool(RECORD) == {"billing": {"card": "4111"}}


def test_only_first_positional_dict_is_filtered() -> None:
    @minimum_necessary(["a"])
    def tool(label: str, first: dict[str, Any], second: dict[str, Any]) -> tuple[Any, ...]:
        return label, first, second

    label, first, second = tool("x", {"a": 1, "b": 2}, {"a": 3, "b": 4})
    assert label == "x"
    assert first == {"a": 1}
    assert second == {"a": 3, "b": 4}


def test_keyword_dict_is_filtered_when_no_positional_dict() -> None:
    @minimum_necessary(["patient.mrn"])
    def tool(*, flag: bool, record: dict[str, Any], other: dict[str, Any]) -> tuple[Any, ...]:
        return flag, record, other

    flag, record, other = tool(flag=True, record=RECORD, other={"z": 1})
    assert flag is True
    assert record == {"patient": {"mrn": "MRN-1"}}
    assert other == {"z": 1}


def test_no_dict_arguments_pass_through_unchanged() -> None:
    @minimum_necessary(["a"])
    def tool(x: int, *, y: str) -> tuple[int, str]:
        return x, y

    assert tool(1, y="two") == (1, "two")


def test_original_input_is_not_mutated() -> None:
    @minimum_necessary(["patient.mrn"])
    def tool(record: dict[str, Any]) -> dict[str, Any]:
        return record

    tool(RECORD)
    assert RECORD["patient"]["ssn"] == "123-45-6789"
