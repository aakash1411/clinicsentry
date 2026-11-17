"""PHI benchmark harness and local-LLM detector tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from clinicsentry.benchmarks import (
    BenchmarkDocument,
    GoldSpan,
    bundled_synthetic_dataset,
    evaluate_phi,
    load_brat,
    load_dataset,
    load_jsonl,
    normalize_label,
)
from clinicsentry.cli import main
from clinicsentry.phi import LocalLLMDetector
from clinicsentry.phi.firewall import PHIFirewall

TEXT = "Jane Doe called 555-123-4567 on 2024-01-02."
DOC = BenchmarkDocument(
    "d1",
    TEXT,
    [GoldSpan(0, 8, "PATIENT"), GoldSpan(16, 28, "PHONE"), GoldSpan(32, 42, "DATE")],
)


def test_normalize_label_maps_corpus_and_detector_labels() -> None:
    assert normalize_label("PATIENT") == "NAME"
    assert normalize_label("person") == "NAME"
    assert normalize_label("MEDICALRECORD") == "MRN"
    assert normalize_label("LOCATION-OTHER") == "GEOGRAPHIC"
    assert normalize_label("PROFESSION") is None
    assert normalize_label("PUMP_SERIAL") == "PUMP_SERIAL"
    assert normalize_label("PUMP_SERIAL", {"pump-serial": "device"}) == "DEVICE"


def test_perfect_detector_has_zero_leakage() -> None:
    def perfect(text: str) -> list[tuple[str, int, int]]:
        return [("NAME", 0, 8), ("PHONE", 16, 28), ("DATE", 32, 42)]

    r = evaluate_phi(perfect, [DOC])
    assert r.span_recall == 1.0
    assert r.leakage_rate == 0.0
    assert r.precision == 1.0
    assert r.strict_f1 == 1.0


def test_partial_coverage_counts_as_leak_but_wrong_type_does_not() -> None:
    def partial(text: str) -> list[tuple[str, int, int]]:
        # Name covered with the wrong type, phone only half covered, plus a false positive.
        return [("DATE", 0, 8), ("PHONE", 20, 28), ("SSN", 9, 15)]

    r = evaluate_phi(partial, [DOC])
    assert r.gold_spans == 3
    assert r.protected_spans == 1
    assert r.by_category["NAME"].protected == 1
    assert r.by_category["NAME"].strict_hits == 0
    assert r.by_category["PHONE"].protected == 0
    assert r.by_category["PHONE"].overlap_hits == 1
    assert r.by_category["DATE"].protected == 0
    assert r.precision == pytest.approx(2 / 3)
    assert 0 < r.char_recall < 1


def test_report_never_contains_text_or_values() -> None:
    r = evaluate_phi(PHIFirewall(), [DOC])
    blob = json.dumps(r.to_dict()) + r.to_markdown()
    for secret in ("Jane", "555-123-4567", "2024-01-02"):
        assert secret not in blob


def test_firewall_detector_and_callable_targets_agree() -> None:
    fw = evaluate_phi(PHIFirewall(), [DOC])
    assert fw.by_category["PHONE"].protected == 1
    assert fw.by_category["NAME"].protected == 0
    with pytest.raises(TypeError):
        evaluate_phi(object(), [DOC])


def test_jsonl_loader_and_validation(tmp_path: Path) -> None:
    path = tmp_path / "d.jsonl"
    path.write_text(
        json.dumps(
            {"id": "a", "text": TEXT, "annotations": [{"start": 0, "end": 8, "phi_type": "NAME"}]}
        )
        + "\n\n"
    )
    (doc,) = load_jsonl(path)
    assert doc.doc_id == "a"
    assert doc.spans == [GoldSpan(0, 8, "NAME")]
    path.write_text(json.dumps({"text": "abc", "spans": [{"start": 0, "end": 9, "label": "X"}]}))
    with pytest.raises(ValueError, match="out of range"):
        load_jsonl(path)


def test_brat_loader_handles_discontinuous_spans(tmp_path: Path) -> None:
    (tmp_path / "n1.txt").write_text(TEXT)
    (tmp_path / "n1.ann").write_text(
        "T1\tPATIENT 0 4;5 8\tJane Doe\nT2\tPHONE 16 28\t555-123-4567\n#1\tAnnotatorNotes T1\tx\n"
    )
    (tmp_path / "n2.txt").write_text("no annotations")
    docs = load_dataset(tmp_path)
    assert [d.doc_id for d in docs] == ["n1", "n2"]
    assert docs[0].spans == [
        GoldSpan(0, 4, "PATIENT"),
        GoldSpan(5, 8, "PATIENT"),
        GoldSpan(16, 28, "PHONE"),
    ]
    assert docs[1].spans == []
    assert load_brat(tmp_path)[0].text == TEXT
    with pytest.raises(ValueError):
        load_dataset(tmp_path, "csv")


def test_bundled_dataset_regression_floor() -> None:
    """Deterministic categories on the bundled synthetic notes must not regress."""
    docs = bundled_synthetic_dataset()
    assert len(docs) == 50
    r = evaluate_phi(PHIFirewall(), docs)
    for cat in ("SSN", "EMAIL", "DATE", "MRN", "PHONE"):
        assert r.by_category[cat].leakage_rate == 0.0, cat
    assert r.precision == 1.0


# --- CLI --------------------------------------------------------------------


def test_cli_phi_bench_json_and_gate(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["phi-bench", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["dataset"] == "bundled-synthetic"
    assert out["documents"] == 50
    assert main(["phi-bench", "--min-recall", "0.999"]) == 1
    capsys.readouterr()
    label_map = tmp_path / "map.yaml"
    label_map.write_text("NAME: null\n")
    assert main(["phi-bench", "--label-map", str(label_map), "--json"]) == 0
    assert "NAME" not in json.loads(capsys.readouterr().out)["by_category"]


def test_cli_phi_bench_with_dataset_and_policy(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    data = tmp_path / "d.jsonl"
    data.write_text(
        json.dumps({"text": TEXT, "spans": [{"start": 16, "end": 28, "label": "PHONE"}]})
    )
    policy = tmp_path / "p.yaml"
    policy.write_text("phi_firewall:\n  mode: REDACT\n")
    assert main(["phi-bench", "--dataset", str(data), "--policy", str(policy), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["detector"] == "policy:p.yaml"
    assert out["span_recall"] == 1.0


# --- Local LLM detector -----------------------------------------------------


def _fake(content: Any, calls: list[dict[str, Any]] | None = None) -> Any:
    def transport(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        if calls is not None:
            calls.append({"url": url, "payload": payload})
        body = content if isinstance(content, str) else json.dumps(content)
        return {"choices": [{"message": {"content": body}}]}

    return transport


def test_llm_detector_maps_strings_to_offsets() -> None:
    calls: list[dict[str, Any]] = []
    det = LocalLLMDetector(
        transport=_fake(
            {"phi": [{"type": "name", "text": "Jane Doe"}, {"type": "x", "text": "absent"}]}, calls
        ),
        model="m",
    )
    hits = det.detect("Jane Doe saw Jane Doe.")
    assert [(h.phi_type, h.start, h.end, h.source) for h in hits] == [
        ("NAME", 0, 8, "local_llm"),
        ("NAME", 13, 21, "local_llm"),
    ]
    assert calls[0]["url"] == "http://127.0.0.1:11434/v1/chat/completions"
    assert calls[0]["payload"]["model"] == "m"
    assert calls[0]["payload"]["temperature"] == 0


def test_llm_detector_accepts_fenced_json() -> None:
    det = LocalLLMDetector(
        transport=_fake('```json\n{"phi": [{"type": "CITY", "text": "Boston"}]}\n```')
    )
    assert [h.phi_type for h in det.detect("Lives in Boston.")] == ["CITY"]


@pytest.mark.parametrize("content", ["not json", {"nope": 1}, {"phi": "x"}])
def test_llm_detector_fails_open_with_error_hook(content: Any) -> None:
    errors: list[Exception] = []
    det = LocalLLMDetector(transport=_fake(content), on_error=errors.append)
    assert det.detect("Jane Doe") == []
    assert len(errors) == 1
    assert "Jane" not in str(errors[0])


def test_llm_detector_chunks_long_text_with_correct_offsets() -> None:
    calls: list[dict[str, Any]] = []
    det = LocalLLMDetector(
        transport=_fake({"phi": [{"type": "NAME", "text": "Zed Q"}]}, calls), max_chunk_chars=200
    )
    text = ("word " * 60) + "Zed Q end"
    hits = det.detect(text)
    assert len(calls) == 2
    assert [text[h.start : h.end] for h in hits] == ["Zed Q"]


def test_llm_detector_refuses_remote_endpoints() -> None:
    with pytest.raises(ValueError, match="loopback"):
        LocalLLMDetector(base_url="https://llm.example.com/v1")
    with pytest.raises(ValueError):
        LocalLLMDetector(base_url="file:///etc/passwd")
    assert LocalLLMDetector(base_url="https://llm.example.com/v1", allow_remote=True)
    assert LocalLLMDetector(base_url="http://[::1]:8000/v1")


def test_llm_backend_is_wired_into_firewall(monkeypatch: pytest.MonkeyPatch) -> None:
    from clinicsentry.phi import llm

    monkeypatch.setattr(
        llm, "_http_transport", _fake({"phi": [{"type": "PERSON", "text": "Jane Doe"}]})
    )
    fw = PHIFirewall(detector_backend="local_llm")
    result = fw.scan(TEXT, origin_agent="t")
    assert "Jane Doe" not in str(result.redacted)
    r = evaluate_phi(fw, [DOC])
    assert r.by_category["NAME"].protected == 1


def test_llm_backend_unreachable_keeps_regex_layer() -> None:
    fw = PHIFirewall(detector_backend="local_llm")
    fw._cloud._transport = _fake("garbage")
    result = fw.scan(TEXT, origin_agent="t")
    assert "555-123-4567" not in str(result.redacted)
