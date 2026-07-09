"""B2 + B6: reversible tokenization and streaming redaction."""

from __future__ import annotations

import re

import pytest

from clinicsentry.phi.firewall import PHIFirewall

# --- B2: tokenize / detokenize -------------------------------------------------


def test_tokenize_roundtrip_through_llm_answer() -> None:
    fw = PHIFirewall(session_salt="s1")
    tok = fw.tokenize({"note": "MRN 12345678"})
    token = next(iter(tok.mapping))
    assert token.startswith("<MRN_")
    answer = f"Patient with {token} is scheduled."
    assert tok.detokenize(answer) == "Patient with MRN 12345678 is scheduled."


def test_tokens_deterministic_within_session() -> None:
    fw = PHIFirewall(session_salt="s1")
    t1 = fw.tokenize("SSN 123-45-6789")
    t2 = fw.tokenize("again SSN 123-45-6789")
    assert set(t1.mapping) == set(t2.mapping)


def test_tokens_differ_across_sessions() -> None:
    a = PHIFirewall(session_salt="a").tokenize("SSN 123-45-6789")
    b = PHIFirewall(session_salt="b").tokenize("SSN 123-45-6789")
    assert set(a.mapping) != set(b.mapping)


def test_format_preserving_keeps_shape() -> None:
    fw = PHIFirewall(session_salt="s1")
    tok = fw.tokenize("SSN 123-45-6789", format_preserving=True)
    assert "123-45-6789" not in tok.text
    assert re.search(r"\b\d{3}-\d{2}-\d{4}\b", tok.text)
    assert tok.detokenize(tok.text) == "SSN 123-45-6789"


def test_tokenize_multiple_types() -> None:
    fw = PHIFirewall(session_salt="s1")
    tok = fw.tokenize("SSN 123-45-6789 email jane@example.com")
    assert len(tok.mapping) == 2
    restored = tok.detokenize(tok.text)
    assert "123-45-6789" in restored
    assert "jane@example.com" in restored


# --- B6: streaming redaction ----------------------------------------------------


def _collect(chunks: list[str], holdback: int = 32) -> str:
    fw = PHIFirewall()
    r = fw.stream_redactor(holdback=holdback)
    parts = [r.push(c) for c in chunks]
    parts.append(r.flush())
    return "".join(parts)


def test_stream_redacts_ssn_split_across_chunks() -> None:
    out = _collect(["The patient SSN is 123-", "45-", "6789 and stable. " + "x" * 64])
    assert "123-45-6789" not in out
    assert "[REDACTED:SSN]" in out


def test_stream_clean_text_passes_through_byte_identical() -> None:
    text = "word " * 40
    out = _collect([text[i : i + 7] for i in range(0, len(text), 7)])
    assert out == text


def test_stream_emits_incrementally_not_only_at_flush() -> None:
    fw = PHIFirewall()
    r = fw.stream_redactor(holdback=16)
    emitted = r.push("a" * 100)
    assert emitted  # safe prefix released before flush
    assert r.flush()


def test_stream_flush_finalizes_and_blocks_reuse() -> None:
    fw = PHIFirewall()
    r = fw.stream_redactor()
    r.push("hello ")
    r.flush()
    with pytest.raises(RuntimeError, match="flushed"):
        r.push("more")


def test_stream_registers_tags_for_audit() -> None:
    fw = PHIFirewall()
    r = fw.stream_redactor(origin_agent="llm-stream")
    r.push("SSN 123-45-6789 " + "pad " * 40)
    r.flush()
    assert any(t.phi_type == "SSN" for t in fw.propagation.tags.values())


def test_stream_holdback_lower_bound() -> None:
    fw = PHIFirewall()
    with pytest.raises(ValueError, match="holdback"):
        fw.stream_redactor(holdback=4)
