"""Compliance attestation rule engine (ADR-0007).

A rule's ``predicate`` field is a string drawn from a small whitelisted
vocabulary. We parse the string with :func:`ast.parse` in expression mode,
then dispatch to a function in :data:`PREDICATE_REGISTRY`. No user-supplied
Python is ever executed — only registered predicates are callable.

Predicate grammar:

- Bare identifiers (e.g. ``chain_verifies``) → call the registered function
  with no arguments.
- ``every_event.has(<field>)`` → all events have a truthy value at ``<field>``.
- ``event_count >= N`` / ``event_count > N`` (and ``<=`` / ``<`` / ``==``) →
  compare event count against the integer literal ``N``.

Any other shape is rejected with ``satisfied=False, reason="unknown predicate"``.

Predicates whose precondition never occurred in the session (no PHI detected,
no interventional calls, ...) return ``applicable=False``: the rule does not
block, but the attestation records that it was not exercised rather than
claiming it passed on evidence.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from clinicsentry.audit.backend import AuditBackend, InMemoryAuditBackend
from clinicsentry.types import AuditEvent, AuditEventType, ClinicalRiskTier

__all__ = [
    "ComplianceRule",
    "RuleResult",
    "RuleSet",
    "evaluate_rules",
    "load_default_rulesets",
    "load_ruleset",
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ComplianceRule:
    """A single declarative attestation rule."""

    id: str
    title: str
    predicate: str
    severity: str = "info"  # blocker | warning | info
    references: list[str] = field(default_factory=list)
    framework: str = "generic"


@dataclass(frozen=True)
class RuleResult:
    """Outcome of evaluating one :class:`ComplianceRule` against a session."""

    rule_id: str
    satisfied: bool
    evidence: list[str] = field(default_factory=list)
    reason: str = ""
    applicable: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Serialize for inclusion in the regulatory report attestation."""
        return {
            "rule_id": self.rule_id,
            "satisfied": self.satisfied,
            "applicable": self.applicable,
            "evidence": list(self.evidence),
            "reason": self.reason,
        }


@dataclass
class RuleSet:
    """A named collection of rules loaded from one YAML file."""

    name: str
    version: str
    rules: list[ComplianceRule]


# ---------------------------------------------------------------------------
# Predicate implementations
# ---------------------------------------------------------------------------

# Each predicate accepts ``events`` plus an optional ``context`` dict carrying
# extra arguments (secret_key, backend, session_id) and returns
# ``(satisfied, evidence_event_ids, reason, applicable)``.

PredicateOutcome = tuple[bool, list[str], str, bool]
PredicateFn = Callable[[list[AuditEvent], dict[str, Any]], PredicateOutcome]


def _not_applicable(reason: str) -> PredicateOutcome:
    """Non-blocking outcome for a rule whose precondition never occurred."""
    return True, [], reason, False


def _has_field(events: list[AuditEvent], field_name: str) -> PredicateOutcome:
    """Check that every event has a truthy value at ``field_name``."""
    if not events:
        return _not_applicable("no events to check")
    missing: list[str] = []
    for ev in events:
        value = getattr(ev, field_name, None)
        if not value or value == "unknown":
            missing.append(ev.event_id)
    if missing:
        return False, missing, f"{len(missing)} event(s) missing {field_name}", True
    return True, [e.event_id for e in events], f"all events have {field_name}", True


def _predicate_chain_verifies(
    events: list[AuditEvent], context: dict[str, Any]
) -> PredicateOutcome:
    """Verify the audit chain hashes and HMAC signatures end-to-end."""
    secret_key = context.get("secret_key")
    if secret_key is None:
        return False, [], "secret_key not provided", True
    if not events:
        return _not_applicable("no events to verify")
    session_id = events[0].session_id
    # Build an in-memory backend pre-populated with the supplied events so
    # AuditChain.verify reads them in order.
    from clinicsentry.audit.chain import AuditChain

    backend: AuditBackend = context.get("backend") or InMemoryAuditBackend()
    if context.get("backend") is None:
        for ev in events:
            backend.append(ev)
    chain = AuditChain(session_id=session_id, secret_key=secret_key, backend=backend)
    ok, errors = chain.verify()
    return ok, [e.event_id for e in events], "; ".join(errors) if errors else "chain verified", True


def _predicate_signature_present(
    events: list[AuditEvent], _context: dict[str, Any]
) -> PredicateOutcome:
    """Check that every event carries a non-empty signature."""
    return _has_field(events, "signature")


def _predicate_no_gaps_in_sequence(
    events: list[AuditEvent], _context: dict[str, Any]
) -> PredicateOutcome:
    """Check that sequence numbers are a contiguous ascending run."""
    if not events:
        return _not_applicable("no events to check")
    seqs = [e.sequence_number for e in events]
    expected = list(range(seqs[0], seqs[0] + len(seqs)))
    if seqs != expected:
        return False, [e.event_id for e in events], f"sequence gap: {seqs}", True
    return True, [e.event_id for e in events], f"sequence intact ({len(seqs)} events)", True


def _predicate_phi_redacted_when_detected(
    events: list[AuditEvent], _context: dict[str, Any]
) -> PredicateOutcome:
    """Every PHI_DETECTED needs a following PHI_REDACTED covering all findings.

    Events carrying ``phi_tags_detected`` without any PHI_DETECTED event mean
    the firewall ran without audit instrumentation; that fails rather than
    passing vacuously.
    """
    detected = [e for e in events if e.event_type == AuditEventType.PHI_DETECTED]
    redacted = [e for e in events if e.event_type == AuditEventType.PHI_REDACTED]
    if not detected:
        tagged = [e.event_id for e in events if e.phi_tags_detected]
        if tagged:
            return (
                False,
                tagged,
                f"{len(tagged)} event(s) carry PHI tags but no PHI_DETECTED evidence was recorded",
                True,
            )
        return _not_applicable("no PHI detected")
    unmatched: list[AuditEvent] = []
    for det in detected:
        nxt = next((r for r in redacted if r.sequence_number > det.sequence_number), None)
        if nxt is None:
            unmatched.append(det)
            continue
        det_count = det.redacted_input.get("count")
        red_count = nxt.redacted_input.get("count")
        if isinstance(det_count, int) and isinstance(red_count, int) and red_count < det_count:
            unmatched.append(det)
    if unmatched:
        return (
            False,
            [e.event_id for e in unmatched],
            f"{len(unmatched)} PHI detection(s) without full redaction",
            True,
        )
    evidence = [e.event_id for e in detected + redacted]
    return True, evidence, "every PHI detection has matching redaction", True


def _predicate_escalation_for_interventional(
    events: list[AuditEvent], _context: dict[str, Any]
) -> PredicateOutcome:
    """Every interventional tool call must be paired with an escalation for it.

    Pairing is one-to-one by ``agent_id`` (the action name), so one escalation
    cannot cover several calls or a different action.
    """
    call_types = {AuditEventType.TOOL_CALL, AuditEventType.MCP_TOOL_CALL}
    calls = [
        e
        for e in events
        if e.event_type in call_types and e.risk_tier == ClinicalRiskTier.INTERVENTIONAL
    ]
    if not calls:
        return _not_applicable("no interventional tool calls")
    available = [e for e in events if e.event_type == AuditEventType.ESCALATION_TRIGGERED]
    matched: list[AuditEvent] = []
    unmatched: list[AuditEvent] = []
    for call in calls:
        esc = next((e for e in available if e.agent_id == call.agent_id), None)
        if esc is None:
            unmatched.append(call)
        else:
            available.remove(esc)
            matched.append(esc)
    if unmatched:
        return (
            False,
            [e.event_id for e in unmatched],
            f"{len(unmatched)} interventional call(s) without escalation",
            True,
        )
    return (
        True,
        [e.event_id for e in calls] + [e.event_id for e in matched],
        "interventional calls escalated",
        True,
    )


def _predicate_session_has_start_and_end(
    events: list[AuditEvent], _context: dict[str, Any]
) -> PredicateOutcome:
    """Check that the session contains SESSION_START and SESSION_END events."""
    start = next((e for e in events if e.event_type == AuditEventType.SESSION_START), None)
    end = next((e for e in events if e.event_type == AuditEventType.SESSION_END), None)
    if start and end:
        return True, [start.event_id, end.event_id], "session bounded", True
    missing = []
    if not start:
        missing.append("SESSION_START")
    if not end:
        missing.append("SESSION_END")
    return False, [], f"missing {', '.join(missing)}", True


def _predicate_iec62304_traceability_present(
    events: list[AuditEvent], context: dict[str, Any]
) -> PredicateOutcome:
    """Check that the iec62304 metadata section was supplied to the report."""
    if context.get("iec62304_present"):
        return True, [], "iec62304 metadata captured", True
    return False, [], "iec62304 metadata absent", True


def _predicate_human_review_for_advisory(
    events: list[AuditEvent], _context: dict[str, Any]
) -> PredicateOutcome:
    """Every ADVISORY escalation needs a later HUMAN_REVIEW_RESPONSE for that action."""
    advisory_escalations = [
        e
        for e in events
        if e.event_type == AuditEventType.ESCALATION_TRIGGERED
        and e.risk_tier == ClinicalRiskTier.ADVISORY
    ]
    if not advisory_escalations:
        return _not_applicable("no advisory escalations")
    reviews = [e for e in events if e.event_type == AuditEventType.HUMAN_REVIEW_RESPONSE]
    unmatched = [
        e.event_id
        for e in advisory_escalations
        if not any(
            r.sequence_number > e.sequence_number and r.agent_id == e.agent_id for r in reviews
        )
    ]
    if unmatched:
        return False, unmatched, f"{len(unmatched)} advisory escalation(s) without review", True
    return (
        True,
        [e.event_id for e in advisory_escalations] + [r.event_id for r in reviews],
        "all advisory escalations reviewed",
        True,
    )


PREDICATE_REGISTRY: dict[str, PredicateFn] = {
    "chain_verifies": _predicate_chain_verifies,
    "signature_present": _predicate_signature_present,
    "no_gaps_in_sequence": _predicate_no_gaps_in_sequence,
    "phi_redacted_when_detected": _predicate_phi_redacted_when_detected,
    "escalation_triggered_for_interventional": _predicate_escalation_for_interventional,
    "session_has_start_and_end": _predicate_session_has_start_and_end,
    "iec62304_traceability_present": _predicate_iec62304_traceability_present,
    "human_review_for_advisory": _predicate_human_review_for_advisory,
}


# ---------------------------------------------------------------------------
# Predicate parsing
# ---------------------------------------------------------------------------


_COMPARATORS: dict[type[ast.cmpop], Callable[[int, int], bool]] = {
    ast.Eq: lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
    ast.Lt: lambda a, b: a < b,
    ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b,
    ast.GtE: lambda a, b: a >= b,
}


def _evaluate_predicate(
    predicate: str, events: list[AuditEvent], context: dict[str, Any]
) -> PredicateOutcome:
    """Parse and dispatch a predicate string. Pure — no side effects, no eval."""
    try:
        tree = ast.parse(predicate.strip(), mode="eval")
    except SyntaxError:
        return False, [], f"predicate parse error: {predicate!r}", True

    node = tree.body

    # Bare name → call the registered function with no parameters.
    if isinstance(node, ast.Name):
        fn = PREDICATE_REGISTRY.get(node.id)
        if fn is None:
            return False, [], f"unknown predicate: {node.id!r}", True
        return fn(events, context)

    # ``every_event.has(<field>)``
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "every_event"
        and node.func.attr == "has"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
    ):
        return _has_field(events, node.args[0].id)

    # ``event_count <op> N``
    if (
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and node.left.id == "event_count"
        and len(node.ops) == 1
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Constant)
        and isinstance(node.comparators[0].value, int)
    ):
        op = type(node.ops[0])
        comparator = _COMPARATORS.get(op)
        if comparator is None:
            return False, [], f"unsupported comparator: {op.__name__}", True
        threshold = int(node.comparators[0].value)
        actual = len(events)
        ok = comparator(actual, threshold)
        reason = f"event_count={actual} vs threshold={threshold}"
        return ok, [e.event_id for e in events], reason, True

    return False, [], f"unsupported predicate shape: {predicate!r}", True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_rules(
    rules: Iterable[ComplianceRule],
    events: Iterable[AuditEvent],
    *,
    secret_key: bytes | None = None,
    backend: AuditBackend | None = None,
    iec62304_present: bool = False,
) -> list[RuleResult]:
    """Evaluate ``rules`` against ``events`` and return per-rule results.

    Args:
        rules: an iterable of :class:`ComplianceRule`.
        events: the session's audit events.
        secret_key: HMAC key required by ``chain_verifies``.
        backend: optional backend to use for ``chain_verifies`` (avoids
            mutating a fresh in-memory store).
        iec62304_present: True if the caller supplied an ``iec62304`` section
            to ``build_report``.

    Returns:
        One :class:`RuleResult` per input rule, in input order.
    """
    events_list = list(events)
    context: dict[str, Any] = {
        "secret_key": secret_key,
        "backend": backend,
        "iec62304_present": iec62304_present,
    }
    results: list[RuleResult] = []
    for rule in rules:
        satisfied, evidence, reason, applicable = _evaluate_predicate(
            rule.predicate, events_list, context
        )
        results.append(
            RuleResult(
                rule_id=rule.id,
                satisfied=satisfied,
                evidence=evidence,
                reason=reason,
                applicable=applicable,
            )
        )
    return results


def load_ruleset(path: str | Path) -> RuleSet:
    """Load a YAML rule file into a :class:`RuleSet`.

    The YAML schema is:

    ```yaml
    name: hipaa
    version: "1.0"
    rules:
      - id: HIPAA-164.312-a-1
        title: "Access control"
        predicate: "every_event.has(agent_id)"
        severity: blocker
        references: ["45 CFR §164.312(a)(1)"]
    ```
    """
    file_path = Path(path)
    with file_path.open() as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ValueError(f"ruleset {file_path} must be a mapping at top level")
    name = str(raw.get("name") or file_path.stem)
    version = str(raw.get("version", "0"))
    rule_dicts = raw.get("rules") or []
    if not isinstance(rule_dicts, list):
        raise ValueError(f"ruleset {file_path} 'rules' must be a list")
    rules: list[ComplianceRule] = []
    for r in rule_dicts:
        if not isinstance(r, dict) or "id" not in r or "predicate" not in r:
            raise ValueError(f"rule in {file_path} missing required keys: {r!r}")
        rules.append(
            ComplianceRule(
                id=str(r["id"]),
                title=str(r.get("title", "")),
                predicate=str(r["predicate"]),
                severity=str(r.get("severity", "info")),
                references=[str(x) for x in r.get("references", [])],
                framework=name,
            )
        )
    return RuleSet(name=name, version=version, rules=rules)


_DEFAULT_RULES_DIR = Path(__file__).parent / "rules"


def load_default_rulesets() -> list[RuleSet]:
    """Load every YAML file shipped under ``compliance/rules/``."""
    if not _DEFAULT_RULES_DIR.exists():
        return []
    return [load_ruleset(p) for p in sorted(_DEFAULT_RULES_DIR.glob("*.yaml"))]
