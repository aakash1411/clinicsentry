"""Compliance attestation rule engine (ADR-0007).

This module turns the hard-coded boolean attestations in
:func:`clinicsentry.audit.report.build_report` into a declarative,
YAML-driven rule engine. Each rule has a stable id, a whitelisted predicate
expression, a severity, and regulatory citation references.

Public API:

- :class:`ComplianceRule` — rule schema.
- :class:`RuleResult` — evaluation outcome with evidence.
- :class:`RuleSet` — collection of rules loaded from a YAML file.
- :func:`load_ruleset` — load a YAML file into a :class:`RuleSet`.
- :func:`load_default_rulesets` — load all bundled framework rule files.
- :func:`evaluate_rules` — evaluate a list of rules against a session's events.
"""

from clinicsentry.compliance.engine import (
    ComplianceRule,
    RuleResult,
    RuleSet,
    evaluate_rules,
    load_default_rulesets,
    load_ruleset,
)

__all__ = [
    "ComplianceRule",
    "RuleResult",
    "RuleSet",
    "evaluate_rules",
    "load_default_rulesets",
    "load_ruleset",
]
