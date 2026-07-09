"""A5: policy JSON Schema, CLI command, and docs↔schema consistency."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from clinicsentry.cli import main as cli_main
from clinicsentry.policy import load_policy, policy_schema

REPO = Path(__file__).resolve().parent.parent


def test_schema_lists_every_accepted_top_level_key() -> None:
    from clinicsentry.policy import _TOP_LEVEL_KEYS

    schema = policy_schema()
    assert set(schema["properties"]) == _TOP_LEVEL_KEYS


def test_schema_phi_keys_match_loader() -> None:
    from clinicsentry.policy import _PHI_KEYS

    schema = policy_schema()
    assert set(schema["properties"]["phi_firewall"]["properties"]) == _PHI_KEYS


def test_policy_schema_cli(capsys) -> None:
    rc = cli_main(["policy-schema"])
    assert rc == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["title"] == "ClinicSentry policy"


def test_example_policy_yaml_loads() -> None:
    cfg = load_policy(REPO / "examples" / "policy.yaml", apply_env=False)
    assert cfg.meddevice.enabled


def _yaml_blocks(markdown: str) -> list[str]:
    return re.findall(r"```yaml\n(.*?)```", markdown, re.DOTALL)


def test_docs_policy_reference_loads_through_real_loader() -> None:
    """Every yaml block in docs/policy.md must be accepted by load_policy —
    the wishlist's A5 complaint was docs drifting from the schema."""
    doc = (REPO / "docs" / "policy.md").read_text(encoding="utf-8")
    blocks = _yaml_blocks(doc)
    assert blocks, "docs/policy.md must contain the policy example"
    for block in blocks:
        parsed = yaml.safe_load(block)
        if not isinstance(parsed, dict):
            continue  # fragment (e.g. env-var examples)
        load_policy(parsed, apply_env=False)


def test_schema_validates_example_policy_if_jsonschema_installed() -> None:
    try:
        import jsonschema
    except ImportError:
        return
    data = yaml.safe_load((REPO / "examples" / "policy.yaml").read_text())
    jsonschema.validate(data, policy_schema())
