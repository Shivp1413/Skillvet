"""Regression guard on the bundled examples and on skillvet's own skill.

These tests encode the promise the README makes about the examples: a good
skill passes, a sloppy one is flagged for review, and a hostile one is blocked.
If a rule change ever breaks that, this file fails first.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from skillvet import scanner  # noqa: E402
from skillvet.models import Severity  # noqa: E402

EXAMPLES = ROOT / "examples"
EXAMPLE_CASES = {
    "pdf-invoice-extractor": ("PASS", {"critical": 0, "high": 0}),
    # review-level quality problems only: no security findings at all
    "meeting-notes-helper": ("REVIEW", {"critical": 0}),
    "risky-web-scraper": ("BLOCK", None),
}

HOSTILE_RULES = {"PI-001", "PI-002", "PI-004", "PI-005", "PI-006", "PI-007", "PI-009", "PI-010", "PI-012", "PI-014"}


def scan_path(relative: str):
    result = scanner.scan_skill(str(ROOT / relative))
    return result


@pytest.mark.parametrize("name", sorted(EXAMPLE_CASES))
def test_example_exists(name):
    assert (EXAMPLES / name / "SKILL.md").is_file()


@pytest.mark.parametrize("name,expected", sorted(EXAMPLE_CASES.items()))
def test_example_verdict(name, expected):
    verdict, severity_ceiling = expected
    result = scan_path(f"examples/{name}")
    assert result.verdict == verdict, [
        (f.rule_id, str(f.severity), f.message) for f in result.findings
    ]
    if severity_ceiling:
        for sev, limit in severity_ceiling.items():
            assert result.count(Severity(sev)) == limit


def test_good_example_scores_full_marks():
    result = scan_path("examples/pdf-invoice-extractor")
    assert result.score == 100
    assert result.grade == "A+"


def test_hostile_example_triggers_the_expected_rules():
    result = scan_path("examples/risky-web-scraper")
    found = {f.rule_id for f in result.findings}
    missing = HOSTILE_RULES - found
    assert not missing, f"the hostile fixture no longer trips: {sorted(missing)}"
    assert result.score <= 10


def test_hostile_example_hidden_characters_are_critical():
    result = scan_path("examples/risky-web-scraper")
    hidden = [f for f in result.findings if f.rule_id == "PI-002"]
    assert hidden and hidden[0].severity.value == "critical"


def test_sloppy_example_has_no_security_findings():
    result = scan_path("examples/meeting-notes-helper")
    security = [f for f in result.findings if str(f.category) == "security"]
    assert security == [], security


def test_skillvets_own_skill_passes():
    """skillvet ships a skill describing itself; it must satisfy its own rules."""
    result = scan_path("skills/skillvet")
    assert result.verdict == "PASS", [
        (f.rule_id, str(f.severity), f.message) for f in result.findings
    ]


def test_repository_root_scans_without_findings_above_medium():
    """The whole repo, scanned as a maintainer would, stays clean."""
    results = scanner.scan_paths([str(ROOT / "skills")])
    assert results
    worst = max(
        (f.severity.rank for r in results for f in r.findings),
        default=0,
    )
    assert worst < Severity.HIGH.rank
