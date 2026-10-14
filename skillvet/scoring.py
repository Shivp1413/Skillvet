"""Scoring and verdict logic.

Two independent signals, because they answer different questions:

* ``verdict`` -- is it *safe and loadable*? Driven by security findings and by
  spec problems that stop the skill loading at all. A CI gate uses this.
* ``score``   -- how *healthy* is it overall, quality included? A number that
  goes up as the author fixes things, which is what makes it worth shipping a
  badge for.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from .models import Category, Finding, Severity

REPEAT_FACTOR = 0.25
RULE_CAP_MULTIPLIER = 2.0
LOAD_BLOCKING_SPEC_RULES = {"SPEC-001", "SPEC-002", "SPEC-003"}

GRADES: List[Tuple[int, str]] = [
    (97, "A+"),
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (55, "D"),
    (0, "F"),
]


def score_findings(findings: List[Finding]) -> int:
    """Start at 100 and subtract, with diminishing returns per rule."""
    per_rule: Dict[str, List[Finding]] = {}
    for f in findings:
        per_rule.setdefault(f.rule_id, []).append(f)

    penalty = 0.0
    for rule_findings in per_rule.values():
        base = max(f.severity.penalty for f in rule_findings)
        if base == 0:
            continue
        total = base
        for _ in range(len(rule_findings) - 1):
            total += base * REPEAT_FACTOR
        penalty += min(total, base * RULE_CAP_MULTIPLIER)

    return max(0, min(100, round(100 - penalty)))


def grade_for(score: int) -> str:
    for threshold, letter in GRADES:
        if score >= threshold:
            return letter
    return "F"  # pragma: no cover - GRADES ends at 0


def verdict_for(findings: List[Finding], score: int) -> str:
    if any(f.severity is Severity.CRITICAL for f in findings):
        return "BLOCK"
    if any(
        f.rule_id in LOAD_BLOCKING_SPEC_RULES and f.severity.rank >= Severity.HIGH.rank
        for f in findings
    ):
        return "BLOCK"
    if any(
        f.category is Category.SECURITY and f.severity is Severity.HIGH for f in findings
    ):
        return "BLOCK"
    high = sum(1 for f in findings if f.severity is Severity.HIGH)
    medium = sum(1 for f in findings if f.severity is Severity.MEDIUM)
    if high or medium >= 3 or score < 80:
        return "REVIEW"
    return "PASS"


def summarize(findings: List[Finding]) -> Tuple[int, str, str]:
    score = score_findings(findings)
    return score, grade_for(score), verdict_for(findings, score)


def gate_failed(
    findings: List[Finding],
    score: int,
    fail_on: Severity = Severity.HIGH,
    min_score: int = 0,
) -> Tuple[bool, str]:
    """Return (failed, reason) for CI use."""
    threshold = fail_on.rank
    worst = [f for f in findings if f.severity.rank >= threshold and f.severity.rank > 0]
    if worst:
        top = max(worst, key=lambda f: f.severity.rank)
        return True, (
            f"{len(worst)} finding(s) at or above '{fail_on}' "
            f"(worst: {top.rule_id} {top.severity} in {top.file})"
        )
    if min_score and score < min_score:
        return True, f"score {score} is below the required minimum of {min_score}"
    return False, ""
