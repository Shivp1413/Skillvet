"""Quality checks.

Spec compliance tells you whether a skill will load. Quality tells you whether
it will work. These checks encode the difference between a SKILL.md that fires
reliably and one that reads well but never activates.
"""

from __future__ import annotations

import os
import re
from typing import List

from .models import Category, Finding, Severity, Skill
from .rules import get as get_rule
from .spec import collect_reference_files

TRIGGER_PATTERNS = re.compile(
    r"\b(?:use\s+(?:this\s+)?(?:skill\s+)?when|use\s+it\s+when|use\s+for|"
    r"when\s+the\s+user|when\s+you\s+need|when\s+asked|when\s+working\s+on|"
    r"when\s+a\s+task|when\s+the\s+task|triggers?|invoke\s+when|"
    r"appropriate\s+when|use\s+whenever|whenever\s+the\s+user|"
    r"when\s+someone|use\s+this\s+to|when\s+reviewing|when\s+building|"
    r"when\s+writing|when\s+debugging|when\s+migrating|when\s+deploying)\b",
    re.IGNORECASE,
)

PROMO = re.compile(
    r"\b(?:supercharg\w*|revolutionar\w*|cutting[\s-]edge|world[\s-]class|"
    r"game[\s-]chang\w*|blazing|effortless\w*|seamless\w*|powerful|amazing|"
    r"ultimate|next[\s-]gen\w*|state[\s-]of[\s-]the[\s-]art|10x|unleash\w*|"
    r"elevate|turbocharg\w*|magic\w*|just\s+works)\b",
    re.IGNORECASE,
)

FIRST_PERSON = re.compile(r"\b(?:I|I'm|I'll|I\s+can|my|we|we'll|our)\b\s+\w+")

VAGUE = re.compile(
    r"\b(?:things?|stuff|various|some|several|etc\.?|and\s+more|"
    r"helps?\s+(?:you\s+)?with|assists?\s+with|deals?\s+with|"
    r"related\s+to|anything|whatever)\b",
    re.IGNORECASE,
)

HEDGE = re.compile(
    r"\b(?:try\s+to|maybe|perhaps|if\s+possible|possibly|consider|"
    r"might\s+want\s+to|optionally|where\s+appropriate|if\s+you\s+like)\b",
    re.IGNORECASE,
)

BOUNDARY = re.compile(
    r"\b(?:do\s+not\s+use|don'?t\s+use|when\s+not\s+to\s+use|out\s+of\s+scope|"
    r"not\s+appropriate|limitations?|does\s+not\s+(?:handle|cover|support)|"
    r"edge\s+cases?|failure\s+mode|if\s+.{0,40}\s+fails?\b|stop\s+and\s+(?:report|ask)|"
    r"refuse|guardrail|precondition|preconditions?)\b",
    re.IGNORECASE,
)

OUTPUT_CONTRACT = re.compile(
    r"\b(?:output\s+(?:format|shape|contract)|expected\s+output|result\s+should|"
    r"returns?\s+a|produces?\s+a|must\s+output|report\s+format|"
    r"the\s+file\s+(?:must|should)\s+contain|done\s+when|success\s+criteria|"
    r"definition\s+of\s+done)\b",
    re.IGNORECASE,
)

HEADING = re.compile(r"^\s{0,3}#{1,6}\s+\S", re.MULTILINE)
CODE_FENCE = re.compile(r"^\s*(?:```|~~~)", re.MULTILINE)
EXAMPLE_CUE = re.compile(
    r"\b(?:example|examples|e\.g\.|for\s+instance|sample\s+(?:input|output))\b",
    re.IGNORECASE,
)

MIN_BODY_LINES = 12
MIN_DESCRIPTION = 40
HEDGE_THRESHOLD = 4


def _f(rule_id: str, message: str, file: str, line=None, snippet=None,
       severity: Severity = None) -> Finding:
    rule = get_rule(rule_id)
    assert rule is not None
    return Finding(
        rule_id=rule_id,
        severity=severity or rule.severity,
        category=Category.QUALITY,
        title=rule.title,
        message=message,
        file=file,
        line=line,
        snippet=snippet,
        remediation=rule.fix,
    )


def _description_line(skill: Skill) -> int:
    if not skill.frontmatter_raw:
        return 2
    for idx, line in enumerate(skill.frontmatter_raw.splitlines(), start=2):
        if line.strip().startswith("description:"):
            return idx
    return 2


def check_quality(skill: Skill) -> List[Finding]:
    findings: List[Finding] = []
    rel_md = os.path.basename(skill.skill_md)
    body = skill.body or ""
    desc = skill.description or ""

    if not desc:
        return findings  # SPEC-005 already covers this.

    dline = _description_line(skill)

    # ---- routing: does the description say WHEN? --------------------------
    if not TRIGGER_PATTERNS.search(desc):
        findings.append(
            _f(
                "Q-001",
                "The description explains the subject but never states when the skill "
                "should activate, which is the only thing the agent routes on.",
                rel_md,
                dline,
                desc[:120] + ("..." if len(desc) > 120 else ""),
            )
        )

    # ---- vagueness / voice ------------------------------------------------
    reasons = []
    if len(desc) < MIN_DESCRIPTION:
        reasons.append(f"it is only {len(desc)} characters long")
    if PROMO.search(desc):
        reasons.append(
            "it uses promotional language ('"
            + PROMO.search(desc).group(0)  # type: ignore[union-attr]
            + "')"
        )
    if VAGUE.search(desc):
        reasons.append(
            "it relies on vague nouns ('"
            + VAGUE.search(desc).group(0)  # type: ignore[union-attr]
            + "')"
        )
    if FIRST_PERSON.search(desc):
        reasons.append("it is written in the first person")
    if reasons:
        findings.append(
            _f(
                "Q-002",
                "The description is hard to route on because " + "; ".join(reasons) + ".",
                rel_md,
                dline,
                desc[:120] + ("..." if len(desc) > 120 else ""),
            )
        )

    # ---- examples ---------------------------------------------------------
    if not EXAMPLE_CUE.search(body) and not CODE_FENCE.search(body):
        findings.append(
            _f(
                "Q-003",
                "The body contains no example, so the agent has to guess the expected "
                "output shape.",
                rel_md,
            )
        )

    # ---- progressive disclosure ------------------------------------------
    has_reference_files = bool(collect_reference_files(skill))
    if skill.body_tokens > 1500 and not has_reference_files:
        findings.append(
            _f(
                "Q-004",
                f"SKILL.md carries ~{skill.body_tokens:,} tokens with no reference files "
                "beside it, so all of that detail is loaded even when only a small part "
                "is relevant.",
                rel_md,
            )
        )

    # ---- boundaries -------------------------------------------------------
    if not BOUNDARY.search(body):
        findings.append(
            _f(
                "Q-005",
                "The skill never says when it should not be used, or what to do when a "
                "step fails. Agents that hit an unexpected input will improvise.",
                rel_md,
            )
        )

    # ---- hedging ----------------------------------------------------------
    hedges = HEDGE.findall(body)
    if len(hedges) >= HEDGE_THRESHOLD:
        findings.append(
            _f(
                "Q-006",
                f"{len(hedges)} hedged instructions found ("
                + ", ".join(sorted({h.lower() for h in hedges})[:5])
                + "). Hedged steps are treated as optional, so behaviour varies run to run.",
                rel_md,
                severity=Severity.LOW,
            )
        )

    # ---- unreferenced scripts --------------------------------------------
    body_lower = body.lower()
    scripts = [
        f for f in skill.files
        if f.is_script and os.path.basename(f.path).lower() != "skill.md"
    ]
    unreferenced = [
        f for f in scripts
        if os.path.basename(f.path).lower() not in body_lower and f.path.lower() not in body_lower
    ]
    for f in unreferenced[:6]:
        findings.append(
            _f(
                "Q-007",
                f"'{f.path}' ships with the skill but is never mentioned in SKILL.md, so "
                "nobody has reviewed what it does.",
                f.path,
            )
        )

    # ---- output contract --------------------------------------------------
    if not OUTPUT_CONTRACT.search(body):
        findings.append(
            _f(
                "Q-008",
                "Nothing states what a correct result looks like, so two runs of the same "
                "skill can produce two different shapes.",
                rel_md,
            )
        )

    # ---- thinness / structure --------------------------------------------
    if body.strip() and skill.body_lines < MIN_BODY_LINES:
        findings.append(
            _f(
                "Q-009",
                f"The body is only {skill.body_lines} lines, which restates what the model "
                "already does without adding a procedure.",
                rel_md,
            )
        )
    if body.strip() and not HEADING.search(body):
        findings.append(
            _f(
                "Q-010",
                "The body has no headings, so neither a reviewer nor the agent can jump to "
                "the section that matters.",
                rel_md,
            )
        )

    return findings
