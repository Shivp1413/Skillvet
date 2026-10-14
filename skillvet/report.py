"""Output renderers: terminal, JSON, SARIF 2.1.0 and Markdown."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from . import __version__
from .models import Finding, ScanResult, Severity
from .rules import RULES

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
SEV_COLOR = {
    Severity.CRITICAL: "\033[97;41m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
VERDICT_COLOR = {"PASS": "\033[32m", "REVIEW": "\033[33m", "BLOCK": "\033[97;41m"}
VERDICT_MARK = {"PASS": "PASS", "REVIEW": "REVIEW", "BLOCK": "BLOCK"}
CAP_LABEL = {
    "read_secret": "reads secrets",
    "network": "network egress",
    "exec": "runs commands",
    "install": "installs packages",
    "privilege": "elevated privileges",
    "persist": "persistence",
    "destructive": "destructive ops",
    "write": "writes files",
}


class Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        return "".join(styles) + text + RESET


def _bar(score: int, width: int = 12) -> str:
    filled = round(score / 100 * width)
    return "\u2588" * filled + "\u2591" * (width - filled)


def render_terminal(
    results: List[ScanResult],
    color: bool = True,
    verbose: bool = False,
    show_capabilities: bool = True,
    quiet: bool = False,
) -> str:
    p = Painter(color)
    out: List[str] = []

    if not results:
        return p("No skill packages found.", BOLD)

    if not quiet:
        out.append("")
        out.append(
            p("skillvet", BOLD)
            + p(f" v{__version__}", DIM)
            + p("   agent skill supply-chain scanner", DIM)
        )

    for result in results:
        skill = result.skill
        name = skill.name or skill.dir_name
        rel_path = os.path.relpath(skill.root, os.getcwd())
        if rel_path.startswith(".."):
            rel_path = skill.root

        out.append("")
        if not quiet:
            out.append(p(f"  {name}", BOLD) + p(f"  \u00b7  {rel_path}", DIM))
            out.append(p("  " + "\u2500" * 66, DIM))

        verdict_style = VERDICT_COLOR.get(result.verdict, "")
        counts = []
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            n = result.count(sev)
            if n:
                counts.append(p(f"{n} {sev.value}", SEV_COLOR[sev]))
        detail = "  \u00b7  ".join(counts) if counts else p("no findings", DIM)

        out.append(
            "  "
            + p(f" {VERDICT_MARK[result.verdict]} ", verdict_style, BOLD)
            + "  "
            + p(f"score {result.score}/100", BOLD)
            + p(f" ({result.grade}) ", DIM)
            + p(_bar(result.score), VERDICT_COLOR.get(result.verdict, ""))
            + "  "
            + detail
        )
        out.append(
            p(
                "     "
                f"{skill.body_tokens:,} est. tokens  \u00b7  "
                f"{result.scanned_files} file(s) scanned  \u00b7  "
                f"{result.elapsed_ms} ms  \u00b7  "
                f"{len(skill.files)} file(s) in package",
                DIM,
            )
        )

        if skill.parse_error and skill.parse_error != "missing frontmatter":
            out.append(p(f"     parse: {skill.parse_error}", "\033[31m"))

        if result.findings:
            out.append("")
            current = None
            for f in result.findings:
                if f.severity != current:
                    current = f.severity
                    label = f.severity.value.upper()
                    out.append(
                        "  "
                        + p(f"{label}", SEV_COLOR[f.severity], BOLD)
                        + p(f"  ({result.count(current)} in this skill)", DIM)
                    )
                location = f.file + (f":{f.line}" if f.line else "")
                out.append(
                    "    "
                    + p(f"{f.rule_id:<8}", BOLD)
                    + p(f"  {f.title}", "")
                )
                out.append(p(f"      {location}", DIM))
                out.append(p(f"      {f.message}", ""))
                if f.snippet:
                    out.append(p(f"      \u2502 {f.snippet}", DIM))
                if verbose and f.remediation:
                    out.append(p(f"      \u2192 {f.remediation}", "\033[36m"))
        out.append("")

        if show_capabilities and result.capabilities:
            kinds: Dict[str, List[str]] = {}
            for c in result.capabilities:
                kinds.setdefault(c.kind, []).append(c.detail)
            pretty = ", ".join(
                f"{CAP_LABEL.get(k, k)} ({len(v)})" for k, v in sorted(kinds.items())
            )
            out.append(p("  capabilities: ", BOLD) + p(pretty, DIM))
            if verbose:
                for c in result.capabilities:
                    out.append(
                        p(
                            f"      {CAP_LABEL.get(c.kind, c.kind):<18} {c.detail}  "
                            f"({c.file}:{c.line})",
                            DIM,
                        )
                    )
            out.append("")

    if len(results) > 1:
        total = sum(r.score for r in results) / len(results)
        worst = min(results, key=lambda r: r.score)
        blocked = [r for r in results if r.verdict == "BLOCK"]
        out.append(p("  " + "\u2500" * 66, DIM))
        out.append(
            p("  Summary", BOLD)
            + p(
                f"   {len(results)} skill(s)  \u00b7  mean score {total:.0f}"
                f"  \u00b7  lowest {worst.score} ({worst.skill.name or worst.skill.dir_name})",
                DIM,
            )
        )
        if blocked:
            out.append(
                p(
                    f"  {len(blocked)} skill(s) blocked: "
                    + ", ".join(r.skill.name or r.skill.dir_name for r in blocked),
                    VERDICT_COLOR["BLOCK"],
                )
            )
        out.append("")
    return "\n".join(out)


def rule_id_free(finding: Finding) -> str:
    """Pad the rule id so titles line up."""
    return f"{finding.rule_id:<8}"


# ------------------------------------------------------------------------ json


def to_json(results: List[ScanResult], include_rules: bool = False) -> str:
    payload: Dict[str, Any] = {
        "tool": {"name": "skillvet", "version": __version__},
        "summary": {
            "skills": len(results),
            "verdicts": {
                v: sum(1 for r in results if r.verdict == v)
                for v in ("PASS", "REVIEW", "BLOCK")
            },
            "mean_score": round(sum(r.score for r in results) / len(results), 1)
            if results
            else None,
            "total_findings": sum(len(r.findings) for r in results),
        },
        "results": [r.to_dict() for r in results],
    }
    if include_rules:
        payload["rules"] = [r.to_dict() for r in RULES]
    return json.dumps(payload, indent=2)


# ----------------------------------------------------------------------- sarif

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_sarif(results: List[ScanResult], scan_root: str = ".") -> str:
    used = {f.rule_id for r in results for f in r.findings}
    rules = []
    for rule in RULES:
        if rule.id not in used:
            continue
        entry: Dict[str, Any] = {
            "id": rule.id,
            "name": rule.title.replace(" ", ""),
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.what},
            "help": {"text": f"{rule.why}\n\nFix: {rule.fix}", "markdown": f"**Why**\n\n{rule.why}\n\n**Fix**\n\n{rule.fix}"},
            "properties": {
                "category": str(rule.category),
                "severity": str(rule.severity),
                "tags": list(rule.tags),
            },
        }
        if rule.cwe:
            entry["properties"]["cwe"] = rule.cwe
            entry["relationships"] = [
                {
                    "target": {
                        "id": rule.cwe,
                        "toolComponent": {"name": "CWE", "guid": "5bab8b3f-3e0f-4d3c-b9d3-0b3c0f2c6a11"},
                    },
                    "kinds": ["superset"],
                }
            ]
        if rule.owasp:
            entry["properties"]["owasp"] = rule.owasp
        rules.append(entry)

    sarif_results = []
    for r in results:
        skill_name = r.skill.name or r.skill.dir_name
        for f in r.findings:
            if f.severity is Severity.INFO:
                continue
            path = os.path.join(os.path.relpath(r.skill.root, scan_root), f.file)
            result_entry: Dict[str, Any] = {
                "ruleId": f.rule_id,
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": f"[{skill_name}] {f.message}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": path.replace(os.sep, "/"),
                                "uriBaseId": "SRCROOT",
                            },
                            "region": {"startLine": max(1, f.line or 1)},
                        }
                    }
                ],
                "partialFingerprints": {
                    "skillvet/v1": f"{f.rule_id}:{path}:{f.line or 0}",
                },
                "properties": {
                    "skill": skill_name,
                    "severity": str(f.severity),
                    "remediation": f.remediation or "",
                },
            }
            if f.snippet:
                result_entry["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": f.snippet
                }
            sarif_results.append(result_entry)

    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skillvet",
                        "version": __version__,
                        "informationUri": "https://github.com/Shivp1413/skillvet",
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {"SRCROOT": {"uri": "file:///"}},
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {"skillsScanned": len(results)},
                    }
                ],
            }
        ],
    }
    return json.dumps(log, indent=2)


# ------------------------------------------------------------------- markdown


def to_markdown(results: List[ScanResult]) -> str:
    lines: List[str] = []
    lines.append("## skillvet report")
    lines.append("")
    if not results:
        lines.append("No skill packages found.")
        return "\n".join(lines)

    blocked = [r for r in results if r.verdict == "BLOCK"]
    icon = {"PASS": "\u2705", "REVIEW": "\u26a0\ufe0f", "BLOCK": "\u26d4"}
    lines.append(
        f"Scanned **{len(results)}** skill package(s). "
        f"Mean score **{sum(r.score for r in results) / len(results):.0f}/100**."
        + (f" **{len(blocked)} blocked.**" if blocked else "")
    )
    lines.append("")
    lines.append("| Skill | Verdict | Score | Grade | Crit | High | Med | Low |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in results:
        name = r.skill.name or r.skill.dir_name
        lines.append(
            f"| `{name}` | {icon.get(r.verdict, '')} {r.verdict} | {r.score} | "
            f"{r.grade} | {r.count(Severity.CRITICAL)} | {r.count(Severity.HIGH)} | "
            f"{r.count(Severity.MEDIUM)} | {r.count(Severity.LOW)} |"
        )
    lines.append("")

    for r in results:
        if not r.findings:
            continue
        name = r.skill.name or r.skill.dir_name
        lines.append(f"<details><summary><b>{name}</b> \u2014 {len(r.findings)} finding(s)</summary>")
        lines.append("")
        for f in r.findings:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"- **{f.severity.value.upper()} \u00b7 {f.rule_id} \u2014 {f.title}** (`{loc}`)")
            lines.append(f"  - {f.message}")
            if f.remediation:
                lines.append(f"  - _Fix:_ {f.remediation}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("<sub>Generated by [skillvet](https://github.com/Shivp1413/skillvet) "
                 "&mdash; Agent Skills supply-chain scanner.</sub>")
    return "\n".join(lines)


def to_badge_json(results: List[ScanResult]) -> Dict[str, Any]:
    """Shields.io endpoint payload for a dynamic score badge."""
    if not results:
        return {"schemaVersion": 1, "label": "skillvet", "message": "no skills", "color": "lightgrey"}
    worst = min(results, key=lambda r: r.score)
    color = {"PASS": "brightgreen", "REVIEW": "yellow", "BLOCK": "critical"}[worst.verdict]
    return {
        "schemaVersion": 1,
        "label": "skillvet",
        "message": f"{worst.score}/100 {worst.grade}",
        "color": color,
    }
