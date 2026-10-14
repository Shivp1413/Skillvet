"""Orchestration: turn a directory into a ScanResult."""

from __future__ import annotations

import json
import os
import time
from typing import Iterable, List, Optional, Set

from . import discovery, quality, scoring, spec
from .models import Capability, Finding, ScanResult, Skill
from .security import SecurityScanner, scan_ignore_file, scan_suppressions

BASELINE_VERSION = 1


def _normalise_snippet(snippet: Optional[str]) -> str:
    return " ".join((snippet or "").split())[:80]


def baseline_key(finding: Finding) -> str:
    return f"{finding.rule_id}|{finding.file}|{_normalise_snippet(finding.snippet)}"


def load_baseline(path: str) -> Set[str]:
    if not path or not os.path.isfile(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return set()
    return {entry.get("key", "") for entry in data.get("entries", []) if entry.get("key")}


def write_baseline(path: str, results: Iterable[ScanResult]) -> int:
    entries = []
    for result in results:
        for f in result.findings:
            entries.append(
                {
                    "key": baseline_key(f),
                    "rule": f.rule_id,
                    "severity": str(f.severity),
                    "file": f.file,
                }
            )
    payload = {
        "version": BASELINE_VERSION,
        "generated_by": "skillvet",
        "entries": sorted(entries, key=lambda e: (e["rule"], e["file"], e["key"])),
    }
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    return len(entries)


def _loadable(skill: Skill) -> bool:
    return skill.parse_error is None and bool(skill.frontmatter)


def scan_skill(
    root: str,
    ignore: Optional[Iterable[str]] = None,
    baseline: Optional[Set[str]] = None,
) -> ScanResult:
    started = time.perf_counter()
    skill, _notes = discovery.load_skill(root)

    # Ignore sources, in order of scope:
    #   1. --ignore on the command line (this run only)
    #   2. .skillvetignore in the skill root (committed, visible in review)
    #   3. 'skillvet: ignore' comments inside a file (line or file scoped)
    cli_ignore = {i.strip().upper() for i in (ignore or []) if i and i.strip()}
    repo_ignore = scan_ignore_file(skill.root)
    scanner = SecurityScanner(ignore=sorted(cli_ignore | repo_ignore))

    findings: List[Finding] = []
    capabilities: List[Capability] = []
    scanned = 0

    if skill.parse_error != "missing SKILL.md":
        md_text = discovery.read_text_file(skill.skill_md)
        if md_text is None:
            try:
                with open(skill.skill_md, "r", encoding="utf-8", errors="replace") as fh:
                    md_text = fh.read()
            except OSError:
                md_text = skill.body
        file_wide, per_line = scan_suppressions(md_text)
        rel = os.path.basename(skill.skill_md)
        findings.extend(scanner.scan_text(md_text, rel, file_wide, per_line))
        # Capabilities are collected from the body only: 'allowed-tools: Bash' in
        # the frontmatter is a declaration, not an action the skill performs.
        capabilities.extend(
            scanner.capabilities(
                skill.body, rel, line_offset=max(0, skill.body_start_line - 1)
            )
        )
        scanned += 1

        for f in skill.files:
            if f.is_binary or f.size == 0 or f.size > discovery.MAX_SCAN_BYTES:
                continue
            if f.path.lower().endswith((".md", ".markdown")):
                continue  # reference material is prose, not an execution surface
            text = discovery.read_text_file(f.abspath)
            if text is None:
                continue
            fw, pl = scan_suppressions(text)
            findings.extend(
                scanner.scan_text(text, f.path, fw, pl, treat_all_as_code=True)
            )
            capabilities.extend(scanner.capabilities(text, f.path))
            scanned += 1

    findings.extend(spec.check_spec(skill))
    if _loadable(skill):
        findings.extend(quality.check_quality(skill))

    # Command-line ignores also apply to static checks.
    if cli_ignore or repo_ignore:
        blocked = cli_ignore | repo_ignore
        findings = [f for f in findings if f.rule_id not in blocked]

    if baseline:
        findings = [f for f in findings if baseline_key(f) not in baseline]

    findings.sort(key=lambda f: (-f.severity.rank, f.file, f.line or 0, f.rule_id))
    score = scoring.score_findings(findings)
    return ScanResult(
        skill=skill,
        findings=findings,
        capabilities=_dedupe_capabilities(capabilities),
        score=score,
        grade=scoring.grade_for(score),
        verdict=scoring.verdict_for(findings, score),
        scanned_files=scanned,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


def _dedupe_capabilities(caps: List[Capability]) -> List[Capability]:
    seen = set()
    out = []
    for c in caps:
        key = (c.kind, c.detail.lower(), c.file)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    order = {
        "read_secret": 0, "network": 1, "exec": 2, "install": 3,
        "privilege": 4, "persist": 5, "destructive": 6, "write": 7,
    }
    return sorted(out, key=lambda c: (order.get(c.kind, 9), c.file, c.line or 0))


def scan_paths(
    paths: Iterable[str],
    ignore: Optional[Iterable[str]] = None,
    excludes: Optional[Iterable[str]] = None,
    baseline: Optional[Set[str]] = None,
) -> List[ScanResult]:
    roots = discovery.find_skill_roots(paths, excludes=excludes)
    return [scan_skill(r, ignore=ignore, baseline=baseline) for r in roots]


def scan_installed(ignore: Optional[Iterable[str]] = None) -> List[ScanResult]:
    results: List[ScanResult] = []
    for root in discovery.installed_roots():
        results.extend(scan_paths([root], ignore=ignore))
    return results
