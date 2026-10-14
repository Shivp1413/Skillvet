"""Agent Skills specification compliance checks."""

from __future__ import annotations

import difflib
import os
import re
from typing import List, Set

from .models import Category, Finding, Severity, Skill
from .rules import get as get_rule

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_NAME = 64
MAX_DESCRIPTION = 1024
BODY_TOKEN_BUDGET = 2500

KNOWN_KEYS = {
    "name", "description", "license", "allowed-tools", "metadata", "version",
    "author", "authors", "homepage", "repository", "tags", "keywords",
    "category", "categories", "model", "icon", "compatibility", "requires",
    "dependencies", "when-to-use", "disable-model-invocation", "user-invocable",
    "argument-hint", "allowed_tools", "tools", "title", "display-name",
}

# A missing path is only a broken reference when it points into a directory a
# skill package conventionally ships. Anything else is usually an output the
# skill produces ("writes reports/summary.csv") rather than a bundled file.
ASSET_DIRS = {
    "references", "reference", "assets", "scripts", "resources", "templates",
    "examples", "data", "docs", "lib", "bin", "prompts", "fixtures",
}

REFERENCE_EXT = (
    ".md", ".markdown", ".txt", ".py", ".sh", ".bash", ".js", ".mjs", ".cjs",
    ".ts", ".json", ".yaml", ".yml", ".toml", ".csv", ".sql", ".rb", ".go",
    ".rs", ".ps1", ".xml", ".html", ".j2", ".jinja", ".tmpl", ".template",
)

MD_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
BACKTICK_PATH = re.compile(r"`([\w./\-]*\/[\w.\-]+|[\w.\-]+\.(?:%s))`" % "|".join(
    e.lstrip(".") for e in REFERENCE_EXT
))


def _f(rule_id: str, message: str, file: str, line=None, snippet=None,
       severity: Severity = None) -> Finding:
    rule = get_rule(rule_id)
    assert rule is not None
    return Finding(
        rule_id=rule_id,
        severity=severity or rule.severity,
        category=Category.SPEC,
        title=rule.title,
        message=message,
        file=file,
        line=line,
        snippet=snippet,
        remediation=rule.fix,
        cwe=rule.cwe,
        owasp=rule.owasp,
    )


def _referenced_paths(body: str) -> List[str]:
    """Paths the body claims are bundled with the skill.

    Deliberately conservative. A bare filename in backticks is usually an
    *output* the skill produces (``invoices.csv``), not an input it ships, so
    only paths with a directory component or a markdown link are treated as
    bundled references. Missing a rare broken link beats flagging every output
    filename as one.
    """
    candidates: List[str] = []
    for m in MD_LINK.finditer(body):
        candidates.append(m.group(1))
    for m in BACKTICK_PATH.finditer(body):
        if "/" in m.group(1):
            candidates.append(m.group(1))

    out: List[str] = []
    for raw in candidates:
        ref = raw.strip().strip("'\"").split("#", 1)[0].split("?", 1)[0]
        if not ref or ref.startswith(("http://", "https://", "mailto:", "data:", "#")):
            continue
        if ref.startswith(("~", "/")):
            continue
        head = ref.lstrip("./").split("/", 1)[0].lower()
        if "/" in ref and head not in ASSET_DIRS:
            continue
        if ref.lower().endswith(REFERENCE_EXT) or "/" in ref:
            out.append(ref)
    return out


def check_spec(skill: Skill) -> List[Finding]:
    findings: List[Finding] = []
    rel_md = os.path.basename(skill.skill_md)

    # -- structural ---------------------------------------------------------
    if skill.parse_error == "missing SKILL.md":
        findings.append(
            _f(
                "SPEC-001",
                "This directory does not contain a SKILL.md, so no agent will load it.",
                os.path.relpath(skill.root, os.path.dirname(skill.root)) or ".",
            )
        )
        return findings

    if skill.parse_error == "missing frontmatter":
        findings.append(
            _f(
                "SPEC-002",
                "The file does not start with a '---' fenced YAML block, so name and "
                "description are never read.",
                rel_md,
                1,
                skill.body.splitlines()[0] if skill.body else None,
            )
        )
        return findings

    if skill.parse_error:
        findings.append(
            _f(
                "SPEC-003",
                f"Frontmatter could not be parsed: {skill.parse_error}",
                rel_md,
                2,
            )
        )
        return findings

    fm = skill.frontmatter

    # -- required fields ----------------------------------------------------
    if not skill.name:
        findings.append(_f("SPEC-004", "Frontmatter has no 'name' field.", rel_md, 2))
    else:
        problems = []
        if len(skill.name) > MAX_NAME:
            problems.append(f"longer than {MAX_NAME} characters ({len(skill.name)})")
        if not NAME_RE.match(skill.name):
            problems.append("not lowercase kebab-case (a-z, 0-9, single hyphens)")
        if problems:
            findings.append(
                _f(
                    "SPEC-007",
                    f"The name '{skill.name}' is " + " and ".join(problems) + ".",
                    rel_md,
                    2,
                    f"name: {skill.name}",
                )
            )
        if skill.name != skill.dir_name:
            findings.append(
                _f(
                    "SPEC-008",
                    f"name is '{skill.name}' but the directory is '{skill.dir_name}'.",
                    rel_md,
                    2,
                )
            )

    if not skill.description:
        findings.append(
            _f("SPEC-005", "Frontmatter has no 'description' field.", rel_md, 2)
        )
    elif len(skill.description) > MAX_DESCRIPTION:
        findings.append(
            _f(
                "SPEC-006",
                f"description is {len(skill.description)} characters, over the "
                f"{MAX_DESCRIPTION} limit. Hosts truncate it, and the trigger clause "
                "is what gets cut.",
                rel_md,
                2,
            )
        )

    # -- unknown / typo keys ------------------------------------------------
    for key in fm:
        if key in KNOWN_KEYS:
            continue
        close = difflib.get_close_matches(key, KNOWN_KEYS, n=1, cutoff=0.75)
        if close:
            findings.append(
                _f(
                    "SPEC-009",
                    f"Unknown key '{key}' is probably a typo for '{close[0]}'. As written "
                    "it is ignored, so any control it was meant to set does not apply.",
                    rel_md,
                    2,
                    f"{key}: ...",
                    severity=Severity.MEDIUM,
                )
            )
        else:
            findings.append(
                _f(
                    "SPEC-009",
                    f"Key '{key}' is not part of the standard. Harmless if intentional, "
                    "but some hosts reject unknown keys.",
                    rel_md,
                    2,
                    f"{key}: ...",
                )
            )

    # -- size / context budget ---------------------------------------------
    if skill.body_tokens > BODY_TOKEN_BUDGET:
        findings.append(
            _f(
                "SPEC-010",
                f"SKILL.md is ~{skill.body_tokens:,} tokens ({skill.body_lines} lines), over the "
                f"~{BODY_TOKEN_BUDGET:,} token budget for a single-file skill. This text is paid "
                "for on every turn it is loaded.",
                rel_md,
            )
        )

    # -- references ---------------------------------------------------------
    missing: List[str] = []
    for ref in dict.fromkeys(_referenced_paths(skill.body)):
        base = ref.lstrip("./")
        if base.lower() in ("skill.md",):
            continue
        if not skill.has_file(base) and not os.path.exists(os.path.join(skill.root, base)):
            missing.append(ref)
    for ref in missing[:8]:
        findings.append(
            _f(
                "SPEC-011",
                f"The body references '{ref}', which does not exist in the package.",
                rel_md,
                _line_of(skill, ref),
                f"{ref}",
            )
        )

    # -- path escapes -------------------------------------------------------
    root_real = os.path.realpath(skill.root)
    for f in skill.files:
        if f.is_symlink:
            target = os.path.realpath(f.abspath)
            if not target.startswith(root_real + os.sep) and target != root_real:
                findings.append(
                    _f(
                        "SPEC-012",
                        f"'{f.path}' is a symlink pointing outside the skill directory "
                        f"({target}).",
                        f.path,
                    )
                )
        if f.path.startswith("../") or "/../" in f.path:
            findings.append(
                _f("SPEC-012", f"'{f.path}' resolves outside the skill directory.", f.path)
            )

    # -- encoding -----------------------------------------------------------
    findings.extend(_encoding_checks(skill))

    # -- license ------------------------------------------------------------
    if not fm.get("license"):
        has_license_file = any(
            f.path.lower() in ("license", "license.md", "license.txt", "copying")
            for f in skill.files
        )
        if not has_license_file:
            findings.append(
                _f(
                    "SPEC-014",
                    "No license declared in frontmatter and no LICENSE file in the package.",
                    rel_md,
                )
            )

    return findings


def _line_of(skill: Skill, needle: str) -> int:
    for idx, line in enumerate(skill.body.splitlines(), start=skill.body_start_line):
        if needle in line:
            return idx
    return skill.body_start_line


def _encoding_checks(skill: Skill) -> List[Finding]:
    out: List[Finding] = []
    try:
        with open(skill.skill_md, "rb") as fh:
            raw = fh.read(64)
    except OSError:
        return out
    if raw.startswith(b"\xef\xbb\xbf"):
        out.append(
            _f(
                "SPEC-013",
                "SKILL.md starts with a UTF-8 BOM. Some parsers treat the first line as "
                "'\\ufeff---' and fail to detect the frontmatter.",
                os.path.basename(skill.skill_md),
                1,
            )
        )
    try:
        with open(skill.skill_md, "rb") as fh:
            data = fh.read(4096)
        if b"\r\n" in data:
            out.append(
                _f(
                    "SPEC-013",
                    "SKILL.md uses CRLF line endings. Normalise to LF so diffs and YAML "
                    "parsing stay predictable across platforms.",
                    os.path.basename(skill.skill_md),
                )
            )
    except OSError:
        pass
    return out


def collect_reference_files(skill: Skill) -> Set[str]:
    return {
        f.path
        for f in skill.files
        if f.path.lower().endswith((".md", ".markdown"))
        and os.path.basename(f.path).lower() != "skill.md"
    }
