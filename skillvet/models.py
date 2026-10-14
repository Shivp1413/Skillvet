"""Data model shared by every part of skillvet."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    @property
    def penalty(self) -> int:
        """Score penalty applied once per rule, before diminishing returns."""
        return {
            Severity.CRITICAL: 45,
            Severity.HIGH: 18,
            Severity.MEDIUM: 6,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:  # pragma: no cover - argparse guards this
            raise ValueError(f"unknown severity {value!r}") from exc

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


class Category(str, Enum):
    SECURITY = "security"
    SPEC = "spec"
    QUALITY = "quality"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


@dataclass
class Finding:
    """A single problem found in a skill package."""

    rule_id: str
    severity: Severity
    category: Category
    title: str
    message: str
    file: str
    line: Optional[int] = None
    snippet: Optional[str] = None
    remediation: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    in_code: Optional[bool] = None
    context: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "rule": self.rule_id,
            "severity": str(self.severity),
            "category": str(self.category),
            "title": self.title,
            "message": self.message,
            "file": self.file,
        }
        if self.line is not None:
            out["line"] = self.line
        if self.snippet:
            out["snippet"] = self.snippet
        if self.remediation:
            out["remediation"] = self.remediation
        if self.cwe:
            out["cwe"] = self.cwe
        if self.owasp:
            out["owasp"] = self.owasp
        if self.in_code is not None:
            out["in_code_fence"] = self.in_code
        if self.context:
            out["context"] = self.context
        return out


@dataclass
class SkillFile:
    """A file bundled inside a skill directory."""

    path: str  # relative, POSIX style
    abspath: str
    size: int
    is_script: bool = False
    is_executable: bool = False
    is_symlink: bool = False
    is_binary: bool = False


@dataclass
class Capability:
    """A capability a skill asks the agent to exercise."""

    kind: str  # exec | network | write | read_secret | install | persist | privilege
    detail: str
    file: str
    line: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {"kind": self.kind, "detail": self.detail, "file": self.file}
        if self.line is not None:
            d["line"] = self.line
        return d


@dataclass
class Skill:
    """A discovered skill package."""

    root: str
    skill_md: str
    name: Optional[str] = None
    description: Optional[str] = None
    frontmatter: Dict[str, Any] = field(default_factory=dict)
    frontmatter_raw: Optional[str] = None
    body: str = ""
    body_start_line: int = 1
    parse_error: Optional[str] = None
    files: List[SkillFile] = field(default_factory=list)

    @property
    def dir_name(self) -> str:
        import os

        return os.path.basename(os.path.normpath(self.root))

    @property
    def body_lines(self) -> int:
        return len(self.body.strip().splitlines())

    @property
    def body_tokens(self) -> int:
        """Rough token estimate. ~4 characters per token is good enough."""
        return round(len(self.body) / 4)

    def has_file(self, needle: str) -> bool:
        needle = needle.strip().lstrip("./")
        return any(f.path.lstrip("./") == needle for f in self.files)


@dataclass
class ScanResult:
    skill: Skill
    findings: List[Finding] = field(default_factory=list)
    capabilities: List[Capability] = field(default_factory=list)
    score: int = 100
    grade: str = "A+"
    verdict: str = "PASS"
    scanned_files: int = 0
    elapsed_ms: int = 0

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    @property
    def worst(self) -> Optional[Severity]:
        ranked = sorted(self.findings, key=lambda f: f.severity.rank, reverse=True)
        return ranked[0].severity if ranked else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.skill.name or self.skill.dir_name,
            "path": self.skill.root,
            "verdict": self.verdict,
            "score": self.score,
            "grade": self.grade,
            "body_tokens_estimate": self.skill.body_tokens,
            "files_scanned": self.scanned_files,
            "elapsed_ms": self.elapsed_ms,
            "summary": {s.value: self.count(s) for s in Severity},
            "capabilities": [c.to_dict() for c in self.capabilities],
            "findings": [f.to_dict() for f in self.findings],
        }


SEVERITY_BADGE = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}
