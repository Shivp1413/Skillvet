"""Finding skill packages on disk and loading them into memory."""

from __future__ import annotations

import os
from typing import Iterable, List, Optional, Tuple

from .frontmatter import FrontmatterError, parse_frontmatter, split_frontmatter
from .models import Skill, SkillFile

SKILL_FILENAMES = ("SKILL.md", "skill.md", "Skill.md")
IGNORED_DIRS = {
    ".git", "node_modules", "dist", "build", "out", "target", "__pycache__",
    ".venv", "venv", ".next", ".cache", ".mypy_cache", ".ruff_cache", ".arena",
    ".turbo", ".parcel-cache", "coverage", ".pytest_cache",
}
SCRIPT_EXT = {
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".py", ".js", ".mjs", ".cjs",
    ".ts", ".tsx", ".rb", ".go", ".pl", ".pm", ".ps1", ".psm1", ".bat", ".cmd",
    ".php", ".lua", ".rs", ".c", ".cpp", ".java", ".kt", ".cs", ".swift",
    ".sql", ".ipynb", ".dockerfile",
}
MAX_SCAN_BYTES = 512 * 1024

INSTALLED_DIRS = (
    os.path.join(".claude", "skills"),
    os.path.join(".codex", "skills"),
    os.path.join(".cursor", "skills"),
    os.path.join(".gemini", "skills"),
    os.path.join(".agents", "skills"),
    os.path.join(".opencode", "skills"),
    os.path.join(".copilot", "skills"),
    os.path.join(".github", "skills"),
    os.path.join(".github", "copilot", "skills"),
    os.path.join(".config", "claude", "skills"),
    os.path.join(".config", "opencode", "skills"),
)


def installed_roots(home: Optional[str] = None, cwd: Optional[str] = None) -> List[str]:
    """Locations where agent tools keep installed skills."""
    home = home or os.path.expanduser("~")
    cwd = cwd or os.getcwd()
    roots: List[str] = []
    for rel in INSTALLED_DIRS:
        for base in (home, cwd):
            candidate = os.path.join(base, rel)
            if os.path.isdir(candidate) and candidate not in roots:
                roots.append(candidate)
    return roots


def _is_binary(head: bytes) -> bool:
    return b"\x00" in head[:4096]


def collect_files(root: str, follow_symlinks: bool = False) -> List[SkillFile]:
    real_root = os.path.realpath(root)
    files: List[SkillFile] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for name in sorted(filenames):
            abspath = os.path.join(dirpath, name)
            rel = os.path.relpath(abspath, root).replace(os.sep, "/")
            try:
                stat = os.lstat(abspath)
            except OSError:
                continue
            is_link = os.path.islink(abspath)
            size = stat.st_size
            is_bin = False
            if not is_link and size and size <= MAX_SCAN_BYTES:
                try:
                    with open(abspath, "rb") as fh:
                        is_bin = _is_binary(fh.read(4096))
                except OSError:
                    is_bin = True
            ext = os.path.splitext(name)[1].lower()
            files.append(
                SkillFile(
                    path=rel,
                    abspath=abspath,
                    size=size,
                    is_script=ext in SCRIPT_EXT or name.lower() == "dockerfile",
                    is_executable=bool(stat.st_mode & 0o111) and not is_link,
                    is_symlink=is_link,
                    is_binary=is_bin,
                )
            )
    # Flag links that resolve outside the package.
    for f in files:
        if f.is_symlink:
            target = os.path.realpath(f.abspath)
            if not target.startswith(real_root):
                f.path = f.path  # keep path for reporting; escape detection is in spec.py
    return files


def find_skill_roots(
    paths: Iterable[str],
    excludes: Optional[Iterable[str]] = None,
) -> List[str]:
    """Resolve user-supplied paths into skill root directories."""
    import fnmatch

    excludes = list(excludes or [])
    roots: List[str] = []

    def excluded(path: str) -> bool:
        norm = path.replace(os.sep, "/")
        return any(
            fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(os.path.basename(norm), pat)
            for pat in excludes
        )

    for raw in paths:
        path = os.path.abspath(os.path.expanduser(raw))
        if excluded(path):
            continue
        if os.path.isfile(path):
            if os.path.basename(path).lower() == "skill.md":
                root = os.path.dirname(path)
                if root not in roots:
                    roots.append(root)
            continue
        if not os.path.isdir(path):
            continue
        if _find_skill_md(path):
            roots.append(path)
            continue
        for dirpath, dirnames, _ in os.walk(path):
            dirnames[:] = [
                d for d in dirnames if d not in IGNORED_DIRS and not excluded(os.path.join(dirpath, d))
            ]
            if _find_skill_md(dirpath):
                if dirpath not in roots:
                    roots.append(dirpath)
                dirnames[:] = []  # a skill root does not contain other skill roots
    return roots


def _find_skill_md(root: str) -> Optional[str]:
    for name in SKILL_FILENAMES:
        candidate = os.path.join(root, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def load_skill(root: str) -> Tuple[Skill, List[str]]:
    """Load a skill directory. Returns (skill, extra_notes)."""
    notes: List[str] = []
    root = os.path.abspath(root)
    skill_md = _find_skill_md(root)

    if skill_md is None:
        return (
            Skill(
                root=root,
                skill_md=os.path.join(root, "SKILL.md"),
                parse_error="missing SKILL.md",
                files=collect_files(root),
            ),
            notes,
        )

    if os.path.basename(skill_md) != "SKILL.md":
        notes.append(f"entry file is {os.path.basename(skill_md)}, the standard expects SKILL.md")

    try:
        with open(skill_md, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except UnicodeDecodeError:
        with open(skill_md, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        notes.append("SKILL.md is not valid UTF-8; decoded with replacement characters")
    except OSError as exc:
        return (
            Skill(root=root, skill_md=skill_md, parse_error=f"cannot read SKILL.md: {exc}"),
            notes,
        )

    skill = Skill(root=root, skill_md=skill_md, files=collect_files(root))

    fm_raw, body, body_start = split_frontmatter(raw)
    skill.body = body
    skill.body_start_line = body_start
    skill.frontmatter_raw = fm_raw

    if fm_raw is None:
        skill.parse_error = "missing frontmatter"
        skill.body = raw
        skill.body_start_line = 1
        return skill, notes

    try:
        data = parse_frontmatter(fm_raw)
    except FrontmatterError as exc:
        skill.parse_error = str(exc)
        return skill, notes

    skill.frontmatter = data
    name = data.get("name")
    description = data.get("description")
    skill.name = str(name).strip() if isinstance(name, (str, int, float)) else None
    skill.description = str(description).strip() if isinstance(description, str) else None
    if isinstance(description, str) and "\n" in description:
        notes.append("description spans multiple lines; a single paragraph routes better")
    return skill, notes


def read_text_file(path: str, max_bytes: int = MAX_SCAN_BYTES) -> Optional[str]:
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > max_bytes:
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
    except OSError:
        return None
    if _is_binary(data[:4096]):
        return None
    return data.decode("utf-8", errors="replace")
