"""Shared fixtures and helpers."""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path
from typing import Iterable, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from skillvet import scanner  # noqa: E402

GOOD_BODY = """
# Widget tester

Use this skill when a widget needs a smoke test.

## Procedure

1. Run the tester script.
2. Report the result.

## Example

```
widget-test ./src
```

## Output

The script prints one line per widget. The task is done when every line is `ok`.

## Failure modes

- If the script fails, stop and report the error. Do not retry blindly.
"""


def write_skill(
    base: Path,
    name: str = "widget-tester",
    frontmatter: Optional[str] = None,
    body: str = GOOD_BODY,
    extra_files: Optional[Iterable[str]] = None,
    license_file: bool = True,
) -> Path:
    """Create a skill package on disk and return its root."""
    root = base / name
    root.mkdir(parents=True, exist_ok=True)
    fm = frontmatter
    if fm is None:
        fm = (
            f"name: {name}\n"
            "description: Use when a widget needs a smoke test; reports one line per widget.\n"
            "license: MIT\n"
        )
    content = f"---\n{fm}---\n{textwrap.dedent(body)}"
    (root / "SKILL.md").write_text(content, encoding="utf-8")
    for rel in extra_files or []:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# hello\n", encoding="utf-8")
    if license_file:
        (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


@pytest.fixture()
def skill_factory(tmp_path):
    counter = {"n": 0}

    def factory(**kwargs):
        counter["n"] += 1
        kwargs.setdefault("name", f"skill-{counter['n']}")
        return write_skill(tmp_path, **kwargs)

    return factory


@pytest.fixture()
def scan():
    def _scan(root):
        return scanner.scan_skill(str(root))

    return _scan


def rule_ids(result) -> list:
    return sorted(f.rule_id for f in result.findings)


def severities(result, rule_id: str):
    return [f.severity for f in result.findings if f.rule_id == rule_id]


@pytest.fixture(autouse=True)
def _no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    yield


@pytest.fixture(autouse=True)
def _cwd_tmp(tmp_path, monkeypatch):
    """Keep CLI tests from picking up the real repository tree."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    yield


def path_without_pycache() -> None:  # pragma: no cover - helper for debugging
    os.environ.pop("PYTHONDONTWRITEBYTECODE", None)
