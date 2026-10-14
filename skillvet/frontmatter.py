"""Dependency-free parser for SKILL.md YAML frontmatter.

Only the subset of YAML that frontmatter realistically uses is supported:
scalars, quoted scalars, inline lists, block sequences, one level of nested
mapping, block scalars (``|`` / ``>`` with chomping) and comments.

Anything outside that subset raises :class:`FrontmatterError` with a line
number instead of silently guessing -- a validator that guesses is worse
than one that fails.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

_FENCE = re.compile(r"^---[ \t]*$")
_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*:(.*)$")
_SEQ = re.compile(r"^[ \t]*-[ \t]+(.*)$")
_QUOTED = re.compile(r"""^(?P<q>["'])(?P<v>.*)(?P=q)$""", re.DOTALL)


class FrontmatterError(ValueError):
    """Raised when frontmatter is present but cannot be parsed."""

    def __init__(self, message: str, line: Optional[int] = None) -> None:
        self.line = line
        super().__init__(f"line {line}: {message}" if line else message)


def split_frontmatter(text: str) -> Tuple[Optional[str], str, int]:
    """Split raw markdown into (frontmatter, body, body_start_line).

    ``frontmatter`` is ``None`` when the document does not open with a fence.
    ``body_start_line`` is the 1-based line number of the first body line.
    """
    if text.startswith("\ufeff"):
        text = text[1:]
    normalised = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalised.split("\n")

    # Allow a leading HTML comment or blank lines before the fence? No: the
    # Agent Skills spec requires the fence to be the very first thing.
    if not lines or not _FENCE.match(lines[0]):
        return None, normalised, 1

    for idx in range(1, len(lines)):
        if _FENCE.match(lines[idx]):
            fm = "\n".join(lines[1:idx])
            body = "\n".join(lines[idx + 1 :])
            return fm, body, idx + 2
    raise FrontmatterError("frontmatter opened with '---' but never closed")


def _coerce_scalar(raw: str) -> Any:
    v = raw.strip()
    if v == "":
        return None
    quoted = _QUOTED.match(v)
    if not quoted and not v.startswith("["):
        # YAML: an unquoted ' #' starts a comment. Mirrored here so that
        # 'name: a  # note' parses the way every YAML reader would read it.
        v = re.sub(r"\s+#.*$", "", v).strip()
        if v == "":
            return None
    if quoted:
        inner = quoted.group("v")
        if quoted.group("q") == '"':
            inner = inner.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
        return inner
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    if re.fullmatch(r"-?\d+\.\d+", v):
        return float(v)
    # Inline flow list: [a, b, c]
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        return [_coerce_scalar(part) for part in _split_flow(inner)]
    return v


def _split_flow(inner: str) -> List[str]:
    parts, buf, quote = [], [], None
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch == ",":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts]


def parse_frontmatter(raw: str) -> Dict[str, Any]:
    """Parse the YAML subset used by SKILL.md frontmatter into a dict."""
    lines = raw.split("\n")
    data: Dict[str, Any] = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        indent = len(line) - len(line.lstrip(" "))
        if indent != 0:
            raise FrontmatterError("unexpected indentation", i + 1)

        match = _KEY.match(line)
        if not match:
            raise FrontmatterError(
                f"expected 'key: value', got {stripped!r}", i + 1
            )
        key, rest = match.group(1), match.group(2)

        if key in data:
            raise FrontmatterError(f"duplicate key {key!r}", i + 1)

        # Block scalar: key: | / > with optional chomping indicator.
        block = re.match(r"^[ \t]*([|>])([+-]?)[ \t]*$", rest)
        if block:
            style, chomp = block.group(1), block.group(2)
            chunk, i = _read_block(lines, i + 1)
            data[key] = _fold(chunk, style, chomp)
            continue

        if rest.strip() == "":
            # Either a nested mapping or a block sequence follows.
            value, i = _read_nested(lines, i + 1, key)
            data[key] = value
            continue

        data[key] = _coerce_scalar(rest)
        i += 1

    return data


def _read_block(lines: List[str], start: int) -> Tuple[List[str], int]:
    """Read an indented block scalar; returns (raw_lines, next_index)."""
    collected: List[str] = []
    base: Optional[int] = None
    i = start
    while i < len(lines):
        line = lines[i]
        if line.strip() == "":
            collected.append("")
            i += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            break
        if base is None:
            base = indent
        collected.append(line[base:] if indent >= base else line.lstrip(" "))
        i += 1
    # Drop trailing blank lines (chomping applied by caller).
    while collected and collected[-1] == "":
        collected.pop()
    return collected, i


def _fold(chunk: List[str], style: str, chomp: str) -> str:
    if style == "|":
        text = "\n".join(chunk)
    else:  # folded
        out: List[str] = []
        for line in chunk:
            if not line.strip():
                out.append("\n")
            elif out and not out[-1].endswith("\n"):
                out.append(" " + line)
            else:
                out.append(line)
        text = "".join(out)
    if chomp == "-":
        return text.rstrip("\n")
    if chomp == "+":
        return text + "\n"
    return text.rstrip("\n")


def _read_nested(lines: List[str], start: int, key: str) -> Tuple[Any, int]:
    """Read a block sequence or one-level nested mapping after ``key:``."""
    items: List[Any] = []
    mapping: Dict[str, Any] = {}
    mode: Optional[str] = None
    i = start

    while i < len(lines):
        line = lines[i]
        if line.strip() == "" or line.strip().startswith("#"):
            i += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            break

        seq = _SEQ.match(line)
        if seq:
            if mode == "map":
                raise FrontmatterError("mixed mapping and sequence", i + 1)
            mode = "seq"
            items.append(_coerce_scalar(seq.group(1)))
            i += 1
            continue

        entry = _KEY.match(line.strip())
        if not entry:
            raise FrontmatterError(f"cannot parse nested value {line.strip()!r}", i + 1)
        if mode == "seq":
            raise FrontmatterError("mixed sequence and mapping", i + 1)
        mode = "map"
        sub_key, sub_rest = entry.group(1), entry.group(2)
        if sub_rest.strip() == "":
            # Two levels deep is enough for frontmatter (e.g. metadata.author).
            sub_items, i = _read_block_or_deeper(lines, i + 1)
            mapping[sub_key] = sub_items
        else:
            mapping[sub_key] = _coerce_scalar(sub_rest)
            i += 1

    if mode == "map":
        return mapping, i
    return items, i


def _read_block_or_deeper(lines: List[str], start: int) -> Tuple[Any, int]:
    """Third level: a sequence of scalars, or a list of small maps."""
    items: List[Any] = []
    maps: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    i = start
    while i < len(lines):
        line = lines[i]
        if line.strip() == "" or line.strip().startswith("#"):
            i += 1
            continue
        if len(line) - len(line.lstrip(" ")) == 0:
            break
        seq = _SEQ.match(line)
        if seq:
            if current is not None:
                maps.append(current)
                current = None
            items.append(_coerce_scalar(seq.group(1)))
            i += 1
            continue
        entry = _KEY.match(line.strip())
        if entry:
            current = current or {}
            current[entry.group(1)] = _coerce_scalar(entry.group(2))
            i += 1
            continue
        break
    if current is not None:
        maps.append(current)
    return (maps if maps else items), i
