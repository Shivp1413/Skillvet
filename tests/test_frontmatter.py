"""Frontmatter parsing: the subset of YAML a SKILL.md actually needs."""

from __future__ import annotations

import pytest

from skillvet.frontmatter import (
    FrontmatterError,
    parse_frontmatter,
    split_frontmatter,
)


def test_splits_fence_and_body():
    fm, body, start = split_frontmatter("---\nname: a\n---\n# Title\nbody\n")
    assert fm == "name: a"
    assert body == "# Title\nbody\n"
    assert start == 4


def test_no_frontmatter_returns_none():
    fm, body, start = split_frontmatter("# Just a title\n")
    assert fm is None
    assert start == 1


def test_unclosed_fence_raises():
    with pytest.raises(FrontmatterError):
        split_frontmatter("---\nname: a\nno close\n")


def test_bom_is_stripped():
    fm, _, _ = split_frontmatter("\ufeff---\nname: a\n---\n")
    assert fm == "name: a"


def test_scalars_and_types():
    data = parse_frontmatter(
        'name: widget-tester\n'
        'license: "MIT"\n'
        "version: 2\n"
        "ratio: 1.5\n"
        "enabled: true\n"
        "missing: null\n"
    )
    assert data["name"] == "widget-tester"
    assert data["license"] == "MIT"
    assert data["version"] == 2
    assert data["ratio"] == 1.5
    assert data["enabled"] is True
    assert data["missing"] is None


def test_colon_inside_value_is_kept():
    data = parse_frontmatter("description: Use when the file says 'a: b'\n")
    assert data["description"] == "Use when the file says 'a: b'"


def test_inline_list():
    data = parse_frontmatter("allowed-tools: [Read, Write, Bash]\n")
    assert data["allowed-tools"] == ["Read", "Write", "Bash"]


def test_block_sequence():
    data = parse_frontmatter("tags:\n  - alpha\n  - beta\n")
    assert data["tags"] == ["alpha", "beta"]


def test_nested_mapping():
    data = parse_frontmatter("metadata:\n  author: Ada\n  homepage: https://example.com\n")
    assert data["metadata"] == {"author": "Ada", "homepage": "https://example.com"}


def test_block_scalar_folded_and_literal():
    data = parse_frontmatter("a: |\n  line one\n  line two\nb: >\n  joined\n  together\n")
    assert data["a"] == "line one\nline two"
    assert data["b"] == "joined together"


def test_chomping_indicator():
    data = parse_frontmatter("a: |-\n  text\n")
    assert data["a"] == "text"


def test_comments_are_ignored():
    data = parse_frontmatter("# a comment\nname: a  # trailing\n")
    assert data["name"] == "a"


def test_duplicate_key_is_an_error():
    with pytest.raises(FrontmatterError) as exc:
        parse_frontmatter("name: a\nname: b\n")
    assert "duplicate" in str(exc.value)


def test_tab_indentation_is_an_error():
    with pytest.raises(FrontmatterError):
        parse_frontmatter("metadata:\n\tauthor: Ada\n")


def test_unparseable_line_reports_a_line_number():
    with pytest.raises(FrontmatterError) as exc:
        parse_frontmatter("name: a\njust some prose\n")
    assert exc.value.line == 2


def test_mixed_sequence_and_mapping_is_an_error():
    with pytest.raises(FrontmatterError):
        parse_frontmatter("tags:\n  - alpha\n  key: value\n")
