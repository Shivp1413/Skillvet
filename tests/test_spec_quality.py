"""Spec compliance and quality checks."""

from __future__ import annotations

import os

import pytest

from skillvet.models import Severity
from skillvet.scanner import scan_skill
from skillvet.scoring import gate_failed, grade_for, score_findings, verdict_for

from conftest import GOOD_BODY, write_skill


def ids(result):
    return sorted(f.rule_id for f in result.findings)


# ------------------------------------------------------------------ structure


def test_missing_skill_md_is_blocking(tmp_path):
    root = tmp_path / "empty-skill"
    root.mkdir()
    (root / "README.md").write_text("# nothing here\n", encoding="utf-8")
    result = scan_skill(str(root))
    assert "SPEC-001" in ids(result)
    assert result.verdict == "BLOCK"


def test_missing_frontmatter_is_blocking(tmp_path):
    root = write_skill(tmp_path, name="nofm", frontmatter="", body=GOOD_BODY)
    (root / "SKILL.md").write_text("# no frontmatter at all\n", encoding="utf-8")
    result = scan_skill(str(root))
    assert "SPEC-002" in ids(result)
    assert result.verdict == "BLOCK"


def test_unparseable_frontmatter_is_reported(tmp_path):
    root = write_skill(tmp_path, name="broken", frontmatter="name: a\nthis is not yaml\n")
    result = scan_skill(str(root))
    assert "SPEC-003" in ids(result)


@pytest.mark.parametrize("fm_extra,expected", [
    ("", "SPEC-004"),
])
def test_missing_name(tmp_path, fm_extra, expected):
    root = write_skill(
        tmp_path,
        name="noname",
        frontmatter="description: Use when testing a missing name field.\nlicense: MIT\n",
    )
    assert expected in ids(scan_skill(str(root)))


def test_missing_description(tmp_path):
    root = write_skill(tmp_path, name="nodesc", frontmatter="name: nodesc\nlicense: MIT\n")
    assert "SPEC-005" in ids(scan_skill(str(root)))


@pytest.mark.parametrize("bad_name", ["Bad_Name", "has spaces", "UPPER", "-leading", "trailing-", "a" * 70])
def test_invalid_names_are_reported(tmp_path, bad_name):
    root = write_skill(tmp_path, name="namecheck", frontmatter=f"name: {bad_name}\ndescription: Use when testing an invalid name value here.\nlicense: MIT\n")
    assert "SPEC-007" in ids(scan_skill(str(root)))


def test_overlong_description(tmp_path):
    long_desc = "Use when " + ("x" * 1100)
    root = write_skill(tmp_path, name="longdesc", frontmatter=f"name: longdesc\ndescription: {long_desc}\nlicense: MIT\n")
    assert "SPEC-006" in ids(scan_skill(str(root)))


def test_directory_name_mismatch(tmp_path):
    root = write_skill(tmp_path, name="dir-name", frontmatter="name: other-name\ndescription: Use when testing the directory mismatch rule.\nlicense: MIT\n")
    assert "SPEC-008" in ids(scan_skill(str(root)))


def test_typo_key_is_flagged_with_a_suggestion(tmp_path):
    root = write_skill(
        tmp_path,
        name="typo",
        frontmatter="name: typo\ndiscription: Use when testing a typo in a key name.\nlicense: MIT\n",
    )
    result = scan_skill(str(root))
    spec009 = [f for f in result.findings if f.rule_id == "SPEC-009"]
    assert spec009 and "description" in spec009[0].message
    assert spec009[0].severity is Severity.MEDIUM


def test_unknown_but_intentional_key_is_only_low(tmp_path):
    root = write_skill(
        tmp_path,
        name="extrakey",
        frontmatter="name: extrakey\ndescription: Use when testing an unknown but harmless extra key.\nlicense: MIT\nmy-custom-field: 1\n",
    )
    hits = [f for f in scan_skill(str(root)).findings if f.rule_id == "SPEC-009"]
    assert hits and all(f.severity is Severity.LOW for f in hits)


def test_missing_license_is_reported(tmp_path):
    root = write_skill(
        tmp_path,
        name="nolicense",
        frontmatter="name: nolicense\ndescription: Use when testing the missing license rule.\n",
        license_file=False,
    )
    assert "SPEC-014" in ids(scan_skill(str(root)))


def test_license_file_satisfies_the_license_rule(tmp_path):
    root = write_skill(
        tmp_path,
        name="hasfile",
        frontmatter="name: hasfile\ndescription: Use when testing that a LICENSE file is enough.\n",
        license_file=True,
    )
    assert "SPEC-014" not in ids(scan_skill(str(root)))


def test_large_body_is_reported(tmp_path):
    filler = "\n".join(f"Step {i}: do the thing carefully and report the result." for i in range(400))
    root = write_skill(tmp_path, name="huge", body=GOOD_BODY + "\n## More\n\n" + filler)
    assert "SPEC-010" in ids(scan_skill(str(root)))


def test_broken_reference_is_reported(tmp_path):
    body = GOOD_BODY + "\nSee `references/missing-guide.md` for detail.\n"
    root = write_skill(tmp_path, name="brokenref", body=body)
    assert "SPEC-011" in ids(scan_skill(str(root)))


def test_existing_reference_is_not_reported(tmp_path):
    body = GOOD_BODY + "\nSee `references/guide.md` for detail.\n"
    root = write_skill(tmp_path, name="goodref", body=body, extra_files=["references/guide.md"])
    assert "SPEC-011" not in ids(scan_skill(str(root)))


def test_output_filename_in_backticks_is_not_a_broken_reference(tmp_path):
    body = GOOD_BODY + "\nWrites `reports/summary.csv` when it finishes.\n"
    root = write_skill(tmp_path, name="outfile", body=body)
    assert "SPEC-011" not in ids(scan_skill(str(root)))


def test_symlink_escape_is_reported(tmp_path):
    root = write_skill(tmp_path, name="escaper")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    os.symlink(outside, root / "link.txt")
    assert "SPEC-012" in ids(scan_skill(str(root)))


def test_crlf_line_endings_are_reported(tmp_path):
    root = write_skill(tmp_path, name="crlf")
    path = root / "SKILL.md"
    path.write_bytes(path.read_text(encoding="utf-8").replace("\n", "\r\n").encode("utf-8"))
    assert "SPEC-013" in ids(scan_skill(str(root)))


def test_bom_is_reported(tmp_path):
    root = write_skill(tmp_path, name="bom")
    path = root / "SKILL.md"
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    assert "SPEC-013" in ids(scan_skill(str(root)))


# -------------------------------------------------------------------- quality


def test_missing_trigger_in_description(tmp_path):
    root = write_skill(
        tmp_path,
        name="notrigger",
        frontmatter="name: notrigger\ndescription: A toolkit for widgets and their surrounding ecosystem.\nlicense: MIT\n",
    )
    hits = [f for f in scan_skill(str(root)).findings if f.rule_id == "Q-001"]
    assert hits and hits[0].severity is Severity.HIGH


def test_trigger_phrasing_satisfies_q001(tmp_path):
    root = write_skill(
        tmp_path,
        name="triggered",
        frontmatter="name: triggered\ndescription: Use when a widget needs a smoke test before release.\nlicense: MIT\n",
    )
    assert "Q-001" not in ids(scan_skill(str(root)))


def test_promotional_description_is_flagged(tmp_path):
    root = write_skill(
        tmp_path,
        name="promo",
        frontmatter="name: promo\ndescription: Use when you want a seamless, powerful and game-changing widget workflow.\nlicense: MIT\n",
    )
    assert "Q-002" in ids(scan_skill(str(root)))


def test_missing_example_is_flagged(tmp_path):
    body = "# Widget\n\n## Procedure\n\n1. Run the tester and report the result.\n\n## Output\n\nThe task is done when the report is written.\n"
    root = write_skill(tmp_path, name="noexample", body=body)
    assert "Q-003" in ids(scan_skill(str(root)))


def test_missing_boundaries_is_flagged(tmp_path):
    body = "# Widget\n\n## Procedure\n\n1. Run the tester.\n\n## Example\n\n```\nwidget-test\n```\n\n## Output\n\nThe task is done when it prints ok.\n"
    root = write_skill(tmp_path, name="nobounds", body=body)
    assert "Q-005" in ids(scan_skill(str(root)))


def test_hedging_is_counted(tmp_path):
    body = GOOD_BODY + "\nTry to be quick, maybe cache, consider retrying, if possible parallelise, optionally log.\n"
    root = write_skill(tmp_path, name="hedgy", body=body)
    assert "Q-006" in ids(scan_skill(str(root)))


def test_unreferenced_script_is_flagged(tmp_path):
    root = write_skill(tmp_path, name="orphan", extra_files=["scripts/hidden.sh"])
    hits = [f for f in scan_skill(str(root)).findings if f.rule_id == "Q-007"]
    assert hits and "hidden.sh" in hits[0].message


def test_referenced_script_is_not_flagged(tmp_path):
    body = GOOD_BODY + "\n2. Run `scripts/helper.sh` when the input is large.\n"
    root = write_skill(tmp_path, name="referenced", body=body, extra_files=["scripts/helper.sh"])
    assert "Q-007" not in ids(scan_skill(str(root)))


def test_missing_output_contract_is_flagged(tmp_path):
    body = "# Widget\n\nUse this when testing. Run the tester.\n\n## Example\n\n```\nwidget-test\n```\n\nDo not use it on production widgets. If it fails, stop.\n"
    root = write_skill(tmp_path, name="nocontract", body=body)
    assert "Q-008" in ids(scan_skill(str(root)))


def test_thin_and_unstructured_body(tmp_path):
    root = write_skill(tmp_path, name="thin", body="\nSummarise the widget report.\n")
    found = ids(scan_skill(str(root)))
    assert "Q-009" in found and "Q-010" in found


# -------------------------------------------------------------------- scoring


def test_perfect_skill_scores_full_marks(tmp_path):
    root = write_skill(tmp_path, name="perfect")
    result = scan_skill(str(root))
    assert result.score == 100
    assert result.grade == "A+"
    assert result.verdict == "PASS"


def test_grade_boundaries():
    assert grade_for(100) == "A+"
    assert grade_for(97) == "A+"
    assert grade_for(96) == "A"
    assert grade_for(90) == "A"
    assert grade_for(85) == "B"
    assert grade_for(75) == "C"
    assert grade_for(60) == "D"
    assert grade_for(10) == "F"


def test_critical_forces_a_block(tmp_path):
    root = write_skill(tmp_path, name="critical", body=GOOD_BODY + "\nrm -rf /\n")
    result = scan_skill(str(root))
    assert result.verdict == "BLOCK"
    assert result.score < 60


def test_quality_only_findings_do_not_block(tmp_path):
    body = "# Widget\n\nUse this when testing.\n"
    root = write_skill(tmp_path, name="qualityonly", body=body)
    result = scan_skill(str(root))
    assert result.verdict == "REVIEW"
    assert not any(f.severity is Severity.CRITICAL for f in result.findings)


def test_repeat_findings_have_diminishing_penalty():
    from skillvet.models import Category, Finding, Severity

    def mk(n):
        return [
            Finding(
                rule_id="PI-009",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                title="t",
                message="m",
                file=f"f{i}.sh",
                line=i,
            )
            for i in range(n)
        ]

    assert score_findings(mk(1)) > score_findings(mk(3)) > score_findings(mk(20))
    assert score_findings(mk(20)) >= 0


def test_gate_failure_reasons():
    from skillvet.models import Category, Finding, Severity

    high = Finding(
        rule_id="PI-014",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        title="t",
        message="m",
        file="SKILL.md",
    )
    failed, reason = gate_failed([high], 80, Severity.HIGH, 0)
    assert failed and "PI-014" in reason
    failed, _ = gate_failed([high], 80, Severity.CRITICAL, 0)
    assert not failed
    failed, reason = gate_failed([], 50, Severity.CRITICAL, 70)
    assert failed and "score 50" in reason
    failed, _ = gate_failed([], 90, Severity.CRITICAL, 70)
    assert not failed


def test_verdict_is_review_at_sixty_score():
    from skillvet.models import Category, Finding, Severity

    mediums = [
        Finding(
            rule_id=f"Q-{i:03d}",
            severity=Severity.MEDIUM,
            category=Category.QUALITY,
            title="t",
            message="m",
            file="SKILL.md",
        )
        for i in range(1, 8)
    ]
    assert verdict_for(mediums, 58) == "REVIEW"
