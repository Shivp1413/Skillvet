"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Sequence

from . import __version__, report, scanner
from .models import Severity
from .rules import REGISTRY, RULES, by_category
from .scaffold import scaffold_skill

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_USAGE = 2

COMMANDS = {"scan", "rules", "explain", "init", "score", "badge", "version"}

EPILOG = """examples:
  skillvet scan .                          scan every skill in this repo
  skillvet scan skills/ --explain          scan a folder, show how to fix things
  skillvet scan --installed                scan the skills you already have installed
  skillvet scan . --fail-on high --min-score 80   CI gate
  skillvet scan . --format sarif -o results.sarif  upload to GitHub code scanning
  skillvet init skills/my-new-skill        scaffold a compliant skill
  skillvet explain PI-002                  what a rule means and how to fix it

exit codes:
  0  no findings at or above the gate, score met
  1  gate failed (findings, or score below --min-score)
  2  usage or parse error
"""


def _color_enabled(force: Optional[bool]) -> bool:
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillvet",
        description=(
            "Vet agent skills before you install them: Agent Skills spec compliance, "
            "quality, and prompt-injection / supply-chain risk. Zero dependencies."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"skillvet {__version__}")
    sub = parser.add_subparsers(dest="command")

    # ---- scan ------------------------------------------------------------
    p_scan = sub.add_parser("scan", help="scan one or more skills", description="Scan skill packages.")
    p_scan.add_argument("paths", nargs="*", default=[], help="skill directories or a parent directory")
    p_scan.add_argument("--installed", action="store_true", help="scan skills already installed by agent tools")
    p_scan.add_argument("--format", choices=["terminal", "json", "sarif", "md", "badge"], default="terminal")
    p_scan.add_argument("-o", "--output", help="write output to a file instead of stdout")
    p_scan.add_argument("--json", action="store_true", help="shorthand for --format json")
    p_scan.add_argument("--sarif", action="store_true", help="shorthand for --format sarif")
    p_scan.add_argument("--markdown", action="store_true", help="shorthand for --format md")
    p_scan.add_argument("--fail-on", choices=["never", "critical", "high", "medium", "low", "info"],
                        default="high", help="exit non-zero when a finding at this level exists (default: high)")
    p_scan.add_argument("--min-score", type=int, default=0, help="exit non-zero when the score is below this")
    p_scan.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "info"],
                        default="info", help="hide findings below this severity (default: info)")
    p_scan.add_argument("--ignore", action="append", default=[], metavar="RULE",
                        help="skip a rule id, e.g. --ignore Q-010 (repeatable)")
    p_scan.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="skip files or directories matching a glob (repeatable)")
    p_scan.add_argument("--baseline", metavar="FILE", help="suppress findings recorded in a baseline file")
    p_scan.add_argument("--write-baseline", metavar="FILE", help="record current findings as the baseline, then exit 0")
    p_scan.add_argument("--explain", action="store_true", help="show remediation for every finding")
    p_scan.add_argument("--no-capabilities", action="store_true", help="hide the capability inventory")
    p_scan.add_argument("--quiet", action="store_true", help="minimal output")
    p_scan.add_argument("--list-rules", action="store_true", help="print the rule catalogue and exit")
    p_scan.add_argument("--color", action="store_true", default=None, help="force colour output")
    p_scan.add_argument("--no-color", dest="color", action="store_false", help="disable colour output")
    p_scan.add_argument("--strict-parse", action="store_true", help="treat a malformed package as a usage error")

    # ---- rules -----------------------------------------------------------
    p_rules = sub.add_parser("rules", help="list the rule catalogue")
    p_rules.add_argument("--json", action="store_true")
    p_rules.add_argument("--category", choices=["security", "spec", "quality"])

    # ---- explain ---------------------------------------------------------
    p_explain = sub.add_parser("explain", help="explain one rule")
    p_explain.add_argument("rule_id", help="e.g. PI-002")

    # ---- init ------------------------------------------------------------
    p_init = sub.add_parser("init", help="scaffold a new, compliant skill")
    p_init.add_argument("path", help="directory to create (also becomes the skill name)")
    p_init.add_argument("--description", "-d", default=None, help="what the skill does and when to use it")
    p_init.add_argument("--license", default="MIT", help="license identifier (default: MIT)")
    p_init.add_argument("--force", action="store_true", help="write into a non-empty directory")

    # ---- score / badge ---------------------------------------------------
    p_score = sub.add_parser("score", help="print just the score, for scripts")
    p_score.add_argument("paths", nargs="*", default=["."])
    p_score.add_argument("--min-score", type=int, default=0)

    p_badge = sub.add_parser("badge", help="print a shields.io endpoint payload")
    p_badge.add_argument("paths", nargs="*", default=["."])

    # ---- version ---------------------------------------------------------
    sub.add_parser("version", help="print the version")

    return parser


def _print_rule_table(category: Optional[str] = None, as_json: bool = False) -> str:
    import json

    rules = RULES
    if category:
        from .models import Category

        rules = by_category(Category(category))
    if as_json:
        return json.dumps([r.to_dict() for r in rules], indent=2)
    lines = []
    current = None
    for r in rules:
        if r.category != current:
            current = r.category
            lines.append("")
            lines.append(f"{str(current).upper()} RULES")
            lines.append("-" * 78)
        lines.append(f"  {r.id:<9} {str(r.severity):<9} {r.title}")
    lines.append("")
    lines.append("Run 'skillvet explain <RULE-ID>' for the rationale and the fix.")
    return "\n".join(lines)


def _print_explanation(rule_id: str) -> str:
    rule = REGISTRY.get(rule_id.upper())
    if rule is None:
        close = [r for r in REGISTRY if r.upper().endswith(rule_id.upper())]
        hint = f" Did you mean {', '.join(close)}?" if close else ""
        return f"Unknown rule '{rule_id}'.{hint}\nRun 'skillvet rules' to list every rule."
    lines = [
        "",
        f"{rule.id}  \u00b7  {str(rule.severity).upper()}  \u00b7  {str(rule.category).upper()}",
        "=" * 78,
        f"{rule.title}",
        "",
        "What it detects",
        f"  {rule.what}",
        "",
        "Why it matters",
        f"  {rule.why}",
        "",
        "How to fix it",
        f"  {rule.fix}",
    ]
    if rule.cwe or rule.owasp:
        lines.append("")
        lines.append("Mappings")
        if rule.cwe:
            lines.append(f"  {rule.cwe}  https://cwe.mitre.org/data/definitions/{rule.cwe.split('-')[-1]}.html")
        if rule.owasp:
            lines.append(f"  {rule.owasp}")
    lines.append("")
    return "\n".join(lines)


def _parse_severity(value: str) -> Optional[Severity]:
    if value == "never":
        return None
    return Severity(value)


def cmd_scan(args: argparse.Namespace) -> int:
    if args.list_rules:
        print(_print_rule_table())
        return EXIT_OK

    fmt = args.format
    if args.json:
        fmt = "json"
    if args.sarif:
        fmt = "sarif"
    if args.markdown:
        fmt = "md"

    paths: List[str] = list(args.paths)
    if args.installed:
        installed = scanner.discovery.installed_roots()
        if not installed:
            print("No installed skill directories found (looked for .claude/skills, "
                  ".codex/skills, .cursor/skills, .gemini/skills, .agents/skills and friends).")
            return EXIT_OK
        paths.extend(installed)
    if not paths:
        paths = ["."]

    baseline = scanner.load_baseline(args.baseline) if args.baseline else None
    results = scanner.scan_paths(
        paths, ignore=args.ignore, excludes=args.exclude, baseline=baseline
    )

    if not results:
        message = (
            "No SKILL.md found in: " + ", ".join(paths) + "\n"
            "A skill package is a directory containing a SKILL.md file."
        )
        if fmt == "json":
            print(report.to_json([]))
        elif fmt == "sarif":
            print(report.to_sarif([]))
        else:
            print(message)
        return EXIT_USAGE if args.strict_parse else EXIT_OK

    if args.write_baseline:
        count = scanner.write_baseline(args.write_baseline, results)
        print(f"Baseline written to {args.write_baseline} ({count} entr{'y' if count == 1 else 'ies'}).")
        return EXIT_OK

    # severity filter for display and for the gate
    min_sev = Severity(args.min_severity)
    visible = [
        r for r in results
    ]
    if min_sev is not Severity.INFO:
        for r in visible:
            r.findings = [f for f in r.findings if f.severity.rank >= min_sev.rank]

    if fmt == "terminal":
        text = report.render_terminal(
            visible,
            color=_color_enabled(args.color),
            verbose=args.explain,
            show_capabilities=not args.no_capabilities,
            quiet=args.quiet,
        )
    elif fmt == "json":
        text = report.to_json(visible)
    elif fmt == "sarif":
        text = report.to_sarif(visible, scan_root=os.getcwd())
    elif fmt == "badge":
        import json

        text = json.dumps(report.to_badge_json(results), indent=2)
    else:
        text = report.to_markdown(visible)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        if fmt != "terminal" or not args.quiet:
            print(f"Wrote {args.output}")
    else:
        print(text)

    if fmt in ("terminal", "md"):
        offenders = [r for r in visible if r.findings]
        if offenders and not args.quiet and fmt == "terminal":
            print("  Run with --explain for the fix, or --json for machine output.")
            print("")

    fail_on = _parse_severity(args.fail_on)
    all_findings = [f for r in results for f in r.findings]
    worst_score = min(r.score for r in results)
    if fail_on is not None:
        from .scoring import gate_failed

        failed, reason = gate_failed(all_findings, worst_score, fail_on, args.min_score)
    else:
        failed, reason = (worst_score < args.min_score, f"score {worst_score} below {args.min_score}")
    if failed:
        # Machine-readable formats must stay parseable, so the gate message goes
        # to stderr whenever stdout is a JSON, SARIF or Markdown document.
        machine_readable = fmt in ("json", "sarif", "badge", "md")
        stream = sys.stderr if machine_readable else sys.stdout
        if args.quiet:
            print(reason, file=stream)
        else:
            print(f"  gate failed: {reason}", file=stream)
        return EXIT_GATE_FAILED
    return EXIT_OK


def cmd_score(args: argparse.Namespace) -> int:
    results = scanner.scan_paths(args.paths or ["."])
    if not results:
        print("noskill")
        return EXIT_USAGE
    worst = min(results, key=lambda r: r.score)
    print(f"{worst.score} {worst.grade} {worst.verdict} {worst.skill.name or worst.skill.dir_name}")
    if args.min_score and worst.score < args.min_score:
        return EXIT_GATE_FAILED
    return EXIT_OK


def cmd_badge(args: argparse.Namespace) -> int:
    import json

    results = scanner.scan_paths(args.paths or ["."])
    print(json.dumps(report.to_badge_json(results), indent=2))
    return EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    try:
        created = scaffold_skill(
            args.path, description=args.description, license_id=args.license, force=args.force
        )
    except FileExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print("")
    print(f"  Created {created['name']} in {created['path']}")
    for f in created["files"]:
        print(f"    + {f}")
    print("")
    print("  Next steps")
    print("    1. Replace the description's trigger clause with the words users actually type.")
    print("    2. Write the procedure under 'Procedure'.")
    print("    3. Run 'skillvet scan .' until it reports PASS.")
    print("")
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)

    if not raw:
        build_parser().print_help()
        return EXIT_OK

    # Allow 'skillvet .' and 'skillvet --json .' as shorthand for 'scan'.
    if raw[0] not in COMMANDS and not raw[0] in ("-h", "--help"):
        raw = ["scan"] + raw

    parser = build_parser()
    try:
        args = parser.parse_args(raw)
    except SystemExit as exc:
        # --help and --version exit through argparse; keep main() an int-returning
        # function so it stays usable when embedded.
        return int(exc.code or EXIT_OK)

    if args.command == "version" or args.command is None:
        print(f"skillvet {__version__}")
        return EXIT_OK
    if args.command == "rules":
        print(_print_rule_table(args.category, args.json))
        return EXIT_OK
    if args.command == "explain":
        print(_print_explanation(args.rule_id))
        return EXIT_OK
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "score":
        return cmd_score(args)
    if args.command == "badge":
        return cmd_badge(args)

    parser.error(f"unknown command {args.command!r}")  # pragma: no cover
    return EXIT_USAGE  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
