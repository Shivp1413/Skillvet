# CLI reference

```
skillvet <command> [options]
```

| Command | Purpose |
| --- | --- |
| `scan` | Analyse one or more skill packages (default command) |
| `rules` | List the rule catalogue |
| `explain <RULE-ID>` | Rationale, mapping and fix for one rule |
| `init <path>` | Scaffold a new, compliant skill |
| `score <path>` | Print only the score, for scripts |
| `badge <path>` | Print a shields.io endpoint payload |
| `version` | Print the version |

`scan` is assumed when the first argument is not a command, so
`skillvet .` and `skillvet scan .` are the same thing.

---

## `skillvet scan`

```
skillvet scan [PATHS...] [options]
```

Scans every directory containing a `SKILL.md` at or below each path. A file path
pointing directly at a `SKILL.md` works too, and a directory that contains no
skill is reported rather than silently skipped.

| Option | Default | Description |
| --- | --- | --- |
| `--installed` | off | Also scan the skill directories used by agent tools in `$HOME` and the current project |
| `--format {terminal,json,sarif,md,badge}` | `terminal` | Output format |
| `--json` | | Shorthand for `--format json` |
| `--sarif` | | Shorthand for `--format sarif` |
| `--markdown` | | Shorthand for `--format md` |
| `-o, --output FILE` | stdout | Write to a file instead of stdout |
| `--fail-on {never,critical,high,medium,low,info}` | `high` | Exit `1` when a finding at this level or above exists |
| `--min-score N` | `0` | Exit `1` when the score is below `N` |
| `--min-severity {critical,high,medium,low,info}` | `info` | Hide findings below this severity |
| `--ignore RULE` | | Skip a rule id. Repeatable |
| `--exclude GLOB` | | Skip files or directories matching a glob. Repeatable |
| `--baseline FILE` | | Suppress findings recorded in a baseline |
| `--write-baseline FILE` | | Record current findings as a baseline, then exit `0` |
| `--explain` | off | Print the remediation for every finding |
| `--no-capabilities` | off | Hide the capability inventory |
| `--quiet` | off | Minimal output |
| `--list-rules` | off | Print the rule catalogue and exit |
| `--color` / `--no-color` | auto | Force colour on or off. `NO_COLOR` is honoured |
| `--strict-parse` | off | Treat "no skill found" as exit code `2` |

### Examples

```bash
skillvet scan .                                  # everything under the current directory
skillvet scan skills/pdf-tools                   # one package
skillvet scan skills/ --explain                  # with the fix for each finding
skillvet scan . --fail-on critical --min-score 60
skillvet scan . --exclude 'examples/hostile-*'   # skip known-bad fixtures
skillvet scan . --ignore Q-010 --ignore SPEC-014 # skip two rules
skillvet scan . --json | jq '.summary'
skillvet scan . --sarif -o skillvet.sarif
skillvet scan . --markdown -o comment.md
skillvet score . && echo "clean"
```

---

## `skillvet rules`

```
skillvet rules [--json] [--category {security,spec,quality}]
```

```bash
skillvet rules
skillvet rules --category security
skillvet rules --json | jq '.[] | select(.severity == "critical")'
```

## `skillvet explain`

```bash
skillvet explain PI-002
```

Prints what the rule detects, why it matters, the fix, and the CWE / OWASP
mapping. Every finding in terminal output can be looked up this way.

## `skillvet init`

```
skillvet init <path> [--description TEXT] [--license MIT] [--force]
```

Creates a skill package that scores 100/100 out of the box: `SKILL.md`,
`README.md`, `references/details.md` and a `LICENSE`. The skill name is derived
from the directory name and normalised to kebab-case.

```bash
skillvet init skills/release-notes -d "Use when the user asks for release notes or a changelog entry."
```

The license copyright line is filled from `git config user.name`, then
`$SKILLVET_AUTHOR`, then `$USER`; if none is available it reads
`The <name> authors`. Pass `--force` to write into a non-empty directory.

## `skillvet score` and `skillvet badge`

```bash
skillvet score .            # → 100 A+ PASS pdf-invoice-extractor
skillvet score . --min-score 80
skillvet badge .            # → shields.io endpoint JSON
```

`badge` is designed for a shields.io endpoint badge, so a README can show a live
score:

```json
{ "schemaVersion": 1, "label": "skillvet", "message": "100/100 A+", "color": "brightgreen" }
```

---

## Output formats

### Terminal

Severity-grouped, with the matched line quoted for every finding, then a
capability inventory. Colour is used when stdout is a terminal and `NO_COLOR` is
unset.

### JSON

```json
{
  "tool": { "name": "skillvet", "version": "1.0.0" },
  "summary": { "skills": 1, "verdicts": {"PASS": 1, "REVIEW": 0, "BLOCK": 0}, "total_findings": 2 },
  "results": [
    {
      "name": "pdf-invoice-extractor",
      "path": "examples/pdf-invoice-extractor",
      "verdict": "PASS",
      "score": 100,
      "grade": "A+",
      "summary": { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
      "capabilities": [{ "kind": "exec", "detail": "bash", "file": "SKILL.md", "line": 39 }],
      "findings": [
        {
          "rule": "Q-001", "severity": "high", "category": "quality",
          "title": "description does not state when to use the skill",
          "message": "...", "file": "SKILL.md", "line": 3,
          "snippet": "...", "remediation": "..."
        }
      ]
    }
  ]
}
```

The JSON schema is additive: fields may be added in a minor release, existing
fields will not be renamed without a major version.

### SARIF

SARIF 2.1.0, for GitHub code scanning and any SARIF viewer. Rules carry their
CWE and OWASP mappings; results carry a stable `partialFingerprints` value so
alerts survive line moves.

### Markdown

A summary table plus collapsible detail per package. Built for a pull-request
comment; see [ci.md](ci.md) for the workflow that posts it.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Gate passed |
| `1` | Gate failed: a finding at or above `--fail-on`, or a score below `--min-score` |
| `2` | Usage error, or no skill found with `--strict-parse` |

Machine-readable formats keep stdout parseable: the gate message is written to
stderr when the output is JSON, SARIF, badge or Markdown.

---

## Environment

| Variable | Effect |
| --- | --- |
| `NO_COLOR` | Disables colour, whatever the terminal reports |
| `SKILLVET_AUTHOR` | Copyright name used by `skillvet init` |
| `PYTHONPATH` | Not needed when installed; required for `python3 -m skillvet` from a checkout |
