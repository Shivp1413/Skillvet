# Running skillvet in CI

The goal is a check that fails loudly on real risk, stays quiet on noise, and
leaves enough evidence in the pull request that a reviewer can decide quickly.

## Choosing a gate

| Repository | Recommended gate | Why |
| --- | --- | --- |
| You publish skills | `--fail-on high --min-score 85` | Your own packages should be exemplary |
| You consume skills | `--fail-on high` | Block on anything that can hurt the machine |
| You vendor skills you did not write | `--fail-on medium --min-score 70` | Accept nothing unexplained from a third party |
| Monorepo, first rollout | `--write-baseline`, then `--fail-on high` | See "Adopting on an existing repository" below |

`--fail-on critical` is a reasonable starting point if you want reporting before
enforcement. `--fail-on never` makes skillvet a reporter: it still exits `1` if
`--min-score` is set and missed.

---

## GitHub Actions

### Minimal

```yaml
name: skill review
on: [pull_request]

jobs:
  skillvet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install .
      - run: skillvet scan skills/ --fail-on high --min-score 85
```

### With code scanning and a pull-request comment

This is the workflow this repository ships as
`.github/workflows/skillvet.yml`. It scans only the skills the pull request
touched, uploads SARIF so findings appear inline on the diff, and keeps one
sticky comment up to date.

```yaml
name: review skills
on:
  pull_request:
    paths: ["**/SKILL.md"]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  skillvet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install .

      - name: Find changed skills
        id: changed
        run: |
          set -euo pipefail
          dirs=$(git diff --name-only \
              "${{ github.event.pull_request.base.sha }}" \
              "${{ github.event.pull_request.head.sha }}" \
            | grep -E 'SKILL\.md$' | xargs -r -n1 dirname | sort -u | tr '\n' ' ')
          [ -n "$dirs" ] && echo "found=true" >> "$GITHUB_OUTPUT" || echo "found=false" >> "$GITHUB_OUTPUT"
          echo "dirs=$dirs" >> "$GITHUB_OUTPUT"

      - name: Scan
        if: steps.changed.outputs.found == 'true'
        id: scan
        continue-on-error: true
        run: skillvet scan ${{ steps.changed.outputs.dirs }} --fail-on high --min-score 70 --no-color

      - name: SARIF
        if: steps.changed.outputs.found == 'true'
        run: skillvet scan ${{ steps.changed.outputs.dirs }} --sarif -o skillvet.sarif --fail-on never

      - uses: github/codeql-action/upload-sarif@v3
        if: steps.changed.outputs.found == 'true'
        with:
          sarif_file: skillvet.sarif
          category: skillvet

      - name: Comment
        if: steps.changed.outputs.found == 'true'
        run: skillvet scan ${{ steps.changed.outputs.dirs }} --markdown --fail-on never > body.md

      - uses: marocchino/sticky-pull-request-comment@v2
        if: steps.changed.outputs.found == 'true'
        with:
          header: skillvet
          path: body.md

      - if: steps.changed.outputs.found == 'true' && steps.scan.outcome == 'failure'
        run: exit 1
```

`security-events: write` is only needed for the SARIF upload. Everything else
runs with a read-only token.

### As a composite action

```yaml
- uses: actions/checkout@v4
- uses: skillvet/skillvet/.github/actions/skillvet@v1
  with:
    paths: skills/
    fail-on: high
    min-score: "85"
    sarif-file: skillvet.sarif
```

The action installs skillvet, scans, optionally writes SARIF, and fails the job
when the gate does.

---

## GitLab CI

```yaml
skill-review:
  image: python:3.12-slim
  stage: test
  rules:
    - changes: ["**/SKILL.md"]
  script:
    - pip install .
    - skillvet scan skills/ --fail-on high --min-score 85 --no-color
  artifacts:
    when: always
    paths: [skillvet.sarif]
    reports:
      # GitLab reads SARIF natively from the security dashboard
      sast: skillvet.sarif
```

---

## Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Shivp1413/skillvet
    rev: v1.0.0
    hooks:
      - id: skillvet
        args: ["--fail-on", "high"]
```

The hook in this repository runs on Markdown changes and scans the whole skills
tree rather than only staged files, because a skill is a directory and a partial
view of it is misleading.

---

## A plain git hook

```bash
cat > .git/hooks/pre-commit <<'EOF'
#!/bin/sh
if command -v skillvet >/dev/null 2>&1; then
  skillvet scan skills/ --fail-on high --quiet || {
    echo "skillvet blocked this commit: fix the findings or run 'skillvet scan skills/ --explain'"
    exit 1
  }
fi
EOF
chmod +x .git/hooks/pre-commit
```

---

## Adopting on an existing repository

An existing tree usually has dozens of findings. Do not spend a week fixing
descriptions before you get any protection.

```bash
# 1. Record what exists today as accepted.
skillvet scan skills/ --write-baseline .skillvet-baseline.json
git add .skillvet-baseline.json
git commit -m "chore: record the current skill findings as a baseline"

# 2. Gate only new risk from here on.
skillvet scan skills/ --baseline .skillvet-baseline.json --fail-on high
```

Baseline entries are keyed by rule, file and the matched text, so:

- moving a file or adding lines above a finding does not resurrect it,
- a *new* instance of an already-accepted rule is still reported,
- deleting the baseline file restores the full report at any time.

Review the baseline file in the pull request like any other code. It is the
record of what you decided to live with.

---

## Machine output in a pipeline

```bash
# Fail only on critical findings, and post the count to Slack
skillvet scan skills/ --json --fail-on never > report.json
count=$(jq '[.results[].findings[] | select(.severity=="critical")] | length' report.json)
if [ "$count" -gt 0 ]; then
  jq -r '.results[] | .name as $n | .findings[] | select(.severity=="critical") | "\($n): \(.rule) \(.file):\(.line) — \(.title)"' report.json
fi
```

```bash
# Track the mean score over time
skillvet scan skills/ --json | jq -r '.summary.mean_score'
```

---

## Troubleshooting

**`No SKILL.md found`** — the path is a parent with no skill below it, or the
package uses a different entry filename. Run with `--strict-parse` in CI to turn
this into a failure instead of a silent pass.

**A finding is correct but accepted** — suppress it in the smallest scope that
works: one line with a comment, one package with `.skillvetignore`, one
repository with a baseline. See the README.

**A finding is wrong** — open an issue with the snippet and the rule id. False
positives are treated as bugs, and every rule is expected to carry a negative
test.

**SARIF upload fails with "not valid SARIF"** — check that the scan produced at
least one non-`info` result; an empty SARIF file is valid but some uploaders
reject a run with no results. `--fail-on never` keeps the job green while still
producing the file.
