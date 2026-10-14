# Triage guide

How to turn a finding list into a decision.

## Verdicts

**PASS** — no findings at all, or only low-severity style notes. Installing it
is a normal, reversible action.

**REVIEW** — findings a human should read first. Nothing here has to stop the
work, but the package will behave inconsistently until at least the high
severity routing and structure findings are fixed.

**BLOCK** — at least one critical finding, at least one high severity security
finding, or a package that cannot load at all. Do not install, copy or run it.

## Which findings are worth escalating

Escalate to the user immediately:

- `PI-002` hidden characters. The payload was deliberately concealed from review.
- `PI-004`, `PI-005` exfiltration. Credentials may already have left the machine.
- `PI-006`, `PI-007`, `PI-010` remote execution or destruction.
- `PI-012` configuration changes that outlive the session.

Mention but do not escalate:

- `PI-008` an embedded credential. Revoke it, then remove it from the file.
- `PI-009`, `PI-011`, `PI-013` capability findings. Report what the package
  reaches for and let the user decide whether that is expected.
- `PI-015` irreversible operations. Ask for a confirmation step to be added.

Fix directly when the user asked for a review of their own package:

- `Q-001` through `Q-010` are about routing and reliability, not safety.

## Reporting rules

1. Quote the exact line for any high or critical finding. A rule id alone is not
   evidence, and it does not survive the reader checking it.
2. Never present a score without the verdict. A 70 with a clean security profile
   is a different situation from a 70 with an exfiltration finding.
3. State which findings came from the baseline file, so accepted risks are not
   mistaken for new ones.
4. Count the files scanned. A package with a SKILL.md and no bundled files has a
   much smaller attack surface than the same skill with ten scripts in it.
