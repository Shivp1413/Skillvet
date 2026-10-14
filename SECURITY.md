# Security policy

## Reporting a vulnerability in skillvet

**Do not open a public issue.** Use GitHub's private reporting:

**https://github.com/Shivp1413/skillvet/security/advisories/new**

Include what you have: the version, a description, a reproduction, and how you
think it could be exploited.

| Stage | Target |
| --- | --- |
| Acknowledgement | 48 hours |
| Initial assessment and severity | 5 days |
| Fix or mitigation for high and critical | 30 days |
| Public advisory | with the fix, crediting you unless you prefer otherwise |

In scope, and taken seriously:

- a crafted SKILL.md that makes the scanner crash, hang, or consume unbounded
  memory or disk,
- a path traversal or symlink trick that makes the scanner read files outside
  the scanned package and report their contents,
- a way to make the scanner report `PASS` on a package that should `BLOCK`
  (a rule bypass),
- corruption of the SARIF or JSON output that could mislead an automated gate,
- anything in the `--baseline` or `.skillvetignore` machinery that suppresses
  findings beyond what the file says.

Out of scope:

- rule false positives and false negatives in general — these are bugs, please
  open a normal issue with a snippet,
- the fact that a `PASS` is not a proof of safety (see "Threat model" below),
- vulnerabilities in a skill that skillvet failed to detect, unless you have a
  general bypass rather than one specific pattern.

---

## Threat model

It helps to be precise about what this tool is, because over-trusting a linter
is its own risk.

### What skillvet defends against

A skill is executable prose. It is read by a model that has the user's
credentials, filesystem access and network access. The attacker's cheapest path
is therefore to get hostile text into the model's context, and the second
cheapest is to get a hostile script onto the disk next to it.

`skillvet` is aimed at exactly that: **static, pre-install inspection** of the
package as an artifact. It reads bytes and reports patterns. It is designed for
the moment before a human copies a directory into `~/.claude/skills`, and for
the CI gate in front of that moment.

### What skillvet does not defend against

- **Runtime behaviour.** A bundled script that looks harmless and does something
  else when it runs is out of scope. skillvet never executes what it scans.
- **Clean skills that are useful and dangerous.** A skill that legitimately posts
  to the network will show up in the capability inventory and score `INFO`, not
  a finding. Deciding whether that is acceptable is a human judgement.
- **Novel obfuscation.** Every pattern is a heuristic. A payload encoded in a way
  nobody has written a rule for will pass.
- **Compromised dependencies of the skill.** If a skill calls a package that is
  later hijacked, skillvet sees a pinned install and nothing else.
- **Anything after installation.** skillvet does not monitor, sandbox, or
  intercept a running agent.
- **Supply chain of skillvet itself.** Mitigated, not eliminated: no runtime
  dependencies, a standard-library-only import check in CI, MIT license, and a
  codebase small enough to read in an afternoon. That is the honest claim.

### Trust boundaries

| Component | Trust |
| --- | --- |
| The scanned package | **Untrusted.** Parsed as data; never executed, imported or installed |
| `.skillvetignore`, `--baseline`, `--ignore` | **Partially trusted.** They suppress findings, so review them in a diff like any code |
| The rule registry | Trusted, versioned with the tool, and covered by tests |
| The environment (`NO_COLOR`, `SKILLVET_AUTHOR`) | Not a security boundary |

### Design decisions that reduce risk

- **No `eval`, no `exec`, no dynamic imports** anywhere in the scanner.
- **No network access.** The scanner makes no outbound requests, ever, including
  for updates or telemetry.
- **No writes outside the paths you ask for.** The only files skillvet creates
  are the ones you name with `-o`, `--write-baseline` and `init`.
- **Bounded input.** Files above `MAX_SCAN_BYTES`, binary files and symlinks are
  skipped rather than followed.
- **Regexes are anchored and non-nested.** Patterns are written to avoid
  catastrophic backtracking; if you find one that hangs, that is a security
  report, not a performance nit.

---

## Verifying a release

```bash
pip download skillvet==1.0.0 --no-deps
sha256sum skillvet-1.0.0-py3-none-any.whl
```

Compare against the checksum published on the GitHub release page. Provenance
attestation via `actions/attest-build-provenance` is on the roadmap for the next
minor release.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | yes, security fixes and detection tuning |
| < 1.0 | no |
