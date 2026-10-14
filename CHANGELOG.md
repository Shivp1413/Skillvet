# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] — 2026-10-13

The first release. 40 rules, zero dependencies.

### Added

- **Security scanner (16 rules, `PI-*`)** for prompt injection, hidden and
  invisible characters, credential exfiltration, exfiltration hosts and image
  beacons, piped remote code execution, destructive filesystem and device
  commands, embedded credentials, credential-store and keychain access,
  obfuscated payloads, unpinned activation-time installs, agent-configuration
  tampering, privilege escalation and persistence, suppressed user confirmation,
  and irreversible operations with no nearby guard. Informational inventory of
  the hosts a package contacts.
- **Specification checks (14 rules, `SPEC-*`)** for a missing or unparseable
  `SKILL.md`, missing `name` and `description`, invalid names, over-long
  descriptions, misspelled frontmatter keys, oversized bodies, broken file
  references, path escapes, non-UTF8 content and missing licenses.
- **Quality checks (10 rules, `Q-*`)** for descriptions that never state a
  trigger, vague or promotional wording, missing examples and output contracts,
  absent scope boundaries, hedged instructions, unreferenced bundled scripts,
  and missing structure.
- **Verdicts and scoring.** `PASS`, `REVIEW` and `BLOCK` driven by security and
  loadability; a 0–100 score with letter grades for overall health.
- **Five output formats** — terminal, JSON, SARIF 2.1.0, Markdown for pull
  request comments, and a shields.io endpoint payload for a live badge.
- **`skillvet init`** scaffolds a package that scores 100/100.
- **`skillvet explain <RULE-ID>`** documents any rule with its rationale, fix,
  CWE and OWASP mapping.
- **Suppression at three scopes** — inline comments, a per-package
  `.skillvetignore`, and repository baselines that survive line moves.
- **Capability inventory** listing what a package asks the agent to do: network
  egress, command execution, secret reads, installs, writes, privileges.
- **Bundled skill** at `skills/skillvet/` so an agent can triage findings.
- **Composite GitHub Action** and a ready pull-request review workflow.
- **Three example packages** (pass, review, hostile) with regression tests.

### Design decisions

- **Zero runtime dependencies**, enforced by a CI job that fails the build if
  anything outside the standard library is imported.
- **Context-aware detection.** Prose, fenced code and bundled scripts are
  scanned differently. Combination rules (such as secret-read *near* a network
  call) are used where a single token would be too noisy.
- **Negation-aware findings.** A document that warns about an attack pattern is
  downgraded and annotated rather than silently dropped.
- **Suppression is always explicit.** Nothing is hidden without a line in a diff.

[Unreleased]: https://github.com/Shivp1413/skillvet/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Shivp1413/skillvet/releases/tag/v1.0.0
