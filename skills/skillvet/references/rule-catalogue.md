# Rule catalogue

## Security

| Rule | Severity | Detects |
| --- | --- | --- |
| `PI-001` | critical | Text that tells the agent to ignore its existing instructions |
| `PI-002` | critical | Zero-width, bidi or tag-block characters hiding text |
| `PI-003` | high | Role reassignment, or a claim of a new system prompt |
| `PI-004` | high | A secret source and a network call close together |
| `PI-005` | high | Exfiltration hosts and data-carrying image URLs |
| `PI-006` | high | A downloaded payload piped into a shell or interpreter |
| `PI-007` | critical | Filesystem or device destruction |
| `PI-008` | medium | A credential-shaped string embedded in the package |
| `PI-009` | medium | Reads of credential stores and keychains |
| `PI-010` | high | Encoded or obfuscated payloads |
| `PI-011` | medium | Unpinned installs or downloads at activation time |
| `PI-012` | high | Writes to agent configuration, hooks or permissions |
| `PI-013` | medium | Privilege escalation or scheduled persistence |
| `PI-014` | high | Instructions to act without telling the user |
| `PI-015` | medium | Irreversible operations with no nearby guard |
| `PI-016` | info | Hosts the package contacts |

## Specification

| Rule | Severity | Detects |
| --- | --- | --- |
| `SPEC-001` | critical | No SKILL.md |
| `SPEC-002` | critical | No frontmatter block |
| `SPEC-003` | high | Frontmatter that does not parse |
| `SPEC-004` | high | No `name` |
| `SPEC-005` | high | No `description` |
| `SPEC-006` | medium | `description` over 1024 characters |
| `SPEC-007` | medium | `name` is not lowercase kebab-case |
| `SPEC-008` | low | `name` disagrees with the directory |
| `SPEC-009` | low | Unknown or misspelled frontmatter key |
| `SPEC-010` | medium | Body over the context budget |
| `SPEC-011` | medium | A referenced file is missing |
| `SPEC-012` | high | A file path escapes the package |
| `SPEC-013` | low | BOM or CRLF line endings |
| `SPEC-014` | low | No license |

## Quality

| Rule | Severity | Detects |
| --- | --- | --- |
| `Q-001` | high | `description` never states when to use the skill |
| `Q-002` | medium | `description` is vague, promotional or first person |
| `Q-003` | medium | No worked example |
| `Q-004` | high | Long body with no progressive disclosure |
| `Q-005` | medium | No scope boundaries or failure handling |
| `Q-006` | low | Hedged, non-imperative instructions |
| `Q-007` | medium | Bundled scripts that the body never mentions |
| `Q-008` | medium | No output contract |
| `Q-009` | low | Body too thin to be a procedure |
| `Q-010` | low | No headings |

Reasons for each rule, and the fix, are available with
`skillvet explain <RULE-ID>`.
