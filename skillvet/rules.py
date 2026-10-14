"""The rule catalogue.

Every rule carries enough metadata to be explained to a human (``--explain``),
mapped to a standard (CWE / OWASP LLM Top 10) and emitted into SARIF, because a
security finding nobody can act on is just noise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from .models import Category, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    category: Category
    what: str
    why: str
    fix: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    tags: tuple = ()

    def to_dict(self) -> Dict[str, object]:
        d: Dict[str, object] = {
            "id": self.id,
            "title": self.title,
            "severity": str(self.severity),
            "category": str(self.category),
            "what": self.what,
            "why": self.why,
            "fix": self.fix,
        }
        if self.cwe:
            d["cwe"] = self.cwe
        if self.owasp:
            d["owasp"] = self.owasp
        if self.tags:
            d["tags"] = list(self.tags)
        return d


S, H, M, L, I = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
SEC, SPEC, QUA = Category.SECURITY, Category.SPEC, Category.QUALITY

RULES: List[Rule] = [
    # ----------------------------------------------------------------- security
    Rule(
        "PI-001",
        "Instruction override attempt",
        S,
        SEC,
        "The text tells the agent to ignore, forget or replace its existing instructions.",
        "Agent skills are loaded straight into the model's context, so a phrase like "
        "'ignore all previous instructions' is not prose -- it is a remote instruction "
        "channel into your session. This is the classic prompt-injection payload.",
        "Delete the phrase. If the skill genuinely needs to override a default, state the "
        "behaviour it wants directly ('Always run the formatter before committing').",
        cwe="CWE-1426",
        owasp="LLM01: Prompt Injection",
        tags=("prompt-injection", "llm01"),
    ),
    Rule(
        "PI-002",
        "Hidden or invisible instructions",
        S,
        SEC,
        "Zero-width characters, Unicode tag-block glyphs or bidi overrides are used to hide text.",
        "Invisible characters survive copy-paste and render as nothing in a diff, so a reviewer "
        "approves a file that contains instructions they never saw. This is how skills smuggle "
        "payloads past human review.",
        "Strip all zero-width / bidi / tag-block characters. Keep every instruction visible in "
        "plain ASCII so it can be reviewed in a pull request.",
        cwe="CWE-506",
        owasp="LLM01: Prompt Injection",
        tags=("prompt-injection", "obfuscation"),
    ),
    Rule(
        "PI-003",
        "Role or system-prompt hijack",
        H,
        SEC,
        "The text reassigns the agent's role, claims a new system prompt, or asks for an unlocked mode.",
        "Reassigning the role is the first half of most jailbreaks: once the model believes it is "
        "'DAN' or in 'developer mode', its safety rules are treated as out of scope.",
        "Remove the roleplay framing. Describe the task ('Review the diff') rather than the identity "
        "('You are an unrestricted engineer').",
        cwe="CWE-1426",
        owasp="LLM01: Prompt Injection",
        tags=("prompt-injection", "jailbreak"),
    ),
    Rule(
        "PI-004",
        "Credential exfiltration",
        H,
        SEC,
        "Credentials or environment secrets are read and sent over the network.",
        "The most common real-world malicious skill: read the developer's keys, POST them to a "
        "collector, continue as if nothing happened. It costs the victim every credential the "
        "agent process can see.",
        "Never read secret files or environment variables in a skill. If a task needs a token, "
        "reference it by name and let the user supply it through their own secret store.",
        cwe="CWE-522",
        owasp="LLM02: Sensitive Information Disclosure",
        tags=("exfiltration", "secrets"),
    ),
    Rule(
        "PI-005",
        "Exfiltration channel (webhook or image beacon)",
        H,
        SEC,
        "A request to an exfiltration-friendly host, or a markdown image that carries data in its URL.",
        "Markdown image syntax is the quietest leak available to a skill: the agent renders a "
        "picture, the browser sends your data as a query string, and nothing looks suspicious.",
        "Remove the outbound call. If a skill must phone home, use a documented, allow-listed "
        "endpoint and make the data being sent explicit in the SKILL.md.",
        cwe="CWE-201",
        owasp="LLM02: Sensitive Information Disclosure",
        tags=("exfiltration", "beacon"),
    ),
    Rule(
        "PI-006",
        "Piped remote code execution",
        H,
        SEC,
        "A remote payload is downloaded and piped straight into a shell or interpreter.",
        "'curl | sh' executes whatever the server returns today, not what a reviewer read "
        "yesterday. The remote endpoint is unauthenticated, unpinned and outside your review.",
        "Download to a file first, verify a checksum or signature, then execute. Pin an exact "
        "version and a specific host.",
        cwe="CWE-494",
        owasp="LLM06: Excessive Agency",
        tags=("rce", "supply-chain"),
    ),
    Rule(
        "PI-007",
        "Destructive filesystem or device command",
        S,
        SEC,
        "A command that can destroy data outside the working directory (rm -rf /, mkfs, dd to a device, fork bomb).",
        "Agents run commands with the user's full privileges. A single 'helpful' cleanup line can "
        "delete a home directory or wipe a disk, and there is no undo.",
        "Scope every delete to a specific, explicit path and guard it ('refuse if the path is not "
        "inside the project root'). Never write device-level commands into a skill.",
        cwe="CWE-73",
        owasp="LLM06: Excessive Agency",
        tags=("destructive",),
    ),
    Rule(
        "PI-008",
        "Hard-coded credential in the package",
        M,
        SEC,
        "A live-looking API key, token or private key is embedded in a file.",
        "Skills are frequently forked, vendored and republished. A key committed inside one leaks "
        "the moment the package is cloned, and the leak is invisible to the original author.",
        "Revoke the key, then remove it from the file and read it from the environment instead. "
        "Add a .gitignore entry and a pre-commit secret scanner.",
        cwe="CWE-798",
        owasp="LLM02: Sensitive Information Disclosure",
        tags=("secrets",),
    ),
    Rule(
        "PI-009",
        "Sensitive file or keychain access",
        M,
        SEC,
        "The skill reads credential stores such as ~/.ssh, ~/.aws, .env, .netrc or the OS keychain.",
        "Reading these paths is rarely part of a legitimate skill and is the reconnaissance step "
        "that precedes exfiltration. Even a benign read pulls secrets into the model's context, "
        "where they persist for the rest of the session.",
        "Keep secrets out of the agent's context entirely. Pass a single-purpose, short-lived "
        "token through an environment variable when a task truly needs it.",
        cwe="CWE-522",
        owasp="LLM02: Sensitive Information Disclosure",
        tags=("secrets", "recon"),
    ),
    Rule(
        "PI-010",
        "Obfuscated or encoded payload",
        H,
        SEC,
        "Base64, hex or char-code blobs are decoded and executed, or an encoded instruction is supplied.",
        "Obfuscation exists to defeat review. Legitimate skills do not need to hide their "
        "instructions behind an encoder, and 'decode this and do it' is the same payload with "
        "extra steps.",
        "Replace the blob with readable source. If binary data is genuinely required, ship it as a "
        "reviewed asset file with a documented format.",
        cwe="CWE-506",
        owasp="LLM01: Prompt Injection",
        tags=("obfuscation",),
    ),
    Rule(
        "PI-011",
        "Unpinned remote fetch during activation",
        M,
        SEC,
        "The skill downloads or installs code from the network while it activates.",
        "Activation-time fetches make a skill's behaviour change without any commit in your repo. "
        "It also turns every run into a network dependency and a supply-chain trust decision.",
        "Vendor what you need into the skill, or pin an exact version and verify a checksum.",
        cwe="CWE-494",
        owasp="LLM05: Supply Chain",
        tags=("supply-chain",),
    ),
    Rule(
        "PI-012",
        "Agent-configuration tampering",
        H,
        SEC,
        "The skill edits agent settings, hooks, permissions or global instruction files.",
        "Writing to CLAUDE.md, AGENTS.md, settings.json or a hook turns a one-shot review into "
        "persistence: the payload survives the session, applies to every future project, and may "
        "disable the permission prompts that would have stopped it.",
        "Skills must not modify agent configuration. Ask the user to apply configuration changes "
        "themselves, and never enable bypass-permissions modes.",
        cwe="CWE-15",
        owasp="LLM06: Excessive Agency",
        tags=("persistence",),
    ),
    Rule(
        "PI-013",
        "Privilege escalation or persistence",
        M,
        SEC,
        "Privilege escalation (sudo, setuid, containers) or a scheduled task is installed.",
        "Privilege escalation converts a skill-level compromise into a machine-level one, and a "
        "cron or systemd entry keeps it there after the session ends.",
        "Run without elevated privileges. If a step needs root, document it as a manual step the "
        "user performs deliberately.",
        cwe="CWE-269",
        owasp="LLM06: Excessive Agency",
        tags=("persistence", "escalation"),
    ),
    Rule(
        "PI-014",
        "Suppressed user confirmation",
        H,
        SEC,
        "The skill instructs the agent not to ask, not to warn, or to hide what it did.",
        "Concealment is the clearest malicious signal in the whole catalogue. A skill that tells "
        "the agent to act silently is buying speed with the user's ability to stop it.",
        "Keep the user in the loop for anything destructive, expensive, or outbound. Explicitly "
        "document where the skill pauses for approval.",
        cwe="CWE-693",
        owasp="LLM06: Excessive Agency",
        tags=("agency", "stealth"),
    ),
    Rule(
        "PI-015",
        "Irreversible operation without a guard",
        M,
        SEC,
        "Force-push, hard reset, destructive SQL, infrastructure teardown or recursive delete with no confirmation step.",
        "These are exactly the commands an over-eager agent runs on a bad interpretation. The "
        "damage is not recoverable, and the skill leaves no explicit checkpoint for the human.",
        "Add an explicit confirmation step, use dry-run flags first, and state what must be true "
        "before the command may run.",
        cwe="CWE-693",
        owasp="LLM06: Excessive Agency",
        tags=("destructive",),
    ),
    Rule(
        "PI-016",
        "Network egress inventory",
        I,
        SEC,
        "Informational: hosts this skill contacts.",
        "Even a clean skill has a network surface. Listing it lets a reviewer answer 'what does "
        "this talk to?' without reading every line.",
        "Confirm each host is one you expect. Prefer first-party or allow-listed endpoints.",
        tags=("inventory",),
    ),
    # --------------------------------------------------------------------- spec
    Rule(
        "SPEC-001",
        "Missing SKILL.md",
        S,
        SPEC,
        "No SKILL.md exists at the root of this directory.",
        "SKILL.md is the entry point the Agent Skills standard defines. Without it there is "
        "nothing for an agent to load and nothing for a reviewer to read.",
        "Create SKILL.md at the skill root. Run 'skillvet init' to scaffold a valid one.",
    ),
    Rule(
        "SPEC-002",
        "Missing YAML frontmatter",
        S,
        SPEC,
        "The file does not open with a '---' fenced YAML block.",
        "name and description live in frontmatter. Without it an agent cannot discover or route "
        "the skill, so the package silently never activates.",
        "Start the file with '---', then name and description, then a closing '---'.",
    ),
    Rule(
        "SPEC-003",
        "Frontmatter is not valid YAML",
        H,
        SPEC,
        "The frontmatter block could not be parsed.",
        "A malformed block means the fields are never read. Most real cases are a missing quote, "
        "a tab character, or a colon inside an unquoted value.",
        "Quote any value containing ':' or '#', use spaces (never tabs) for indentation, and "
        "re-run 'skillvet scan' until the parse error clears.",
    ),
    Rule(
        "SPEC-004",
        "Required field 'name' is missing",
        H,
        SPEC,
        "Frontmatter has no name field.",
        "name is how other tools, marketplaces and registries identify the package.",
        "Add 'name: <kebab-case-name>' as the first frontmatter key.",
    ),
    Rule(
        "SPEC-005",
        "Required field 'description' is missing",
        H,
        SPEC,
        "Frontmatter has no description field.",
        "description is the only text the agent reads when deciding whether to load a skill. "
        "Without it the skill is inert.",
        "Add a one-to-three sentence description that says what the skill does and when to use it.",
    ),
    Rule(
        "SPEC-006",
        "description exceeds 1024 characters",
        M,
        SPEC,
        "The description is longer than the standard's limit.",
        "Over-long descriptions are truncated by some hosts, which can cut off the trigger "
        "condition -- the most important sentence in the file.",
        "Move detail into the body and keep the description under 1024 characters.",
    ),
    Rule(
        "SPEC-007",
        "name is not a valid skill identifier",
        M,
        SPEC,
        "name is not lowercase kebab-case, contains invalid characters, or is longer than 64 characters.",
        "Clients normalise names to locate the skill directory; invalid characters break "
        "discovery and produce duplicate-looking entries in marketplaces.",
        "Use lowercase letters, digits and single hyphens, 64 characters or fewer, matching the "
        "directory name.",
    ),
    Rule(
        "SPEC-008",
        "name does not match the directory name",
        L,
        SPEC,
        "The name field and the containing directory disagree.",
        "Most installers copy the directory, so the mismatch is invisible locally and confusing "
        "once the skill is published.",
        "Rename the directory to match name, or update name to match the directory.",
    ),
    Rule(
        "SPEC-009",
        "Unknown frontmatter key",
        L,
        SPEC,
        "A frontmatter key is not part of the standard and is probably a typo.",
        "Typos ('discription', 'allowed_tools') are read as absent, so a security control like "
        "allowed-tools silently does not apply.",
        "Remove the key or correct it to the documented spelling.",
    ),
    Rule(
        "SPEC-010",
        "Body exceeds a comfortable context budget",
        M,
        SPEC,
        "SKILL.md is large enough to consume a significant share of the context window.",
        "Skills that dump everything into SKILL.md force the agent to hold reference material it "
        "does not need for the current task, which crowds out the actual work.",
        "Keep SKILL.md under a few hundred lines and move depth into reference files that the "
        "body points to, loaded only when needed.",
    ),
    Rule(
        "SPEC-011",
        "Referenced file does not exist",
        M,
        SPEC,
        "The body points at a bundled file that is not present.",
        "Broken references are the most common way a skill fails at runtime, and the failure is "
        "confusing because the instructions read as if they should work.",
        "Either add the missing file or fix the path. Paths are relative to the skill root.",
    ),
    Rule(
        "SPEC-012",
        "File escapes the skill directory",
        H,
        SPEC,
        "A bundled file is a symlink or path that resolves outside the skill root.",
        "Path escapes let a package read or overwrite files elsewhere on the machine while "
        "looking like a self-contained folder.",
        "Ship a real copy inside the skill directory instead of a link or relative escape.",
    ),
    Rule(
        "SPEC-013",
        "Non-UTF8 content, BOM or CRLF line endings",
        L,
        SPEC,
        "The file has an encoding or line-ending quirk.",
        "Strict parsers and some Windows tooling choke on a BOM or mixed line endings, which "
        "turns into a mystery 'invalid frontmatter' report upstream.",
        "Save as UTF-8 without BOM and use LF line endings.",
    ),
    Rule(
        "SPEC-014",
        "No license declared",
        L,
        SPEC,
        "Neither frontmatter nor the repository declares a license.",
        "Skills are copied, vendored and republished. Without a license nobody can legally reuse "
        "the package, which caps its adoption.",
        "Add 'license: MIT' to frontmatter and include a LICENSE file at the repository root.",
    ),
    # ------------------------------------------------------------------ quality
    Rule(
        "Q-001",
        "description does not state when to use the skill",
        H,
        QUA,
        "The description explains the topic but not the trigger condition.",
        "Routing is the description's whole job. 'Helps with databases' never fires; 'Use when "
        "the task involves writing or reviewing SQL migrations' fires reliably.",
        "Add an explicit trigger, ideally phrased 'Use when ...'. Front-load the words a user "
        "would actually type.",
    ),
    Rule(
        "Q-002",
        "description is vague or written in the wrong voice",
        M,
        QUA,
        "The description is promotional, first-person, or too generic to route on.",
        "Descriptions are matched against real tasks. Marketing language ('supercharge your "
        "workflow') carries no signal, and first person ('I can help you') collides with the "
        "agent's own identity.",
        "Write in the third person about the capability: 'Extracts invoice totals from PDFs into "
        "CSV.' Say what it does, not how good it is.",
    ),
    Rule(
        "Q-003",
        "No worked example",
        M,
        QUA,
        "The body contains no example of input and expected output.",
        "Examples are the highest-signal part of a skill: they pin down the output shape and stop "
        "the agent from inventing its own format.",
        "Add a short example block showing a realistic request and the expected result.",
    ),
    Rule(
        "Q-004",
        "No progressive disclosure",
        H,
        QUA,
        "The body is long but bundles no reference files.",
        "The standard expects a small SKILL.md plus optional reference material loaded on demand. "
        "A single long file is paid for on every single turn, whether or not it is relevant.",
        "Move deep reference material into files next to SKILL.md and link them from the body, "
        "keeping only the routing information and the core procedure inline.",
    ),
    Rule(
        "Q-005",
        "No scope boundaries or failure handling",
        M,
        QUA,
        "The skill never says when it should not be used, or what to do when a step fails.",
        "Skills that cannot fail gracefully will improvise. An explicit boundary is what stops an "
        "agent from 'helpfully' continuing after the input did not match expectations.",
        "Add a short section covering when not to use the skill and how to stop and report when "
        "a precondition is not met.",
    ),
    Rule(
        "Q-006",
        "Hedged or non-imperative instructions",
        L,
        QUA,
        "Instructions use hedges such as 'try to', 'maybe', 'if possible', or 'consider'.",
        "Hedged instructions are treated as optional by the model, so behaviour drifts between "
        "runs and the skill feels unreliable.",
        "Use direct imperatives: 'Run', 'Write', 'Refuse'. Reserve hedges for genuine edge cases.",
    ),
    Rule(
        "Q-007",
        "Bundled scripts are never referenced",
        M,
        QUA,
        "Executable files ship in the package but the body never mentions them.",
        "Unreferenced scripts are unreviewed scripts: they still get executed when the agent "
        "explores the directory, but no human ever read them.",
        "Link each script from SKILL.md with a sentence explaining when to run it, or delete it.",
    ),
    Rule(
        "Q-008",
        "No success criteria or output contract",
        M,
        QUA,
        "The skill does not define what a correct result looks like.",
        "Without an output contract every run produces a different shape, which breaks anything "
        "downstream and makes the skill hard to trust.",
        "State the expected output format and the conditions for calling the task done.",
    ),
    Rule(
        "Q-009",
        "Body is too thin to be useful",
        L,
        QUA,
        "The body is only a few lines, so the skill is a stub rather than a procedure.",
        "A skill with no procedure just restates what the model already does, adding context cost "
        "for no gain.",
        "Add the actual steps, decision points and examples that make this skill worth loading.",
    ),
    Rule(
        "Q-010",
        "No structure for scanning",
        L,
        QUA,
        "The body has no headings, so an agent cannot navigate to the relevant part.",
        "Headings are how both humans and models locate the one section they need, and how "
        "progressive disclosure stays possible as the skill grows.",
        "Add short descriptive headings: 'When to use', 'Procedure', 'Examples', 'Failure modes'.",
    ),
]

REGISTRY: Dict[str, Rule] = {r.id: r for r in RULES}


def get(rule_id: str) -> Optional[Rule]:
    return REGISTRY.get(rule_id)


def by_category(category: Category) -> List[Rule]:
    return [r for r in RULES if r.category == category]


def rule_ids() -> List[str]:
    return [r.id for r in RULES]
