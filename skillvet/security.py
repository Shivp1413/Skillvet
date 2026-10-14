"""Security analysis for skill packages.

Design notes
------------
* **Context matters.** A phrase inside a fenced code block is usually a sample or
  a config; the same phrase in prose is a live instruction to the model. Rules
  declare where they apply, and findings from prose are ranked higher.
* **Combination beats single tokens.** Reading a secret is suspicious. Reading a
  secret *and* posting it to an unknown host is a finding. Multi-signal rules use
  a line window instead of one regex, which is what keeps the false-positive rate
  low enough for people to leave the tool switched on.
* **False positives are handled with suppression, not by weakening rules.** Both
  inline comments and a .skillvetignore file are supported, and every finding can
  be explained with `skillvet rules --explain`.
"""

from __future__ import annotations

import base64
import re
from typing import Dict, Iterable, List, Optional, Tuple

from .models import Capability, Category, Finding, Severity, Skill
from .rules import get as get_rule

# --------------------------------------------------------------------- helpers

INVISIBLE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff"
    "\u00ad\u034f\u17b4\u17b5\U000e0000-\U000e007f]"
)

FENCE = re.compile(r"^\s*(```|~~~)")

SUPPRESS_INLINE = re.compile(
    r"skillvet:\s*(?P<scope>ignore-file|ignore-next-line|ignore)\b"
    r"\s*(?P<rules>(?:[A-Za-z]{2,8}-\d{1,4})(?:\s*,\s*[A-Za-z]{2,8}-\d{1,4})*)?",
    re.IGNORECASE,
)


def _line_is_code(lines: List[str]) -> List[bool]:
    """Return a per-line flag: True when the line sits inside a fenced block."""
    flags: List[bool] = []
    inside = False
    fence_token = ""
    for line in lines:
        m = FENCE.match(line)
        if m:
            token = m.group(1)
            if not inside:
                inside, fence_token = True, token
            elif token == fence_token:
                inside, fence_token = False, ""
            flags.append(inside)
            continue
        flags.append(inside)
    return flags


def _suppressions(lines: List[str]) -> Tuple[set, Dict[int, set]]:
    """Collect file-wide and per-line rule suppressions."""
    file_wide: set = set()
    per_line: Dict[int, set] = {}
    for idx, line in enumerate(lines, start=1):
        for m in SUPPRESS_INLINE.finditer(line):
            scope = m.group("scope").lower()
            rules = {r.strip().upper() for r in m.group("rules").split(",") if r.strip()}
            rules = {r for r in rules if r} or {"*"}
            if scope == "ignore-file":
                file_wide |= rules
            elif scope == "ignore-next-line":
                per_line.setdefault(idx + 1, set()).update(rules)
            else:
                per_line.setdefault(idx, set()).update(rules)
    return file_wide, per_line


def _snippet(line: str, limit: int = 160) -> str:
    clean = INVISIBLE.sub("", line).strip()
    clean = re.sub(r"\s+", " ", clean)
    if len(clean) > limit:
        clean = clean[: limit - 1] + "\u2026"
    return clean


def _redact(match: str) -> str:
    if len(match) <= 8:
        return "*" * len(match)
    return match[:4] + "\u2026" + match[-3:]


# ------------------------------------------------------------------- patterns

Pattern = Dict[str, object]


def _p(rule: str, regex: str, where: str = "any", flags: int = re.IGNORECASE,
       note: str = "") -> Pattern:
    return {
        "rule": rule,
        "regex": re.compile(regex, flags | re.MULTILINE),
        "where": where,
        "note": note,
    }


INSTRUCTION_OVERRIDE = [
    r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|above|preceding|foregoing)\s+(?:instructions?|prompts?|rules?|context|messages?)",
    r"disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|above|preceding)\s+(?:instructions?|prompts?|rules?)",
    r"forget\s+(?:everything|all|your)\s+(?:you\s+know|previous|prior|instructions?|rules?)",
    r"override\s+(?:your\s+|the\s+)?(?:system\s+prompt|instructions?|safety|guardrails?|restrictions?)",
    r"(?:new|updated|revised)\s+(?:system\s+)?instructions?\s*[:>]",
    r"your\s+(?:real|true|actual)\s+(?:task|instructions?|goal)\s+is",
]

ROLE_HIJACK = [
    r"you\s+are\s+now\s+(?:a|an|the|in)\b",
    r"(?:enter|enable|activate)\s+(?:developer|debug|god|unrestricted|jailbreak|dan)\s*mode",
    r"\bDAN\s+mode\b",
    r"(?:pretend|imagine|assume)\s+(?:that\s+)?you\s+(?:have\s+no|are\s+not\s+bound|ignore)",
    r"(?:bypass|disable|turn\s+off)\s+(?:your\s+)?(?:safety|guardrails?|filters?|restrictions?|alignment)",
    r"without\s+any\s+(?:ethical\s+)?(?:restrictions?|limitations?|filters?)",
]

SUPPRESS_CONFIRMATION = [
    r"(?:do\s+not|don'?t|never)\s+(?:ask|prompt|wait)\s+(?:the\s+)?(?:user\s+)?for\s+(?:confirmation|permission|approval)",
    r"(?:without|skip|bypass|no)\s+(?:asking|confirming|confirmation|permission|approval|prompting)",
    r"(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|warn|mention\s+(?:it\s+)?to)\s+(?:the\s+)?user",
    r"(?:silently|quietly|secretly|covertly|without\s+telling)\b",
    r"hide\s+(?:this|it|what\s+you|your\s+(?:actions|changes))\s+from",
    r"(?:auto|always)[\s-]?approve\b",
    r"--dangerously-skip-permissions",
    r"bypassPermissions",
]

# Destructive at the filesystem or device level. Note the target alternation
# handles the "~/" spelling, which is how home directories are actually written.
RM_TARGET = r"(?:~/?|\$HOME/?|/(?:\s|$|\*)|\*)"
DESTRUCTIVE = [
    r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*[fF][a-zA-Z]*\s+" + RM_TARGET,
    r"\brm\s+-[a-zA-Z]*[fF][a-zA-Z]*[rR][a-zA-Z]*\s+" + RM_TARGET,
    r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+-[a-zA-Z]*[fF][a-zA-Z]*\s+" + RM_TARGET,
    r"\bmkfs(?:\.\w+)?\b",
    r"\bdd\s+if=\S+\s+of=/dev/",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
    r"chmod\s+-R\s+0?777\s+/(?:\s|$)",
    r"\b(?:shred|wipefs)\b[^\n]*(?:/dev/|/home|/var)",
    r">\s*/dev/sd[a-z]\b",
]

# Irreversible but scoped to a repository, database or cloud resource. Handled
# by PI-015, which also checks whether a confirmation step is nearby.
IRREVERSIBLE = [
    r"git\s+push\s+(?:--force\b|-f\b|--force-with-lease\b)",
    r"git\s+reset\s+--hard\b",
    r"git\s+clean\s+-[a-zA-Z]*[fdx][a-zA-Z]*\b",
    r"\bterraform\s+(?:destroy|apply\s+-auto-approve)\b",
    r"\bkubectl\s+delete\s+(?:ns|namespace|all|pv)\b",
    r"\bdrop\s+(?:database|schema|table)\b",
    r"\btruncate\s+table\b",
    r"\bDELETE\s+FROM\s+\w+\s*;",
    r"\baws\s+s3\s+rb\b[^\n]*--force",
]

PIPED_EXEC = [
    r"(?:curl|wget|fetch)\b[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba|z|k|fi)?sh\b",
    r"(?:curl|wget)\b[^\n|;&]*\|\s*(?:sudo\s+)?(?:python3?|node|deno|bun|php|perl|ruby)\b",
    r"(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|;&]*\|\s*(?:iex|invoke-expression)",
    r"\beval\s*\(?\s*(?:base64\s+-d|atob|Buffer\.from)",
    r"\bbash\s+<\(\s*(?:curl|wget)",
]

HOME_PREFIX = (
    r"(?:~|\$HOME|\$\{HOME\}|Path\.home\(\)\s*/\s*['\"]|expanduser\(\s*['\"]~)"
    r"\s*/?\s*['\"]?"
)


def _home(name: str) -> str:
    """A credential store inside the user's home directory, however it is spelled."""
    return HOME_PREFIX + name


SECRET_PATHS = [
    _home(r"\.ssh\b"),
    _home(r"\.aws(?:/|\b)"),
    _home(r"\.netrc\b"),
    _home(r"\.npmrc\b"),
    _home(r"\.git-credentials\b"),
    _home(r"\.docker/config\.json"),
    _home(r"\.kube/config\b"),
    _home(r"\.gnupg\b"),
    _home(r"\.config/gh/hosts\.yml"),
    _home(r"\.config/(?:gcloud|aws)\b"),
    _home(r"Library/Application Support/(?:Google/Chrome|Firefox)"),
    r"\bid_rsa\b",
    r"\bid_ed25519\b",
    r"(?:^|[\s'\"=])\.env(?:\.[a-z]+)?\b(?!\w)",
    r"(?:Login\s+Data|Cookies|cookies\.sqlite|login\.keychain|Login\.keychain)",
    r"security\s+find-(?:generic|internet)-password",
]


SECRET_ENV = [
    r"\$\{?(?:ANTHROPIC|OPENAI|AWS|AZURE|GCP|GOOGLE|GITHUB|GH|HUGGINGFACE|HF|STRIPE|TWILIO|SLACK|DISCORD|DATABASE|DB|MAILGUN|SENDGRID)_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIALS?)\}?",
    r"\$\{?(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|PASSWORD|PASSWD|TOKEN)\}?",
    r"\bprintenv\b",
    r"\benv\s*\|\s*(?:grep|curl|sort|base64)",
    r"(?:cat|read|source)\s+[^\n]*\.env\b",
]

NETWORK = [
    r"\bcurl\b", r"\bwget\b", r"\bhttpie\b|\bhttp\s+(?:GET|POST)\b",
    r"\bfetch\s*\(", r"\brequests\.(?:get|post|put|patch)\b", r"\burllib\b",
    r"\baxios\.", r"\bInvoke-WebRequest\b", r"\bnc\s+-", r"\bnetcat\b",
    r"\bsocket\.socket\b", r"\bhttps?://",
]

EXFIL_HOSTS = [
    r"webhook\.site", r"requestbin", r"pipedream\.net", r"\.ngrok\.(?:io|free|app)",
    r"interact\.sh", r"oast\.(?:fun|live|online|site|me|pro)", r"burpcollaborator",
    r"canarytokens", r"dnslog\.cn", r"beeceptor\.com", r"hookbin\.com",
    r"transfer\.sh", r"0x0\.st", r"termbin\.com", r"pastebin\.com/raw",
]

BEACON_IMAGE = re.compile(
    r"!\[[^\]]*\]\(\s*https?://[^)\s]+[?&][^)\s]*(?:\$\{|\{\{|%s|<%|\+|\bdata\b|\btoken\b|\bkey\b|\bsecret\b|\bpayload\b)",
    re.IGNORECASE,
)

OBFUSCATION = [
    r"(?:echo|printf)\s+['\"]?[A-Za-z0-9+/]{80,}={0,2}['\"]?\s*\|\s*base64\s+-d",
    r"base64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:ba|z)?sh\b",
    r"atob\s*\(",
    r"String\.fromCharCode\s*\(",
    r"(?:exec|eval)\s*\(\s*(?:bytes\.fromhex|bytearray\.fromhex|codecs\.decode)",
    r"(?:\\x[0-9a-fA-F]{2}){6,}",
    r"codecs\.decode\([^)]*['\"]rot13",
]

CONFIG_TAMPER = [
    r"~(?:/\.claude\.json|/)\.claude/settings(?:\.local)?\.json",
    r"\.claude/settings(?:\.local)?\.json",
    r"~/\.codex/config\.(?:toml|json)",
    r"~/\.cursor/(?:mcp\.json|settings\.json)",
    r"\.mcp\.json\b",
    r"\bCLAUDE\.md\b", r"\bAGENTS\.md\b", r"\bGEMINI\.md\b",
    r"\.claude/(?:hooks|plugins|agents)\b",
    r"(?:write|append|add|modify|edit|update)\s+[^\n]{0,40}(?:settings\.json|hooks?|permissions?)",
    r"\bkubectl\s+config\s+view\b",
]

PRIVILEGE = [
    r"\bsudo\b", r"\bdoas\b", r"\bsetcap\b", r"chmod\s+(?:u\+s|4[0-7]{3})\b",
    r"\bnsenter\b", r"docker\s+run[^\n]*--privileged", r"docker\s+run[^\n]*-v\s*/:/",
    r"\bcrontab\b", r"launchctl\s+(?:load|bootstrap)", r"systemctl\s+(?:enable|start)",
    r"~/\.(?:bashrc|zshrc|profile|bash_profile)\b", r"/etc/(?:cron\.\w+|sudoers|passwd)",
    r"export\s+PATH=", r"\busermod\b", r"\bchown\s+-R\s+root",
]

INSTALLS = [
    r"\bpip3?\s+install\b", r"\bnpm\s+(?:i|install|ci)\b", r"\bpipx\s+install\b",
    r"\buv\s+(?:pip\s+)?(?:add|install)\b", r"\bcargo\s+install\b", r"\bgo\s+install\b",
    r"\bbrew\s+install\b", r"\bapt(?:-get)?\s+install\b", r"\bapk\s+add\b",
    r"\bgit\s+clone\b", r"\bnpx\s+(?!-)", r"\bdocker\s+pull\b",
    r"--index-url|--extra-index-url|--trusted-host",
]

CREDENTIAL_STRING = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"sk-ant-api03-[A-Za-z0-9_\-]{20,}"
    r"|sk-(?:proj|live|test)?-?[A-Za-z0-9]{32,}"
    r"|gh[pousr]_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{30,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_\-]{35}"
    r"|xox[baprs]-[A-Za-z0-9\-]{10,}"
    r"|glpat-[A-Za-z0-9_\-]{20,}"
    r"|hf_[A-Za-z0-9]{30,}"
    r"|r8_[A-Za-z0-9]{30,}"
    r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
    r"|-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
    r"|(?:api[_-]?key|apikey|secret|passwd|password|token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-/+]{24,}['\"]"
    r")",
    re.IGNORECASE,
)

# A file may legitimately *quote* an attack in order to warn about it, or ship a
# detection rule. These cues downgrade such a match instead of dropping it, so a
# human still sees it.
NEGATION_CUES = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s+not|avoid|refuse|reject|rejecting|malicious|"
    r"attacker|prompt\s+injection|injection|untrusted|example\s+of|for\s+example|"
    r"bad\s+example|anti-?pattern|instead\s+of|flag|detect|scanner|scans?\s+for|"
    r"warning|unlike|contrast|as\s+opposed\s+to|should\s+not|is\s+not\s+allowed|"
    r"forbidden|test\s+fixture|known\s+bad)\b",
    re.IGNORECASE,
)

# Stricter cue set for PI-014: 'do not ask...' and 'never tell...' are the
# payload itself, so generic negation words must not downgrade them. Only
# explicit "this is an example of an attack" framing counts.
STRICT_NEGATION_CUES = re.compile(
    r"(?:malicious|attacker|attack\s+pattern|anti-?pattern|bad\s+example|"
    r"prompt\s+injection|known\s+bad|test\s+fixture|example\s+of\s+(?:a|an|the)\s+"
    r"(?:attack|malicious|hostile|bad)|we\s+never|skills?\s+must\s+not)",
    re.IGNORECASE,
)


# ------------------------------------------------------------------- the scan


class SecurityScanner:
    """Scans the text of a skill package for malicious or risky instructions."""

    def __init__(self, ignore: Optional[Iterable[str]] = None) -> None:
        self.ignore = {i.upper() for i in (ignore or [])}
        self.patterns: List[Pattern] = []
        for rule_id, pats in (
            ("PI-001", INSTRUCTION_OVERRIDE),
            ("PI-003", ROLE_HIJACK),
            ("PI-014", SUPPRESS_CONFIRMATION),
            ("PI-007", DESTRUCTIVE),
            ("PI-006", PIPED_EXEC),
            ("PI-010", OBFUSCATION),
            ("PI-012", CONFIG_TAMPER),
            ("PI-013", PRIVILEGE),
        ):
            for rx in pats:
                where = "prose" if rule_id in ("PI-001", "PI-003", "PI-014") else "any"
                self.patterns.append(_p(rule_id, rx, where=where))
        # Rules that are safe anywhere but only meaningful in prose.
        for rx in EXFIL_HOSTS:
            self.patterns.append(_p("PI-005", rx, where="any"))
        for rx in SECRET_PATHS:
            self.patterns.append(_p("PI-009", rx, where="any"))
        for rx in INSTALLS:
            self.patterns.append(_p("PI-011", rx, where="any"))

    # -- public API --------------------------------------------------------

    def scan_text(
        self,
        text: str,
        path: str,
        file_wide: Optional[set] = None,
        per_line: Optional[Dict[int, set]] = None,
        treat_all_as_code: bool = False,
    ) -> List[Finding]:
        """Scan one file's text.

        ``treat_all_as_code`` is used for bundled scripts and config files: there
        are no markdown fences to reason about, and prose-only rules (which target
        instructions aimed at the model) do not apply to source code.
        """
        lines = text.splitlines()
        code_flags = [True] * len(lines) if treat_all_as_code else _line_is_code(lines)
        file_wide = set(file_wide or set())
        per_line = per_line or {}
        findings: List[Finding] = []
        seen: set = set()

        def suppressed(rule_id: str, lineno: int) -> bool:
            if rule_id in self.ignore or rule_id in file_wide:
                return True
            marks = per_line.get(lineno, set())
            return "*" in marks or rule_id in marks

        for pat in self.patterns:
            rule_id = str(pat["rule"])
            if rule_id in self.ignore or rule_id in file_wide:
                continue
            rule = get_rule(rule_id)
            if rule is None:  # pragma: no cover - defensive
                continue
            regex: re.Pattern = pat["regex"]  # type: ignore[assignment]
            where = pat["where"]
            for idx, line in enumerate(lines, start=1):
                if suppressed(rule_id, idx):
                    continue
                if where == "prose" and treat_all_as_code:
                    # A shell or Python file does not address the model, so an
                    # instruction-shaped string in it is not an injection vector.
                    continue
                m = regex.search(line)
                if not m:
                    continue
                # One finding per rule per line: several patterns in the same rule
                # often match the same line, and repeating it adds noise, not signal.
                key = (rule_id, idx)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    self._make(rule_id, line, path, idx, code_flags[idx - 1], lines)
                )

        findings.extend(self._hidden_characters(lines, path, suppressed))
        findings.extend(self._credentials(lines, path, code_flags, suppressed))
        findings.extend(self._beacons(lines, path, code_flags, suppressed))
        findings.extend(self._combination_rules(lines, path, code_flags, suppressed))
        return findings

    # -- individual detections --------------------------------------------

    def _make(
        self,
        rule_id: str,
        line: str,
        path: str,
        lineno: int,
        in_code: bool,
        lines: List[str],
    ) -> Finding:
        rule = get_rule(rule_id)
        assert rule is not None
        severity = rule.severity
        note = ""
        if in_code and rule_id in ("PI-001", "PI-003", "PI-014"):
            severity = Severity.MEDIUM if severity is Severity.HIGH else Severity.MEDIUM
            note = " Found inside a fenced code block, so it may be sample text."
        # Negation context: the file may be *warning about* this very pattern.
        window = " ".join(lines[max(0, lineno - 3) : lineno + 1])
        cues = STRICT_NEGATION_CUES if rule_id == "PI-014" else NEGATION_CUES
        if rule_id in ("PI-001", "PI-003", "PI-014", "PI-005") and cues.search(window):
            severity = Severity.LOW
            note = (
                " A negation or warning cue appears nearby, so this may be a documented "
                "anti-pattern rather than a live instruction. Verify before acting on it."
            )
        return Finding(
            rule_id=rule_id,
            severity=severity,
            category=Category.SECURITY,
            title=rule.title,
            message=rule.what + note,
            file=path,
            line=lineno,
            snippet=_snippet(line),
            remediation=rule.fix,
            cwe=rule.cwe,
            owasp=rule.owasp,
            in_code=in_code,
        )

    def _hidden_characters(self, lines, path, suppressed) -> List[Finding]:
        if suppressed("PI-002", 0):
            return []
        rule = get_rule("PI-002")
        assert rule is not None
        out: List[Finding] = []
        for idx, line in enumerate(lines, start=1):
            hits = INVISIBLE.findall(line)
            if not hits:
                continue
            names = sorted({f"U+{ord(c):04X}" for c in hits})
            out.append(
                Finding(
                    rule_id="PI-002",
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    title=rule.title,
                    message=(
                        f"{len(hits)} invisible character(s) found "
                        f"({', '.join(names[:6])}{'...' if len(names) > 6 else ''}). "
                        "They render as nothing but are read by the model."
                    ),
                    file=path,
                    line=idx,
                    snippet=_snippet(line[:120]) or "<line contains only invisible characters>",
                    remediation=rule.fix,
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                )
            )
        return out

    def _credentials(self, lines, path, code_flags, suppressed) -> List[Finding]:
        out: List[Finding] = []
        rule = get_rule("PI-008")
        assert rule is not None
        for idx, line in enumerate(lines, start=1):
            if suppressed("PI-008", idx):
                continue
            for m in CREDENTIAL_STRING.finditer(line):
                raw = m.group(0)
                if "PRIVATE KEY" in raw.upper():
                    detail = "an embedded private key block"
                else:
                    detail = f"a credential-shaped string ({_redact(raw)})"
                out.append(
                    Finding(
                        rule_id="PI-008",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        title=rule.title,
                        message=f"The file contains {detail}.",
                        file=path,
                        line=idx,
                        snippet=_snippet(line.replace(raw, _redact(raw))),
                        remediation=rule.fix,
                        cwe=rule.cwe,
                        owasp=rule.owasp,
                        in_code=code_flags[idx - 1],
                    )
                )
                break
        return out

    def _beacons(self, lines, path, code_flags, suppressed) -> List[Finding]:
        if suppressed("PI-005", 0):
            return []
        out: List[Finding] = []
        rule = get_rule("PI-005")
        assert rule is not None
        for idx, line in enumerate(lines, start=1):
            if suppressed("PI-005", idx):
                continue
            if BEACON_IMAGE.search(line):
                out.append(
                    Finding(
                        rule_id="PI-005",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        title="Data-carrying image beacon",
                        message=(
                            "A markdown image URL appears to interpolate data into the query "
                            "string. Rendering the image transmits that data to a third party."
                        ),
                        file=path,
                        line=idx,
                        snippet=_snippet(line),
                        remediation=rule.fix,
                        cwe=rule.cwe,
                        owasp=rule.owasp,
                        in_code=code_flags[idx - 1],
                    )
                )
        return out

    def _combination_rules(self, lines, path, code_flags, suppressed) -> List[Finding]:
        """Rules that need two signals in the same neighbourhood."""
        out: List[Finding] = []
        window = 8

        secret_rx = [re.compile(p, re.IGNORECASE) for p in SECRET_PATHS + SECRET_ENV]
        net_rx = [re.compile(p, re.IGNORECASE) for p in NETWORK]

        secret_lines = [
            i for i, line in enumerate(lines) if any(rx.search(line) for rx in secret_rx)
        ]
        net_lines = [i for i, line in enumerate(lines) if any(rx.search(line) for rx in net_rx)]

        beacon_lines = {
            idx for idx, line in enumerate(lines) if BEACON_IMAGE.search(line)
        }
        if not suppressed("PI-004", 0):
            rule = get_rule("PI-004")
            assert rule is not None
            reported = set()
            for s in secret_lines:
                if s in beacon_lines:
                    continue  # PI-005 already reports this line with more detail
                for n in net_lines:
                    if abs(s - n) <= window:
                        bucket = s // window
                        if bucket in reported:
                            continue
                        reported.add(bucket)
                        line = lines[s]
                        out.append(
                            Finding(
                                rule_id="PI-004",
                                severity=Severity.HIGH,
                                category=Category.SECURITY,
                                title=rule.title,
                                message=(
                                    "A secret source and a network call appear within "
                                    f"{window} lines of each other (secret on line {s + 1}, "
                                    f"network on line {n + 1}). Verify that no credential is "
                                    "leaving the machine."
                                ),
                                file=path,
                                line=s + 1,
                                snippet=_snippet(line),
                                remediation=rule.fix,
                                cwe=rule.cwe,
                                owasp=rule.owasp,
                                in_code=code_flags[s],
                            )
                        )
                        break

        # PI-015: irreversible op with no nearby guard.
        if not suppressed("PI-015", 0):
            guard = re.compile(
                r"(?:confirm|ask\s+the\s+user|before\s+you\s+(?:run|delete|push)|"
                r"dry[\s-]?run|requires\s+approval|do\s+not\s+run\s+unless|guard)",
                re.IGNORECASE,
            )
            rule = get_rule("PI-015")
            assert rule is not None
            seen_rules = set()
            for rx in IRREVERSIBLE:
                pat = re.compile(rx, re.IGNORECASE)
                for idx, line in enumerate(lines):
                    if "PI-015" in seen_rules or not pat.search(line):
                        continue
                    nearby = "\n".join(lines[max(0, idx - 4) : idx + 4])
                    if guard.search(nearby):
                        continue
                    seen_rules.add("PI-015")
                    out.append(
                        Finding(
                            rule_id="PI-015",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            title=rule.title,
                            message=(
                                "An irreversible operation ('"
                                + pat.search(line).group(0)  # type: ignore[union-attr]
                                + "') appears with no confirmation or dry-run step nearby."
                            ),
                            file=path,
                            line=idx + 1,
                            snippet=_snippet(line),
                            remediation=rule.fix,
                            cwe=rule.cwe,
                            owasp=rule.owasp,
                            in_code=code_flags[idx],
                        )
                    )
        return out

    # -- capabilities ------------------------------------------------------

    def capabilities(self, text: str, path: str, line_offset: int = 0) -> List[Capability]:
        """Inventory of what the skill asks the agent to do (informational).

        ``line_offset`` maps positions back to the original file when only the
        body of a document is being scanned.
        """
        caps: List[Capability] = []
        groups = [
            ("exec", [r"\bbash\b", r"\bsh\s+-c\b", r"\bsubprocess\b", r"os\.system", r"\bexec\s*\(", r"\|\s*(?:ba)?sh\b", r"npm\s+run\b", r"make\s+\w+"]),
            ("network", NETWORK),
            ("read_secret", SECRET_PATHS + SECRET_ENV),
            ("install", INSTALLS),
            ("write", [r"\bwrite_text\b", r">\s*\S+\.(?:json|md|txt|py|ts)", r"\bsave\b.*\bfile\b", r"\btee\b\s"]),
            ("privilege", PRIVILEGE),
            ("persist", CONFIG_TAMPER + [r"\bcrontab\b", r"systemctl\s+enable", r"launchctl\s+load"]),
            ("destructive", DESTRUCTIVE + IRREVERSIBLE),
        ]
        seen = set()
        for kind, pats in groups:
            for rx in pats:
                pat = re.compile(rx, re.IGNORECASE)
                for idx, line in enumerate(text.splitlines(), start=1):
                    m = pat.search(line)
                    if not m:
                        continue
                    detail = m.group(0).strip()
                    key = (kind, detail.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    caps.append(
                        Capability(
                            kind=kind,
                            detail=detail,
                            file=path,
                            line=idx + line_offset,
                        )
                    )
                    break
        return caps


def scan_ignore_file(root: str) -> set:
    """Read .skillvetignore from a skill root, if present."""
    import os

    out: set = set()
    for candidate in (".skillvetignore", ".skillvetignore"):
        path = os.path.join(root, candidate)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.split("#", 1)[0].strip()
                    if line:
                        out.add(line.upper())
        except OSError:  # pragma: no cover - defensive
            pass
    return out


def scan_suppressions(text: str) -> Tuple[set, Dict[int, set]]:
    return _suppressions(text.splitlines())


# ------------------------------------------------------------------- base64
# A short helper used by the self-test: it proves the obfuscation rule fires on
# content that is only meaningful once decoded.
def looks_like_base64_payload(text: str, min_len: int = 36) -> Optional[str]:
    for token in re.findall(r"[A-Za-z0-9+/]{%d,}={0,2}" % min_len, text):
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        except Exception:
            continue
        if decoded and all(32 <= b < 127 or b in (9, 10, 13) for b in decoded):
            return decoded.decode("ascii", "replace")
    return None


def skill_level_ignore(skill: Skill) -> set:
    return scan_ignore_file(skill.root)
