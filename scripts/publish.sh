#!/usr/bin/env bash
#
# Publish skillvet to your own GitHub account, in one command.
#
#   ./scripts/publish.sh                 # repo named after the directory
#   ./scripts/publish.sh my-skill-vet    # or pick a name
#   ./scripts/publish.sh --dry-run       # show what would happen, change nothing
#
# What it does:
#   1. Points every GitHub URL in the project at your account, so the badges,
#      the install commands and the workflow links all resolve for real.
#   2. Creates a git repository with a single initial commit.
#   3. Creates the GitHub repository and pushes, if the gh CLI is available and
#      authenticated. Otherwise it prints the two commands you need.
#
# Safety: step 1 edits text files. Nothing else in the project is touched, and
# the rewrite is a no-op if the URLs are already yours.

set -euo pipefail

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
    shift
fi

REPO_NAME="${1:-$(basename "$PWD")}"
DEFAULT_OWNER="skillvet"        # the placeholder org used in the source tree
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }

if [ ! -f "skillvet/cli.py" ]; then
    warn "Run this from the skillvet project root."
    exit 1
fi

# --- who are we publishing as? -----------------------------------------------
OWNER=""
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    OWNER="$(gh api user --jq .login 2>/dev/null || true)"
fi
if [ -z "$OWNER" ]; then
    OWNER="$(git config --get github.user 2>/dev/null || true)"
fi
if [ -z "$OWNER" ]; then
    OWNER="$(git config --get user.name 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d ' ' || true)"
fi
if [ -z "$OWNER" ] && [ "$DRY_RUN" -eq 0 ]; then
    read -r -p "GitHub username or organisation: " OWNER
fi
OWNER="${OWNER:-your-account}"

say "Publishing as ${OWNER}/${REPO_NAME}"

# --- 1. rewrite the placeholder URLs ----------------------------------------
FILES=$(grep -rl --include='*.md' --include='*.yml' --include='*.yaml' \
        --include='*.toml' --include='*.json' --include='*.sh' \
        -e "${DEFAULT_OWNER}/${DEFAULT_OWNER}" . 2>/dev/null | grep -v '^./.git/' || true)

if [ -z "$FILES" ]; then
    say "No placeholder URLs left to rewrite."
else
    COUNT=$(echo "$FILES" | wc -l | tr -d ' ')
    say "Rewriting GitHub URLs in ${COUNT} file(s)"
    echo "$FILES" | sed 's/^/    /'
    if [ "$DRY_RUN" -eq 0 ]; then
        echo "$FILES" | while IFS= read -r f; do
            [ -n "$f" ] || continue
            sed -i.bak \
                -e "s|github\.com/${DEFAULT_OWNER}/${DEFAULT_OWNER}|github.com/${OWNER}/${REPO_NAME}|g" \
                -e "s|${DEFAULT_OWNER}/${DEFAULT_OWNER}@|${OWNER}/${REPO_NAME}@|g" \
                -e "s|${DEFAULT_OWNER}/${DEFAULT_OWNER}/\.github|${OWNER}/${REPO_NAME}/.github|g" \
                "$f"
            rm -f "${f}.bak"
        done
        say "URLs rewritten."
    fi
fi

# --- 2. git repository -------------------------------------------------------
if [ "$DRY_RUN" -eq 1 ]; then
    say "Dry run: skipping git init, commit and push."
    exit 0
fi

if [ -d .git ]; then
    say "A git repository already exists; committing on top of it."
else
    say "Initialising the repository"
    git init -q -b main
fi

git add -A
if git diff --cached --quiet; then
    say "Nothing new to commit."
else
    git commit -q -m "skillvet 1.0.0 — vet agent skills before you install them

40 rules across spec compliance, quality and supply-chain risk for SKILL.md
packages. Zero dependencies.

- security scanner: prompt injection, hidden characters, exfiltration, piped
  remote execution, destructive commands, config tampering, suppressed
  confirmation
- spec checks: frontmatter, name/description, references, encoding, license
- quality checks: routing, examples, boundaries, output contract, structure
- verdicts (PASS/REVIEW/BLOCK), a 0-100 score, JSON/SARIF/Markdown output
- GitHub Action, pull-request review workflow, pre-commit hook, bundled skill
- 166 tests, three example packages, and a hostile fixture to prove it works"
    say "Committed."
fi

# --- 3. create and push ------------------------------------------------------
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    say "Creating ${OWNER}/${REPO_NAME} on GitHub"
    if gh repo view "${OWNER}/${REPO_NAME}" >/dev/null 2>&1; then
        warn "Repository already exists; pushing to it."
        git remote get-url origin >/dev/null 2>&1 || \
            git remote add origin "git@github.com:${OWNER}/${REPO_NAME}.git"
        git push -u origin main
    else
        gh repo create "${OWNER}/${REPO_NAME}" \
            --public \
            --source=. \
            --remote=origin \
            --description "Vet agent skills before you install them: spec compliance, quality and supply-chain risk for SKILL.md packages. Zero dependencies." \
            --push
    fi

    say "Suggested topics"
    cat <<TOPICS
    gh repo edit ${OWNER}/${REPO_NAME} \\
      --add-topic agent-skills --add-topic ai-agents --add-topic claude-code \\
      --add-topic codex --add-topic cursor --add-topic security \\
      --add-topic supply-chain --add-topic prompt-injection \\
      --add-topic static-analysis --add-topic skill-md --add-topic linter
TOPICS
    say "Done: https://github.com/${OWNER}/${REPO_NAME}"
else
    warn "The gh CLI is missing or not authenticated. Two commands and you are live:"
    cat <<MANUAL

    gh auth login                     # once, if you have gh installed
    # or create the repository by hand at https://github.com/new, then:
    git remote add origin https://github.com/${OWNER}/${REPO_NAME}.git
    git push -u origin main

MANUAL
fi
