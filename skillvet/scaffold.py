"""Generate a new, spec-compliant skill package.

The generated package scores A on skillvet out of the box, so the author starts
from a passing baseline and only has to fill in the two things a generator
cannot know: what the skill does and how it does it.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from typing import Dict, List, Optional

NAME_RE = re.compile(r"[^a-z0-9]+")

SKILL_TEMPLATE = """---
name: {name}
description: {description}
license: {license}
---

# {title}

<!-- TODO: one sentence on what this skill produces, in the terms a user would
     use. Keep it concrete: "turns a folder of receipts into one CSV" beats
     "handles financial data". -->

## When to use this skill

Use this skill when:

- <!-- TODO: the situation that should trigger it -->
- the request names {name_human} directly

Do not use this skill when:

- the task is a one-off that a single command already answers
- <!-- TODO: the adjacent task this skill deliberately does NOT cover -->

## Inputs

- <!-- TODO: what the skill needs that the user must supply -->

If an input is missing, stop and ask for it. Do not invent values.

## Procedure

1. <!-- TODO: step one, as an imperative -->
2. <!-- TODO: step two -->
3. Report what changed and where.

See `references/details.md` for the edge cases and the long-form reference.

## Output

<!-- TODO: name the exact shape of the result. -->

The task is done when {name_human} has produced that result and stated which
files it wrote.

## Example

Request:

```
TODO: a realistic request, phrased the way a user would type it
```

Result:

```
TODO: the output, exactly as this skill should produce it
```

## Failure modes

- If a step fails, stop at that step and report the error verbatim.
- If the output does not match the expected shape, say so instead of guessing.

## Reference material

- `references/details.md` \u2014 background, edge cases and worked examples.
"""

README_TEMPLATE = """# {name}

{description}

## Install

Copy this directory into your agent's skills folder:

```bash
cp -r {name} ~/.claude/skills/{name}
```

Other tools use the same layout: `~/.codex/skills/`, `~/.cursor/skills/`,
`~/.gemini/skills/`, `~/.agents/skills/`.

## Vet it before you install it

```bash
skillvet scan .
```

## What it does

<!-- TODO: two or three sentences, then a short list of the concrete things it
     produces. -->

## Layout

```
{name}/
  SKILL.md            the skill definition an agent reads
  references/         detail loaded only when the skill needs it
  README.md           this file
  LICENSE             {license}
```

## License

{license}
"""

DETAILS_TEMPLATE = """# {title} \u2014 reference

Detail lives here rather than in SKILL.md so the agent only pays for it when the
skill actually needs it. Link to this file from the body; do not paste it in.

## Background

<!-- TODO: the context that makes the procedure make sense. -->

## Edge cases

| Situation | What to do |
| --- | --- |
| <!-- TODO --> | <!-- TODO --> |

## Worked example

<!-- TODO: a full example, longer than the one in SKILL.md. -->

## Further reading

<!-- TODO: links, standards, or internal docs. -->
"""

MIT_TEMPLATE = """MIT License

Copyright (c) {year} {author}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


def slugify(value: str) -> str:
    slug = NAME_RE.sub("-", value.strip().lower()).strip("-")
    return (slug or "new-skill")[:64]


def _human(slug: str) -> str:
    return slug.replace("-", " ")


def resolve_author(explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    for key in ("SKILLVET_AUTHOR",):
        if os.environ.get(key):
            return os.environ[key]
    try:
        out = subprocess.run(
            ["git", "config", "--get", "user.name"],
            capture_output=True, text=True, timeout=3,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return os.environ.get("USER") or os.environ.get("USERNAME") or ""


def scaffold_skill(
    path: str,
    description: Optional[str] = None,
    license_id: str = "MIT",
    force: bool = False,
    author: Optional[str] = None,
) -> Dict[str, object]:
    target = os.path.abspath(os.path.expanduser(path))
    name = slugify(os.path.basename(os.path.normpath(target)))

    if os.path.isdir(target) and os.listdir(target) and not force:
        raise FileExistsError(
            f"{target} is not empty. Pass --force to write into it anyway."
        )

    title = _human(name).title()
    desc = description or (
        f"Use when the task needs {_human(name)} carried out end to end; produces "
        "a reviewed result with the decisions written down."
    )

    os.makedirs(os.path.join(target, "references"), exist_ok=True)

    files: List[str] = []
    written: List[str] = []

    def write(rel: str, content: str) -> None:
        full = os.path.join(target, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        files.append(rel)
        written.append(full)

    write(
        "SKILL.md",
        SKILL_TEMPLATE.format(
            name=name,
            title=title,
            name_human=_human(name),
            description=desc,
            license=license_id,
        ),
    )
    write(
        "README.md",
        README_TEMPLATE.format(name=name, description=desc, license=license_id),
    )
    write("references/details.md", DETAILS_TEMPLATE.format(title=title))

    if license_id.upper() == "MIT":
        owner = resolve_author(author) or f"The {name} authors"
        write("LICENSE", MIT_TEMPLATE.format(year=time.gmtime().tm_year, author=owner))

    return {"name": name, "path": target, "files": files, "written": written}
