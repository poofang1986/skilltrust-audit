# SkillTrust Audit

SkillTrust Audit is a transparent, deterministic pre-install review baseline for AI Agent Skills. It inventories every file, flags high-risk execution and supply-chain surfaces, and creates a SHA-256 release manifest for human verification.

It does **not** certify that a Skill is safe. Its purpose is to make trust decisions smaller, reproducible, and reviewable instead of outsourcing trust to a scanner.

## Why this exists

Agent Skills combine natural-language instructions, executable code, dependencies, and assets. A reviewer must account for all four. Static scanners can miss hidden or opaque content, context-padding attacks, package-source changes, and persuasive prompt injection.

SkillTrust Audit was extracted from the privacy, evidence-separation, and execution-boundary work in DaoCui's safety-bounded decision-support Skills, then generalized for any Skill repository.

## What it checks

- missing or unfinished `SKILL.md` metadata;
- opaque bytecode, binaries, archives, and unknown file types;
- hidden files and directories;
- symbolic links and unexpected executable permissions;
- oversized or heavily padded text;
- environment-variable and credential access;
- subprocess, dynamic evaluation, and direct network access;
- credential-transmission instructions;
- unapproved package registries;
- release contents against a deterministic SHA-256 manifest.

## Quick start

Requires Python 3.10+ and no third-party packages.

```bash
python3 skills/skilltrust-audit/scripts/skilltrust.py audit path/to/skill --format markdown
python3 skills/skilltrust-audit/scripts/skilltrust.py manifest path/to/skill --output path/to/skill/skilltrust-manifest.json
python3 skills/skilltrust-audit/scripts/skilltrust.py verify path/to/skill --manifest path/to/skill/skilltrust-manifest.json
```

Exit code `1` means the configured severity threshold was reached or the manifest did not verify. Exit code `2` means the target, policy, or manifest was invalid.

## Trust decision

A clean deterministic report is only one input. Before installation, confirm the maintainer and source revision, review all declared capabilities, verify dependencies, inspect medium findings, and run the Skill with the minimum required permissions.

See [the threat model](docs/threat-model.md), [the proposed security engagement](docs/engagement-plan.md), and [the internal application scorecard](docs/application-scorecard.md).

The first real-world extraction audit found a non-default dependency registry recorded in an existing Skill module's lockfile. See [the DaoCui field note](docs/field-note-daocui.md).

## Project status

`v0.1.1` is an initial baseline designed for curated Skill repositories and human review. The next research targets are semantic declared-versus-observed behavior comparison, parser fuzzing, and release provenance signing.

Maintainer: Felix Fang (`poofang1986`).

## License

MIT
