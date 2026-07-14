---
name: skilltrust-audit
description: Audit an Agent Skill or Skill repository before installation, release, or inclusion in a curated marketplace. Use for reviewing SKILL.md packages, checking opaque or hidden files, prompt-injection indicators, credential and environment access, command or network execution, dependency-source changes, oversized context payloads, symlinks, and release integrity; also use to create or verify a SHA-256 file manifest and produce a human-review trust report.
---

# SkillTrust Audit

Establish inspectable evidence about an Agent Skill before trusting it. Never describe a clean report as proof that a Skill is safe.

## Audit Workflow

1. Identify the exact Skill directory or repository and its source.
2. Run the deterministic audit:

   ```bash
   python3 scripts/skilltrust.py audit /path/to/skill --format markdown
   ```

3. Treat every `critical` or `high` finding as a release blocker until a human reviews the exact file and line.
4. Review `medium` findings against the declared purpose and trust boundary. Legitimate capability still requires explicit disclosure.
5. Read `references/risk-model.md` before making a trust recommendation.
6. For a release candidate, create and commit an integrity manifest:

   ```bash
   python3 scripts/skilltrust.py manifest /path/to/skill --output /path/to/skill/skilltrust-manifest.json
   python3 scripts/skilltrust.py verify /path/to/skill --manifest /path/to/skill/skilltrust-manifest.json
   ```

7. Report the evidence, unresolved risks, and a decision: `reject`, `quarantine`, `manual_review`, or `eligible_for_curated_install`.

## Decision Rules

- Use `reject` for unexplained credential collection, data exfiltration, destructive execution, or a manifest mismatch in a published release.
- Use `quarantine` for opaque executable content, symlinks, hidden payloads, or unreviewed package-source overrides.
- Use `manual_review` when behavior is powerful but plausibly required, including network access, subprocess execution, environment access, or arbitrary output paths.
- Use `eligible_for_curated_install` only when the source and maintainer are known, all files are inspectable, high findings are resolved, medium findings are documented, dependencies are pinned, and the manifest verifies.

Do not recommend public one-click installation for Skills that operate on credentials, private messages, personal records, production systems, or financial data. Prefer a curated source and a pinned revision.

## Custom Policy

Pass `--policy policy.json` to override size limits, allowed opaque files, ignored paths, or approved registry domains. Read `references/policy.md` before adding exceptions. Keep exceptions narrow and explain each one in review notes.

## Output Contract

Return:

1. target and source revision,
2. finding counts by severity,
3. blocking findings with file and line,
4. declared capability versus observed execution surface,
5. manifest status,
6. unresolved human-review questions,
7. trust decision and exact remediation.

Preserve the distinction inherited from DaoCui's evidence protocol: repository fact, declared intent, detected behavior, human validation, and trust decision are separate layers.
