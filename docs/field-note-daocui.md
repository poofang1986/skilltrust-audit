# Field Note: DaoCui Skill Extraction Audit

## Scope

The initial SkillTrust CLI was run against three existing DaoCui Skill modules: the public router, natal-analysis module, and event-decision module. The audit used the default policy and synthetic/local source only.

## Result

- router module: no deterministic high or critical findings;
- event-decision module: no deterministic high or critical findings;
- natal-analysis module: one consolidated high finding affecting six dependency records in `package-lock.json`.

The six records resolved packages through `registry.npmmirror.com`, while the default SkillTrust policy approved only the canonical npm and Python package registry domains.

## Interpretation

This is a provenance finding, not an allegation that the mirror is malicious. A lockfile can silently preserve the package source configured on a maintainer's machine. Reviewers need to decide whether that source is trusted, document the exception, or regenerate the lockfile against an approved registry.

## Remediation

1. Confirm the intended registry and maintainer policy.
2. Regenerate the lockfile against the approved source or add a narrow documented policy exception.
3. Review package integrity hashes and dependency versions.
4. Verify the release manifest after the lockfile changes.

This field note contains no personal case data and demonstrates the project's core principle: detected behavior, maintainer intent, human validation, and trust decision remain separate.
