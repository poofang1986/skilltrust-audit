# Agent Guidance

Read `docs/threat-model.md` before changing detection or trust decisions.

- Preserve the claim boundary: findings are evidence, never proof of safety.
- Use only synthetic data in tests and examples.
- Do not add network access, subprocess execution, dynamic evaluation, compiled artifacts, or runtime dependencies without an explicit threat-model update.
- Keep all release files inspectable UTF-8 source unless an exact policy exception is documented.
- Run unit tests, self-audit, and manifest verification before release.
- Treat `critical` and `high` findings as blockers; document every accepted `medium` finding.
