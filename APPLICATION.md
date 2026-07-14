# Patch the Planet Application Draft

## Project name

SkillTrust Audit

## Project repository URL

To be added after the public repository and `v0.1.0` release exist.

## Anything we should know about your project, or why you're interested?

SkillTrust Audit is an open-source, deterministic pre-install trust baseline for AI Agent Skills. Agent Skills combine natural-language instructions, executable code, dependencies, and assets, which creates a broad supply-chain and prompt-injection surface. The project inventories every file, flags opaque content, symlinks, context-padding, credential and environment access, command and network execution, and package-source changes, then creates a SHA-256 release manifest for human verification.

The project does not claim that a scanner can prove a Skill is safe. It is designed to make curated human review smaller, repeatable, and evidence-based. It was extracted from privacy, evidence-separation, and execution-boundary controls developed for DaoCui's sensitive decision-support Skills and generalized for other Skill maintainers.

During the initial extraction audit, SkillTrust identified six dependency entries in an existing module's lockfile that resolved through a non-default package mirror. The mirror is not presumed malicious; the finding demonstrates why dependency provenance must be explicit and reviewable instead of silently inherited from a developer machine.

We would value a focused security engagement covering parser and path fuzzing, declared-versus-observed behavior analysis, prompt-injection and opaque-file evasions, dependency and GitHub Actions hardening, release provenance, and regression tests. A successful week would leave merged patches, a hardened threat model, reusable test fixtures, and a release workflow other curated Skill repositories can adopt.
