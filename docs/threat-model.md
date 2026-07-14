# Threat Model

## Scope

SkillTrust reviews a local Agent Skill directory or repository before installation or release. The reviewer controls the audit target and runs the tool without elevated privileges.

## Assets

- user credentials, environment variables, browser sessions, and API keys;
- private files, messages, source code, and personal records;
- the agent's instruction hierarchy and the user's requested action;
- package-manager configuration and dependency provenance;
- the reviewed release identity.

## Trust boundaries

1. Maintainer identity and repository origin.
2. Natural-language instructions in `SKILL.md` and references.
3. Executable scripts and package hooks.
4. Opaque assets, hidden paths, and symbolic links.
5. External registries, URLs, and runtime dependencies.
6. Release packaging between review and installation.

## Threats and controls

| Threat | Baseline control | Residual risk |
|---|---|---|
| Hidden or opaque payload | Full tree inventory; opaque types and hidden paths are findings | New encodings and polyglot files require deeper analysis |
| Context exhaustion or padding | File-size, line-count, and blank-ratio checks | Dense adversarial text may remain within limits |
| Credential or environment access | Pattern-based execution-surface findings | Indirect or obfuscated access can evade patterns |
| Command or network execution | High/medium findings with file and line | Legitimate and malicious uses need human judgment |
| Package-source substitution | Approved registry policy | DNS, account, or upstream package compromise remains possible |
| Path escape | Symlink rejection and explicit file inventory | Runtime-created paths require sandboxing |
| Release substitution | Deterministic SHA-256 manifest | Manifest origin still needs a trusted channel or signature |
| Misleading benign prose | Human review against declared purpose | Static analysis cannot establish intent |

## Security invariants

- Never silently skip a file because its type is unfamiliar.
- Never treat a clean audit as certification.
- Never read outside the target through a symbolic link.
- Never require network access or third-party packages to audit a local Skill.
- Never include real sensitive data in fixtures or reports.

## Planned research

- property-based and coverage-guided fuzzing of frontmatter and policy parsers;
- semantic comparison of declared capability and observed behavior;
- signed release provenance and reproducible packaging;
- evaluation against a transparent corpus of benign and intentionally unsafe synthetic Skills.
