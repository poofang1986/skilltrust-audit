# Risk Model

## Trust Layers

Keep these layers separate:

1. **Repository fact**: files, hashes, permissions, links, dependencies, and revision.
2. **Declared intent**: what `SKILL.md` and the maintainer say the Skill does.
3. **Detected behavior**: code or instructions that access data, tools, networks, commands, or package sources.
4. **Human validation**: whether each behavior is necessary, proportionate, and consistent with the source and audience.
5. **Trust decision**: reject, quarantine, manual review, or eligible for curated install.

A scanner result is evidence, not a verdict. Benign instructions can look dangerous, and malicious behavior can be hidden in apparently benign content.

## Protected Assets

- credentials, environment variables, browser sessions, and API tokens;
- private files, messages, recordings, and personal records;
- source code, release credentials, and production access;
- the agent's instruction hierarchy and user intent;
- package-manager configuration and dependency provenance.

## Primary Threats

- natural-language instructions that redirect the agent away from the user's request;
- scripts that read credentials or transmit local data;
- opaque bytecode, binaries, archives, or hidden files that differ from visible source;
- symlinks that escape the reviewed directory;
- oversized or padded content that hides later instructions from reviewers or models;
- alternate registries, install hooks, or unpinned dependencies that change the supply chain;
- arbitrary command execution or writes outside the declared workspace;
- release contents that no longer match the reviewed revision.

## Non-Goals

SkillTrust does not prove author intent, emulate every runtime, replace sandboxing, or certify a public marketplace. Use it to make manual review smaller, repeatable, and evidence-based.
