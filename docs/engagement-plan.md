# Proposed One-Week Security Engagement

The project asks for a focused review that leaves reusable security engineering behind, not only a list of findings.

## Day 1: threat-model review

- challenge trust boundaries and severity criteria;
- identify false-confidence risks in the current report language;
- select realistic benign and adversarial Skill fixtures.

## Day 2: parser and file-tree testing

- fuzz frontmatter, policy, and manifest parsing;
- test path normalization, symlinks, encodings, oversized files, and polyglot content;
- convert confirmed failures into regression tests.

## Day 3: behavior-surface analysis

- improve declared-versus-observed capability comparison;
- test environment, credential, network, command, registry, and persistence indicators;
- calibrate severity and false-positive handling.

## Day 4: supply chain and release integrity

- review dependency and GitHub Actions controls;
- add reproducible package creation, SBOM, and signed provenance where appropriate;
- verify manifest behavior across release artifacts.

## Day 5: patches and reusable guidance

- merge fixes and tests;
- publish a hardened release and concise field report;
- upstream reusable policy and review guidance for curated Skill maintainers.

Success means confirmed patches, regression tests, and a stronger trust workflow that other Skill repositories can adopt.
