# Security Policy

## Supported version

Security fixes are applied to the latest tagged release and the default branch.

## Reporting

Do not open a public issue for a suspected vulnerability that could expose credentials, private data, or a working exploit. Email the maintainer listed on the repository profile with the subject `SkillTrust security report` and include:

- affected revision and file;
- threat scenario and required permissions;
- minimal reproduction using synthetic data;
- expected and observed behavior;
- suggested remediation, if known.

The maintainer will acknowledge a report within seven days, coordinate validation and remediation, and publish details after a fix is available. No guarantee of bounty or compensation is made.

## Scope

In scope: audit bypasses, manifest integrity errors, path-boundary failures, credential exposure, unsafe default policy, and release-pipeline compromise.

Out of scope: claims that static analysis can never prove, social engineering unrelated to the repository, or tests against systems without authorization.
