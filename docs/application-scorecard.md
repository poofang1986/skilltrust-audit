# Patch the Planet Internal Scorecard

This is an internal readiness estimate inferred from public program language. It is not an OpenAI or Trail of Bits scoring rubric and does not guarantee selection.

| Dimension | Weight | Evidence after public release | Score |
|---|---:|---|---:|
| Open-source eligibility and maintainer proof | 15 | Public repository, MIT license, tagged release, maintainer profile | 15 |
| Criticality and downstream potential | 25 | Applies to Agent Skill supply-chain review; reusable across sensitive Skill domains; no adoption claim yet | 17 |
| Security relevance and attack surface | 20 | Instructions, code, opaque files, secrets, registries, symlinks, context exhaustion, integrity | 20 |
| One-week actionable security value | 15 | Threat model, fuzzing, behavior analysis, supply chain, provenance, patches and tests | 15 |
| Maintenance maturity and collaboration readiness | 15 | Tests, CI, CodeQL, SECURITY.md, AGENTS.md, policy, manifest, bilingual docs | 14 |
| Public adoption evidence | 10 | No external adoption evidence at initial release | 0 |
| **Total after public release** | **100** | No fabricated metrics | **81** |

Before publication the eligibility score is zero, so the local-only project scores 66/100. External adoption can improve the score later, but it must be real and independently verifiable.

The largest review uncertainty is whether evaluators consider a new security baseline sufficiently critical without existing downstream users. The application must state this limitation honestly.
