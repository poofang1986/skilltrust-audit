---
name: daocui-sensitive-decision-example
description: Demonstrate a privacy-minimized, evidence-separated Agent Skill for a synthetic high-impact decision-support workflow. Use only as a review fixture and architecture example; it does not provide real advice or collect real personal data.
---

# DaoCui Sensitive Decision Example

Use synthetic case IDs only. Do not collect names, addresses, credentials, medical records, financial account details, recordings, or third-party private information.

Keep these layers separate:

1. user-provided synthetic fact,
2. deterministic tool output,
3. model interpretation,
4. independent validation,
5. reversible action and stop rule.

Never store an inference as a confirmed fact. Do not write outside the current workspace. Do not access the network, environment variables, browser sessions, or unrelated files.

For any high-impact conclusion, state missing facts and require qualified professional review. This fixture demonstrates how the original DaoCui privacy and evidence boundaries informed SkillTrust's generic trust model.
