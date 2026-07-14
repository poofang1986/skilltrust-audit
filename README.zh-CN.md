# SkillTrust Audit

SkillTrust Audit 是面向 AI Agent Skill 的透明、确定性安装前审计基线。它会完整枚举文件，标记高风险执行面和供应链风险，并生成可供人工验证的 SHA-256 发布清单。

它不承诺“扫描通过就绝对安全”。它的目标是把信任判断变成更小、更可复现、更容易人工核验的工作。

项目从道萃决策支持 Skill 已有的隐私最小化、证据分层和执行边界中抽取，再泛化为适用于其他 Agent Skill 的安全工具。

## 快速使用

仅需 Python 3.10+，没有第三方依赖。

```bash
python3 skills/skilltrust-audit/scripts/skilltrust.py audit path/to/skill --format markdown
python3 skills/skilltrust-audit/scripts/skilltrust.py manifest path/to/skill --output path/to/skill/skilltrust-manifest.json
python3 skills/skilltrust-audit/scripts/skilltrust.py verify path/to/skill --manifest path/to/skill/skilltrust-manifest.json
```

检查范围包括 `SKILL.md` 元数据、不透明文件、隐藏文件、符号链接、上下文填充、环境变量和凭据访问、命令与网络执行、替代包源，以及发布清单完整性。

详细边界见 [威胁模型](docs/threat-model.md) 和 [内部申请评分表](docs/application-scorecard.md)。
