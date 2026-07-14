#!/usr/bin/env python3
"""Deterministic trust-baseline checks for Agent Skill packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

VERSION = "0.1.1"
SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TEXT_EXTENSIONS = {
    "", ".css", ".html", ".js", ".json", ".lock", ".md", ".mjs",
    ".py", ".sh", ".svg", ".toml", ".ts", ".txt", ".yaml", ".yml",
}
OPAQUE_EXTENSIONS = {
    ".7z", ".bin", ".class", ".dll", ".dylib", ".exe", ".gz", ".jar",
    ".o", ".pkl", ".pyc", ".pyo", ".rar", ".so", ".tar", ".whl", ".zip",
}
SKIP_PARTS = {".git", ".mypy_cache", ".pytest_cache", "__pycache__", "node_modules"}
DEFAULT_POLICY = {
    "max_file_bytes": 500_000,
    "max_text_lines": 5_000,
    "allowed_opaque_paths": [],
    "ignored_paths": [],
    "approved_registry_domains": ["pypi.org", "registry.npmjs.org"],
}


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str
    line: int | None = None
    evidence: str | None = None


def relpath(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def path_matches(relative: str, entries: list[str]) -> bool:
    return any(relative == item.rstrip("/") or relative.startswith(item.rstrip("/") + "/") for item in entries)


def load_policy(path: Path | None) -> dict:
    policy = dict(DEFAULT_POLICY)
    if path:
        supplied = json.loads(path.read_text(encoding="utf-8"))
        unknown = sorted(set(supplied) - set(DEFAULT_POLICY))
        if unknown:
            raise ValueError(f"unknown policy fields: {', '.join(unknown)}")
        policy.update(supplied)
    return policy


def add(findings: list[Finding], code: str, severity: str, path: str, message: str,
        line: int | None = None, evidence: str | None = None) -> None:
    findings.append(Finding(severity, code, path, message, line, evidence))


def validate_skill_metadata(root: Path, findings: list[Finding]) -> None:
    skill_files = sorted(root.rglob("SKILL.md"))
    if not skill_files:
        add(findings, "META001", "high", ".", "No SKILL.md was found in the audit target.")
        return

    for skill_file in skill_files:
        relative = relpath(skill_file, root)
        text = skill_file.read_text(encoding="utf-8", errors="replace")
        if not text.startswith("---\n") or "\n---\n" not in text[4:]:
            add(findings, "META002", "high", relative, "SKILL.md has no valid YAML frontmatter boundary.")
            continue
        frontmatter = text[4:text.index("\n---\n", 4)]
        fields = {}
        for line_number, line in enumerate(frontmatter.splitlines(), 2):
            if ":" not in line:
                add(findings, "META003", "medium", relative, "Frontmatter line is not a key-value pair.", line_number, line[:160])
                continue
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
        for required in ("name", "description"):
            if not fields.get(required) or "TODO" in fields[required]:
                add(findings, "META004", "high", relative, f"Frontmatter field '{required}' is missing or unfinished.")
        extra = sorted(set(fields) - {"name", "description"})
        if extra:
            add(findings, "META005", "low", relative, f"Unexpected frontmatter fields: {', '.join(extra)}.")
        name = fields.get("name", "")
        if name and not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
            add(findings, "META006", "medium", relative, "Skill name is not lowercase hyphen-case.")


def scan_text(relative: str, text: str, findings: list[Finding], policy: dict) -> None:
    lines = text.splitlines()
    if len(lines) > policy["max_text_lines"]:
        add(findings, "CTX001", "high", relative, f"Text has {len(lines)} lines; policy limit is {policy['max_text_lines']}.")
    if len(lines) > 500:
        blank_ratio = sum(not line.strip() for line in lines) / len(lines)
        if blank_ratio > 0.90:
            add(findings, "CTX002", "high", relative, f"Text is {blank_ratio:.0%} blank across {len(lines)} lines.")

    download_tools = r"\b(?:cu" + r"rl|w" + r"get)\b[^\n]*(?:\||-o\s+|--output)"
    transmit_verbs = r"(?:se" + r"nd|up" + r"load|exfiltrat\w*)"
    sensitive_terms = r"(?:creden" + r"tial|to" + r"ken|se" + r"cret|private key)"
    pattern_specs = [
        ("DATA001", "high", re.compile(r"\b(?:os\.environ|process\.env|Deno\.env)\b"), "Reads process environment data."),
        ("EXEC001", "high", re.compile(r"\b(?:os\.system|subprocess\.|child_process\.|shell\s*=\s*True)"), "Invokes operating-system commands."),
        ("EXEC002", "high", re.compile(r"\b(?:eval|exec)\s*\("), "Uses dynamic code evaluation."),
        ("NET001", "medium", re.compile(r"\b(?:requests\.(?:get|post|put)|urllib\.request|socket\.socket|fetch\s*\()"), "Contains direct network access."),
        ("NET002", "high", re.compile(download_tools), "Downloads or pipes remote content."),
        ("PROMPT001", "high", re.compile("ignore previous " + "instructions", re.IGNORECASE), "Contains an instruction-hierarchy override phrase."),
        ("PROMPT002", "critical", re.compile(transmit_verbs + r"[^\n]{0,100}" + sensitive_terms, re.IGNORECASE), "Instructs transmission of sensitive credentials."),
        ("SECRET001", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Contains a private-key block."),
        ("SECRET002", "critical", re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b"), "Contains a GitHub token-shaped value."),
    ]
    seen_registry_domains: set[str] = set()
    for line_number, line in enumerate(lines, 1):
        for code, severity, pattern, message in pattern_specs:
            match = pattern.search(line)
            if match:
                add(findings, code, severity, relative, message, line_number, line.strip()[:200])

        registry_match = re.search(r"https?://([^/\s]+)", line)
        if registry_match and re.search(r"(?:registry|index-url|extra-index-url)", line, re.IGNORECASE):
            domain = urlparse(registry_match.group(0)).hostname or ""
            if domain not in policy["approved_registry_domains"] and domain not in seen_registry_domains:
                add(findings, "SUPPLY001", "high", relative, f"References an unapproved package registry: {domain}.", line_number, line.strip()[:200])
                seen_registry_domains.add(domain)


def audit(root: Path, policy: dict) -> dict:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"audit target is not a directory: {root}")
    findings: list[Finding] = []
    validate_skill_metadata(root, findings)

    for path in sorted(root.rglob("*")):
        relative = relpath(path, root)
        if any(part in SKIP_PARTS for part in path.relative_to(root).parts) or path_matches(relative, policy["ignored_paths"]):
            continue
        if path.is_symlink():
            add(findings, "FILE001", "high", relative, "Symbolic link requires manual review and is excluded from content scanning.")
            continue
        if path.is_dir():
            if path.name.startswith(".") and path.name != ".github":
                add(findings, "FILE002", "medium", relative, "Hidden directory requires explicit review.")
            continue
        if path.name.startswith(".") and path.name not in {".gitignore"}:
            add(findings, "FILE003", "medium", relative, "Hidden file requires explicit review.")

        size = path.stat().st_size
        if size > policy["max_file_bytes"]:
            add(findings, "FILE004", "high", relative, f"File size {size} exceeds policy limit {policy['max_file_bytes']}.")

        suffix = path.suffix.lower()
        if suffix in OPAQUE_EXTENSIONS and not path_matches(relative, policy["allowed_opaque_paths"]):
            add(findings, "FILE005", "high", relative, f"Opaque or executable file type '{suffix}' is not allowlisted.")

        mode = path.stat().st_mode
        if mode & stat.S_IXUSR and suffix not in {".py", ".sh"}:
            add(findings, "FILE006", "medium", relative, "Unexpected executable permission.")

        data = path.read_bytes()
        if b"\x00" in data[:8192]:
            if not path_matches(relative, policy["allowed_opaque_paths"]):
                add(findings, "FILE007", "high", relative, "Binary content is not allowlisted.")
            continue
        if suffix not in TEXT_EXTENSIONS:
            if not path_matches(relative, policy["allowed_opaque_paths"]):
                add(findings, "FILE008", "medium", relative, f"Unrecognized file type '{suffix or '<none>'}'.")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            add(findings, "FILE009", "high", relative, "Text-like file is not valid UTF-8.")
            continue
        scan_text(relative, text, findings, policy)

    findings.sort(key=lambda item: (-SEVERITY[item.severity], item.path, item.line or 0, item.code))
    counts = {level: sum(item.severity == level for item in findings) for level in SEVERITY}
    return {
        "tool": "skilltrust-audit",
        "version": VERSION,
        "target": str(root),
        "summary": counts,
        "findings": [asdict(item) for item in findings],
    }


def markdown_report(report: dict) -> str:
    counts = report["summary"]
    lines = [
        "# SkillTrust Audit Report",
        "",
        f"Target: `{report['target']}`",
        "",
        "| Critical | High | Medium | Low |",
        "|---:|---:|---:|---:|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |",
        "",
    ]
    if not report["findings"]:
        lines.append("No deterministic findings. This is not proof that the Skill is safe.")
    for item in report["findings"]:
        location = item["path"] + (f":{item['line']}" if item["line"] else "")
        lines.extend([
            f"## {item['severity'].upper()} {item['code']}",
            "",
            f"- Location: `{location}`",
            f"- Finding: {item['message']}",
        ])
        if item["evidence"]:
            lines.append(f"- Evidence: `{item['evidence']}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def iter_manifest_files(root: Path, excluded: set[Path]):
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file() or path in excluded:
            continue
        if any(part in SKIP_PARTS for part in path.relative_to(root).parts):
            continue
        yield path


def build_manifest(root: Path, output: Path | None = None) -> dict:
    root = root.resolve()
    excluded = {output.resolve()} if output else set()
    files = []
    for path in iter_manifest_files(root, excluded):
        data = path.read_bytes()
        files.append({"path": relpath(path, root), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    return {"format": "skilltrust-manifest-v1", "files": files}


def verify_manifest(root: Path, manifest_path: Path) -> list[str]:
    expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    actual = build_manifest(root, manifest_path)
    expected_map = {item["path"]: item for item in expected.get("files", [])}
    actual_map = {item["path"]: item for item in actual["files"]}
    errors = []
    for path in sorted(set(expected_map) | set(actual_map)):
        if path not in expected_map:
            errors.append(f"unexpected file: {path}")
        elif path not in actual_map:
            errors.append(f"missing file: {path}")
        elif expected_map[path] != actual_map[path]:
            errors.append(f"changed file: {path}")
    return errors


def write_or_print(content: str, output: Path | None) -> None:
    if output:
        output.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="skilltrust", description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser("audit", help="audit a Skill directory or repository")
    audit_parser.add_argument("target", type=Path)
    audit_parser.add_argument("--policy", type=Path)
    audit_parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    audit_parser.add_argument("--output", type=Path)
    audit_parser.add_argument("--fail-on", choices=tuple(SEVERITY), default="high")

    manifest_parser = subparsers.add_parser("manifest", help="create a deterministic SHA-256 manifest")
    manifest_parser.add_argument("target", type=Path)
    manifest_parser.add_argument("--output", type=Path)

    verify_parser = subparsers.add_parser("verify", help="verify a Skill against a manifest")
    verify_parser.add_argument("target", type=Path)
    verify_parser.add_argument("--manifest", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "audit":
            policy = load_policy(args.policy)
            report = audit(args.target, policy)
            content = json.dumps(report, ensure_ascii=False, indent=2) + "\n" if args.format == "json" else markdown_report(report)
            write_or_print(content, args.output)
            threshold = SEVERITY[args.fail_on]
            return int(any(SEVERITY[item["severity"]] >= threshold for item in report["findings"]))
        if args.command == "manifest":
            manifest = build_manifest(args.target, args.output)
            write_or_print(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", args.output)
            return 0
        errors = verify_manifest(args.target, args.manifest)
        if errors:
            sys.stderr.write("\n".join(errors) + "\n")
            return 1
        print("manifest verified")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"skilltrust: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
