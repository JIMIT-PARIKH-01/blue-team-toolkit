"""
Secret / credential scanner (defensive; standard library only).

Greps files for hard-coded secrets (API keys, tokens, private keys, passwords)
so you can find and remove your OWN leaked credentials before pushing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

PATTERNS = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "GitHub token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "Generic API key/secret": re.compile(
        r"(?i)(api[_-]?key|apikey|secret|access[_-]?token)\s*[:=]\s*['\"][0-9A-Za-z\-_]{16,}['\"]"),
    "Hard-coded password": re.compile(
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
}

# Directories/extensions to skip.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".exe",
            ".dll", ".so", ".pyc", ".class", ".jar", ".ico", ".woff", ".ttf"}


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    excerpt: str


def _redact(text: str, max_len: int = 90) -> str:
    text = text.strip()
    return text if len(text) <= max_len else text[:max_len] + "…"


def scan_text(text: str, filename: str = "<text>") -> list:
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule, rx in PATTERNS.items():
            if rx.search(line):
                findings.append(Finding(filename, lineno, rule, _redact(line)))
    return findings


def _is_probably_text(path: Path) -> bool:
    if path.suffix.lower() in SKIP_EXT:
        return False
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(1024)
        return b"\x00" not in chunk          # null byte => binary
    except OSError:
        return False


def scan_path(root: str) -> list:
    """Recursively scan a file or directory for secrets."""
    root_path = Path(root)
    findings = []
    if root_path.is_file():
        files = [root_path]
    else:
        files = [p for p in root_path.rglob("*")
                 if p.is_file() and not (SKIP_DIRS & set(p.parts))]
    for p in files:
        if not _is_probably_text(p):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(text, str(p)))
    return findings


def report(findings: list) -> str:
    if not findings:
        return "No secrets found. OK"
    lines = [f"Found {len(findings)} potential secret(s):", ""]
    for f in findings:
        lines.append(f"  {f.file}:{f.line}  [{f.rule}]")
        lines.append(f"      {f.excerpt}")
    return "\n".join(lines)
