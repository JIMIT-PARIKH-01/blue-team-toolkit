"""
File integrity monitor (defensive; standard library only).

Take a SHA-256 baseline of a directory, then later check it to detect
added / removed / modified files -- a simple tripwire for config dirs,
web roots, or a CTF box you're defending.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}


def _hash_file(path: Path, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def snapshot(root: str) -> dict:
    """Map each file (relative path) -> sha256 under `root`."""
    root_path = Path(root)
    result = {}
    for p in root_path.rglob("*"):
        if p.is_file() and not (SKIP_DIRS & set(p.relative_to(root_path).parts)):
            try:
                result[str(p.relative_to(root_path)).replace("\\", "/")] = _hash_file(p)
            except OSError:
                continue
    return result


def save_baseline(root: str, baseline_path: str) -> int:
    snap = snapshot(root)
    with open(baseline_path, "w", encoding="utf-8") as fh:
        json.dump({"root": str(Path(root).resolve()), "files": snap}, fh, indent=2)
    return len(snap)


@dataclass
class IntegrityResult:
    added: list = field(default_factory=list)
    removed: list = field(default_factory=list)
    modified: list = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.added or self.removed or self.modified)

    def as_text(self) -> str:
        if self.clean:
            return "Integrity OK — no changes since baseline."
        lines = ["Integrity changes detected:"]
        for label, items in (("modified", self.modified), ("added", self.added),
                             ("removed", self.removed)):
            for f in items:
                lines.append(f"  [{label:>8}] {f}")
        return "\n".join(lines)


def check(root: str, baseline_path: str) -> IntegrityResult:
    with open(baseline_path, encoding="utf-8") as fh:
        base = json.load(fh).get("files", {})
    current = snapshot(root)

    base_keys, cur_keys = set(base), set(current)
    added = sorted(cur_keys - base_keys)
    removed = sorted(base_keys - cur_keys)
    modified = sorted(k for k in base_keys & cur_keys if base[k] != current[k])
    return IntegrityResult(added=added, removed=removed, modified=modified)
