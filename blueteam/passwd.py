"""
Password strength & entropy analyzer (defensive; standard library only).

Estimates entropy, flags weaknesses, and gives a rough offline-crack-time
estimate. Analyze your OWN passwords / policy — never other people's secrets.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

# A tiny sample of the most common passwords (real tools use huge lists).
COMMON = {
    "password", "123456", "123456789", "12345678", "qwerty", "abc123",
    "111111", "123123", "admin", "letmein", "welcome", "monkey", "dragon",
    "iloveyou", "password1", "qwerty123", "1q2w3e4r", "000000", "root", "toor",
}

_SEQ = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl")

# Assume a fast offline attack on a weak/unsalted hash.
_GUESSES_PER_SEC = 1e11


@dataclass
class PasswordReport:
    length: int
    entropy_bits: float
    charset_size: int
    rating: str
    crack_time: str
    issues: list = field(default_factory=list)

    def as_text(self) -> str:
        lines = [
            "=== Password analysis ===",
            f"Length        : {self.length}",
            f"Charset size  : {self.charset_size}",
            f"Entropy       : {self.entropy_bits:.1f} bits",
            f"Rating        : {self.rating}",
            f"Offline crack : ~{self.crack_time} (fast unsalted-hash attack)",
        ]
        if self.issues:
            lines.append("Weaknesses:")
            for i in self.issues:
                lines.append(f"  - {i}")
        return "\n".join(lines)


def _charset_size(pw: str) -> int:
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"[0-9]", pw):
        size += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        size += 32  # rough symbol space
    return size


def _has_sequence(pw: str, n: int = 3) -> bool:
    low = pw.lower()
    for seq in _SEQ:
        for i in range(len(seq) - n + 1):
            chunk = seq[i:i + n]
            if chunk in low or chunk[::-1] in low:
                return True
    return False


def _human_time(seconds: float) -> str:
    if seconds < 1:
        return "instant"
    units = [("year", 31536000), ("day", 86400), ("hour", 3600),
             ("minute", 60), ("second", 1)]
    for name, size in units:
        if seconds >= size:
            val = seconds / size
            if val >= 1e9:
                return f"{val:.0e} {name}s"
            return f"{val:.0f} {name}{'s' if val >= 2 else ''}"
    return "instant"


def analyze(pw: str) -> PasswordReport:
    length = len(pw)
    charset = _charset_size(pw)
    entropy = length * math.log2(charset) if charset else 0.0

    issues = []
    if length < 8:
        issues.append("too short (< 8 characters)")
    if pw.lower() in COMMON:
        issues.append("appears in common-password lists")
        entropy = min(entropy, 10)
    if charset <= 10:
        issues.append("only one character type (e.g. digits or letters only)")
    if re.search(r"(.)\1\1", pw):
        issues.append("has 3+ repeated characters in a row")
    if _has_sequence(pw):
        issues.append("contains a keyboard/alphabet/number sequence")

    avg_guesses = 0.5 * (2 ** entropy)
    crack_time = _human_time(avg_guesses / _GUESSES_PER_SEC)

    rating = ("Very weak" if entropy < 28 else "Weak" if entropy < 40 else
              "Reasonable" if entropy < 60 else "Strong" if entropy < 80 else
              "Very strong")
    if pw.lower() in COMMON:
        rating = "Very weak"

    return PasswordReport(length=length, entropy_bits=entropy, charset_size=charset,
                          rating=rating, crack_time=crack_time, issues=issues)
