"""
Log analyzer / brute-force detector (defensive; standard library only).

Parses auth logs (Linux SSH-style and generic "failed login ... <ip>" lines),
counts failed attempts per IP, and flags likely brute-force sources and any
success that follows a burst of failures (possible compromise).
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
FAIL_RES = [
    re.compile(rf"Failed password for (?:invalid user )?(\S+) from {_IP}"),
    re.compile(rf"authentication failure.*rhost={_IP}"),
    re.compile(rf"(?i)failed login.*?from[:\s]+{_IP}"),
    re.compile(rf"(?i)invalid user (\S+) from {_IP}"),
]
OK_RES = [
    re.compile(rf"Accepted password for (\S+) from {_IP}"),
    re.compile(rf"(?i)accepted login for (\S+) from {_IP}"),
]


@dataclass
class LogReport:
    total_lines: int
    failures_by_ip: Counter = field(default_factory=Counter)
    users_tried: dict = field(default_factory=dict)     # ip -> set(users)
    successes: list = field(default_factory=list)        # (user, ip)
    threshold: int = 5

    @property
    def brute_ips(self) -> list:
        return [(ip, n) for ip, n in self.failures_by_ip.most_common()
                if n >= self.threshold]

    @property
    def breach_suspects(self) -> list:
        # success from an IP that also had >= threshold failures
        return [(u, ip) for u, ip in self.successes
                if self.failures_by_ip.get(ip, 0) >= self.threshold]

    def as_text(self) -> str:
        lines = [
            "=== Log analysis ===",
            f"Lines parsed        : {self.total_lines}",
            f"Failed-login IPs    : {len(self.failures_by_ip)}",
            f"Brute-force sources (>= {self.threshold} fails):",
        ]
        if self.brute_ips:
            for ip, n in self.brute_ips:
                users = ", ".join(sorted(self.users_tried.get(ip, [])) [:6])
                lines.append(f"  {ip:<16} {n:>4} fails   users: {users or '-'}")
        else:
            lines.append("  (none)")
        if self.breach_suspects:
            lines.append("POSSIBLE COMPROMISE (success after many fails):")
            for u, ip in self.breach_suspects:
                lines.append(f"  ! user '{u}' logged in from {ip}")
        return "\n".join(lines)


def analyze(lines, threshold: int = 5) -> LogReport:
    if isinstance(lines, str):
        lines = lines.splitlines()
    failures = Counter()
    users = defaultdict(set)
    successes = []
    total = 0

    for line in lines:
        total += 1
        for rx in FAIL_RES:
            m = rx.search(line)
            if m:
                groups = m.groups()
                ip = groups[-1]
                failures[ip] += 1
                if len(groups) == 2:
                    users[ip].add(groups[0])
                break
        for rx in OK_RES:
            m = rx.search(line)
            if m:
                successes.append((m.group(1), m.group(2)))
                break

    return LogReport(total_lines=total, failures_by_ip=failures,
                     users_tried={k: v for k, v in users.items()},
                     successes=successes, threshold=threshold)


def analyze_file(path: str, threshold: int = 5) -> LogReport:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return analyze(fh.read().splitlines(), threshold=threshold)
