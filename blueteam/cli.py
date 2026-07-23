"""
Blue Team Toolkit command line (defensive utilities).

    python -m blueteam passwd   --text "Tr0ub4dour&3"
    python -m blueteam secrets  ./my_project
    python -m blueteam baseline ./webroot --out webroot.baseline.json
    python -m blueteam check    ./webroot --baseline webroot.baseline.json
    python -m blueteam logs     /var/log/auth.log --threshold 5
"""

from __future__ import annotations

import argparse
import sys

from . import passwd, secrets_scan, integrity, logwatch


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blueteam",
        description="Defensive toolkit: password audit, secret scan, file integrity, log analysis.")
    sub = p.add_subparsers(dest="command", required=True)

    pw = sub.add_parser("passwd", help="Analyze a password's strength/entropy.")
    g = pw.add_mutually_exclusive_group(required=True)
    g.add_argument("--text")
    g.add_argument("--stdin", action="store_true")

    sc = sub.add_parser("secrets", help="Scan a file/dir for hard-coded secrets.")
    sc.add_argument("path")

    bl = sub.add_parser("baseline", help="Save a SHA-256 integrity baseline of a dir.")
    bl.add_argument("root")
    bl.add_argument("--out", required=True)

    ck = sub.add_parser("check", help="Check a dir against a saved baseline.")
    ck.add_argument("root")
    ck.add_argument("--baseline", required=True)

    lg = sub.add_parser("logs", help="Analyze an auth log for brute-force/compromise.")
    lg.add_argument("file")
    lg.add_argument("--threshold", type=int, default=5)
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "passwd":
            pw = sys.stdin.readline().rstrip("\n") if args.stdin else args.text
            print(passwd.analyze(pw).as_text())

        elif args.command == "secrets":
            print(secrets_scan.report(secrets_scan.scan_path(args.path)))

        elif args.command == "baseline":
            n = integrity.save_baseline(args.root, args.out)
            print(f"Baselined {n} file(s) -> {args.out}")

        elif args.command == "check":
            res = integrity.check(args.root, args.baseline)
            print(res.as_text())
            return 0 if res.clean else 3

        elif args.command == "logs":
            print(logwatch.analyze_file(args.file, threshold=args.threshold).as_text())
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
