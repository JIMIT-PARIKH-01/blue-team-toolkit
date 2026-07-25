"""Offline tests for the Blue Team Toolkit."""

from blueteam import passwd, secrets_scan, integrity, logwatch


def test_password_weak_vs_strong():
    weak = passwd.analyze("password")
    strong = passwd.analyze("Tr0ub4dour&3xK9!zq")
    assert weak.rating == "Very weak"
    assert strong.entropy_bits > weak.entropy_bits
    assert "common" in " ".join(weak.issues).lower()


def test_password_entropy_positive():
    assert passwd.analyze("abcDEF123!").entropy_bits > 0


def test_secret_scanner_finds_aws_key():
    text = 'aws_key = "AKIAIOSFODNN7EXAMPLE"\nx = 1\n'
    findings = secrets_scan.scan_text(text, "app.py")
    assert any("AWS" in f.rule for f in findings)


def test_secret_scanner_clean_text():
    assert secrets_scan.scan_text("just a normal line of code\n", "a.py") == []


def test_integrity_detects_change(tmp_path):
    root = tmp_path / "watch"
    root.mkdir()
    (root / "a.txt").write_text("original")
    base = tmp_path / "base.json"          # baseline stored OUTSIDE the watched dir
    integrity.save_baseline(str(root), str(base))
    (root / "a.txt").write_text("changed")
    (root / "b.txt").write_text("new")
    res = integrity.check(str(root), str(base))
    assert res.modified == ["a.txt"] and res.added == ["b.txt"] and not res.clean


def test_integrity_clean_when_unchanged(tmp_path):
    root = tmp_path / "watch"
    root.mkdir()
    (root / "x.txt").write_text("stable")
    base = tmp_path / "b.json"             # baseline stored OUTSIDE the watched dir
    integrity.save_baseline(str(root), str(base))
    assert integrity.check(str(root), str(base)).clean


def test_logwatch_detects_bruteforce():
    lines = ["Failed password for admin from 10.0.0.9 port 22 ssh2"] * 7
    lines.append("Accepted password for admin from 10.0.0.9 port 22 ssh2")
    rep = logwatch.analyze(lines, threshold=5)
    assert ("10.0.0.9", 7) in rep.brute_ips
    assert ("admin", "10.0.0.9") in rep.breach_suspects
