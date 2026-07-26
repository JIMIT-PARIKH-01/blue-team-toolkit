# Blue Team Toolkit

[![CI](https://github.com/JIMIT-PARIKH-01/blue-team-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/JIMIT-PARIKH-01/blue-team-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

A **dependency-free** defensive security toolkit — four tools in one, with a
**GUI and a CLI**. The counterpart to offensive/recon tooling: this is about
**protecting** systems and catching your own mistakes.

1. **Password analyzer** — entropy, weakness checks, and an offline crack-time estimate
2. **Secret scanner** — finds hard-coded API keys / tokens / private keys / passwords in your code
3. **File integrity monitor** — SHA-256 baseline + change detection (added / removed / modified)
4. **Log analyzer** — parses auth logs, detects brute-force sources and post-brute-force logins

Built on the Python standard library only (`hashlib`, `re`, `json`).

---

## Install & run

Just **Python 3.8+** — nothing to install.

```powershell
# GUI (tabs: Password / Secrets / Integrity / Logs)
python blueteam/gui.py            # or double-click run.bat

# CLI
python -m blueteam passwd   --text "Tr0ub4dour&3xK9!"
python -m blueteam secrets  ./my_project
python -m blueteam baseline ./webroot --out webroot.baseline.json
python -m blueteam check    ./webroot --baseline webroot.baseline.json
python -m blueteam logs     ./auth.log --threshold 5
```

### Commands

| Command | Purpose |
|---|---|
| `passwd --text PW` | strength, entropy bits, weaknesses, crack-time estimate |
| `secrets PATH` | scan a file/folder for leaked secrets (skips binaries, `.git`, `node_modules`) |
| `baseline ROOT --out FILE` | record a SHA-256 snapshot of a directory |
| `check ROOT --baseline FILE` | report added/removed/modified files (exit 3 if changed) |
| `logs FILE --threshold N` | brute-force sources + possible-compromise detection |

---

## Why it's useful

- **Secret scanner** is your last line of defense before `git push` — it catches an
  `AKIA…` AWS key or a private key you forgot in a script.
- **File integrity monitor** is a mini-tripwire for a web root, config dir, or a CTF box
  you're defending — know instantly if a file was tampered with.
- **Log analyzer** turns a noisy `auth.log` into "IP 10.0.0.9 tried 200 times, then got in."
- **Password analyzer** puts a real number (entropy bits + crack time) on a policy.

## Tip
Store the integrity **baseline file outside** the folder you're monitoring, so the baseline
itself isn't flagged as a new file.

## Project layout

```
blue-team-toolkit/
└── blueteam/
    ├── passwd.py         # password strength / entropy
    ├── secrets_scan.py   # hard-coded secret finder
    ├── integrity.py      # SHA-256 baseline + change check
    ├── logwatch.py       # auth-log brute-force / compromise detection
    ├── cli.py  gui.py  run.bat  requirements.txt
```

## ⬇️ Download & Install

**This is a public tool — download and use it on your device for free.**

```bash
# 1) Clone it
git clone https://github.com/JIMIT-PARIKH-01/blue-team-toolkit.git
cd blue-team-toolkit

# 2) ...or download a ZIP (no git needed)
#    https://github.com/JIMIT-PARIKH-01/blue-team-toolkit/archive/refs/heads/main.zip

# 3) ...or install the command straight from GitHub
pip install git+https://github.com/JIMIT-PARIKH-01/blue-team-toolkit.git
```

Then run it as shown in the usage section above (CLI `python -m ...`, or launch
the GUI via `run.bat`).

<details>
<summary><b>🔒 Requesting access to a private tool</b></summary>

Public tools install with the commands above. If a tool is **private**, access
is granted by the owner through GitHub — a static link cannot unlock private
code, only GitHub can:

1. **Request access** — open an [access request](https://github.com/JIMIT-PARIKH-01/JIMIT-PARIKH-01/issues/new?template=tool-access-request.md&title=Access+request:+blue-team-toolkit) or message on
   [LinkedIn](https://www.linkedin.com/in/jimit-devangkumar-parikh/).
2. The owner reviews it and, if approved, **adds you as a collaborator** on the
   private repository.
3. GitHub then lets you clone / download it with your own account. Access is
   revoked the moment the owner removes you as a collaborator.

</details>

## License
MIT — see [LICENSE](./LICENSE).
