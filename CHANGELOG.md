# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-07-09

### Added
- Agentless SSH collector with a single `@@SECTION`-delimited remote pass per host.
- Inventory: IP, distro, kernel/arch, uptime/load, disk, listening ports, services,
  common-daemon versions, and full installed-package list.
- Severity-ranked hardening **Findings** with recommendations.
- ~30 CIS-style **PASS/FAIL/WARN** checks per host.
- Per-host detail tabs and a colour-coded Summary sheet.
- Parallel execution (`--workers`) and graceful per-host failure handling (Errors sheet).
- Authentication: SSH keys/agent, password login via `sshpass` (`--ask-ssh-pass`,
  `--ssh-pass-env`), passwordless/password sudo, and `--sudo-pass-same-as-ssh`.
- `active_hosts.txt` output listing reachable hosts as a reusable host list.
- Helper utilities `check_xlsx.py` (verify) and `fix_xlsx.py` (repair).

### Security
- Formula-safety: all cell text that could be read as a spreadsheet formula is written
  as text, preventing Excel "Removed Records: Formula" repair warnings and neutralising
  spreadsheet formula-injection from untrusted host data.
- Passwords are passed via stdin/env, never on the command line.
