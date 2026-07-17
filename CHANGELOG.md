# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-07-17

### Added
- `--plan-out PATH`: optional machine-readable **remediation plan** (JSON) intended as
  the input to a separate hardening/patching tool. Structured, safety-annotated fixes
  with `observed`/`expected`, a typed `action`, and `disruptive` / `requires_reboot` /
  `caution` metadata so an unattended run knows what it must not touch.
  Schema `linux-audit.remediation-plan` v1.0, documented in `docs/PLAN_SCHEMA.md`.
- `examples/sample_plan.json` and schema documentation.

### Fixed
- **Firewall detection reported unprotected hosts as protected.** `parse_firewall`
  used substring tests, and `"active" in "inactive"` is true (likewise
  `"running" in "not running"`). A host with ufw inactive or firewalld stopped was
  recorded as having an active firewall — a false PASS on CIS 3.5.1 and a missing
  "No active host firewall detected" finding. Now matches the status value exactly.
  **Anyone who ran v1.0.0 should re-run: firewall results in existing reports may be
  wrong in the unsafe direction.**

### Changed
- Version 1.1.0; build tag `2026-07-17.plan-export`.
- Test fixture made representative (adds `file_perms`, `timesync`, `login.defs`), plus
  regression tests for the firewall bug and tests that police the remediation table
  against the CIS engine so the contract cannot silently rot.

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
