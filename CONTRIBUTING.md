# Contributing

Thanks for your interest in improving linux-audit!

## Reporting issues

Open an issue with:

- What you ran (command line, with any passwords redacted).
- Target OS/distro and version.
- Expected vs actual behaviour, and any message from the **Errors** sheet.

Never paste real passwords, hostnames you don't want public, or full audit reports
into an issue.

## Development

```bash
git clone https://github.com/vikozs/linux-audit.git
cd linux-audit
python3 -m pip install -r requirements.txt
```

The tool is intentionally dependency-light (standard library + `openpyxl`) and the
remote collector is defensive POSIX-ish bash — every probe is guarded so a missing
tool is skipped, not fatal. Please keep both properties.

### Guidelines

- Match the existing style; keep the collector free of hard dependencies on tools that
  may be absent on minimal systems.
- If you add a data section, wire it through parsing, Findings/CIS (where relevant),
  and the workbook, and update the README sheet table.
- Any new cell content must go through the existing cell writers so the formula-safety
  guard applies.
- Verify generated reports with `python3 check_xlsx.py <file>` (expect "clean").

## Pull requests

Keep PRs focused, describe the change and how you tested it, and update `CHANGELOG.md`
under an "Unreleased" heading.
