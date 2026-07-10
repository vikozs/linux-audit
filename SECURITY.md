# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue. Use GitHub's
**Report a vulnerability** (Security → Advisories) or contact the maintainer listed in
the repository. You'll get an acknowledgement as soon as possible and a fix or mitigation
once triaged.

## Scope & handling notes

- This tool collects sensitive information about your infrastructure. Treat generated
  reports and host lists as confidential; the bundled `.gitignore` excludes them.
- Credentials are passed via stdin/env, never on the command line.
- Report output is written with spreadsheet formulas disabled so that data collected
  from a potentially compromised host cannot execute as a formula when the report is
  opened. If you find a way around this, please report it.
- Only use this tool against systems you are authorised to access.
