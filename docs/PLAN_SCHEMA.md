# Remediation plan schema

`linux_audit.py --plan-out plan.json` writes a machine-readable remediation plan
intended as the **input to a separate hardening/patching tool**.

The Excel workbook is prose for humans. This file is structured data for a
machine: not *"PermitRootLogin is enabled"* but
`{key, observed, expected, action, restart, disruptive}`.

```bash
python3 linux_audit.py -H hosts.txt -o audit.xlsx --plan-out plan.json
```

- **Schema:** `linux-audit.remediation-plan`
- **Version:** `1.0`

## Contract

Consumers **must**:

1. Assert `schema == "linux-audit.remediation-plan"` and refuse unknown **major**
   versions. Minor bumps are additive only; new keys may appear, existing keys
   keep their meaning.
2. Treat `disruptive: true` as **do not apply unattended**. Require an explicit
   human opt-in per item or per class.
3. Re-verify `observed` on the host before applying. The plan is a snapshot; the
   host may have changed since the audit.
4. Ignore unknown `action.type` values rather than guessing.

## Top level

| Field | Type | Notes |
|---|---|---|
| `schema` | string | Always `linux-audit.remediation-plan`. |
| `schema_version` | string | `major.minor`. |
| `generated` | string | ISO 8601 with timezone offset. |
| `generator` | object | `{tool, version, build}`. |
| `notes` | string[] | Caveats that travel with the data (heuristic checks, stale package cache, etc.). |
| `summary` | object | `hosts_total`, `hosts_ok`, `hosts_failed`, `remediation_items`, `auto_applicable`, `needs_human`. |
| `hosts` | object[] | One entry per reachable host. |
| `unreachable` | object[] | `{host, error}` for hosts that failed; keeps the fleet view complete. |

## Host

| Field | Type | Notes |
|---|---|---|
| `host` | string | The connection target as given in the host list. |
| `hostname` | string | FQDN as reported by the host itself. |
| `reachable` | bool | Always `true` in `hosts[]`. |
| `facts` | object | See below. |
| `counts` | object | `cis_pass/fail/warn`, `findings_high/medium/low`, `remediation_items`, `auto_applicable`, `needs_human`. |
| `remediation` | object[] | Actionable items. **Only CIS `FAIL` and `WARN` produce entries.** |
| `findings` | object[] | Prose findings mirroring the report: `{severity, category, finding, detail, recommendation}`. |

### `facts`

`distro`, `os_family` (`debian`\|`rhel`\|`suse`\|`unknown`), `kernel`, `arch`,
`package_manager` (`apt`\|`dnf`\|`yum`\|`null`), `ips[]`, `uptime`,
`reboot_required` (bool), `selinux`, `apparmor`, `firewall_active` (bool),
`package_count`, `updates_pending`, `updates_security`.

`os_family` and `package_manager` are what an executor should branch on — never
parse `distro`.

## Remediation item

```json
{
  "check_id": "5.2.1",
  "key": "ssh.permit_root_login",
  "title": "SSH: root login disabled",
  "result": "FAIL",
  "observed": "yes",
  "expected": "no",
  "detail": "PermitRootLogin=yes",
  "action": { "type": "sshd_config", "directive": "PermitRootLogin", "value": "no" },
  "restart": ["sshd"],
  "disruptive": true,
  "requires_reboot": false,
  "caution": "Verify a sudo-capable non-root account can log in first. Automation that logs in as root will break."
}
```

| Field | Notes |
|---|---|
| `check_id` | CIS-style id. Stable, but **`key` is the better join field.** |
| `key` | Stable dotted identifier, independent of CIS numbering. Prefer this. |
| `result` | `FAIL` or `WARN`. `WARN` means the desired state is context-dependent. |
| `observed` / `expected` | State at audit time vs desired. |
| `action` | Structured fix; `type` selects the executor. |
| `restart` | Services to restart/reload afterwards. `["*"]` means "may restart anything". |
| `disruptive` | **Can drop connectivity or break a workload.** Never auto-apply. |
| `requires_reboot` | Change only takes effect after reboot. |
| `caution` | Human-readable warning. Surface it; don't bury it. |

## Action types

| `type` | Payload | Meaning |
|---|---|---|
| `sshd_config` | `directive`, `value` | Set directive in `sshd_config`, reload sshd. |
| `sysctl` | `key`, `value` | Set at runtime **and** persist in `/etc/sysctl.d/`. |
| `file_mode` | `path`, `mode`, `owner`, `group` | Fix ownership/permissions. `group: null` = preserve existing (distro-dependent). |
| `login_defs` | `key`, `value` | Set in `/etc/login.defs`. Affects new accounts only. |
| `package_remove` | `packages[]` | Remove packages. Resolved per host at plan time. |
| `package_install` | `packages{apt[],dnf[]}` | Install; pick the list by `facts.package_manager`. |
| `package_update` | `security_only: true` | Apply security updates. |
| `service_enable` | `unit`, optional `note` | Enable/start a unit. `a\|b` = alternatives; choose by family. |
| `reboot` | — | Reboot required. |
| `manual` | `note` | **Needs a human.** Never automate. |

## Worked example

```python
import json

plan = json.load(open("plan.json"))
assert plan["schema"] == "linux-audit.remediation-plan"
assert plan["schema_version"].split(".")[0] == "1"

for host in plan["hosts"]:
    fam = host["facts"]["os_family"]
    safe = [i for i in host["remediation"] if not i["disruptive"]]
    risky = [i for i in host["remediation"] if i["disruptive"]]

    for item in safe:
        apply_fix(host["host"], fam, item["action"])   # your executor

    for item in risky:
        print(f"{host['host']}: {item['key']} needs approval — {item['caution']}")
```

## Design notes

- **Only FAIL/WARN produce items.** A clean host yields an empty `remediation`
  list, so an executor can no-op safely.
- **`@observed` is resolved at plan time**, not by the consumer. For example
  `package_remove` arrives with a concrete `packages: ["telnet"]`.
- **Every entry in the `REMEDIATION` table is covered by a test** asserting the
  `check_id` is actually emitted by the CIS engine, so the contract cannot
  silently rot.
- **Highest-risk item is `3.5.1` (enable firewall).** Enabling default-deny over
  SSH without allowing the SSH port first loses the host. It is marked
  `disruptive` and carries a caution.
- **`3.2.1` (`ip_forward=0`) is `WARN`, not `FAIL`,** because Docker, Kubernetes,
  VPNs, NAT and routers legitimately require `ip_forward=1`.

## Privacy

The plan describes your infrastructure and its weaknesses in machine-readable
form. It is at least as sensitive as the Excel report. `.gitignore` excludes
`plan.json` and `*.plan.json`; keep it that way.
