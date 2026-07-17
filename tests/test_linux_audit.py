"""Unit tests for linux_audit. Deterministic; no network or SSH required."""
import os
import zipfile
import types
import tempfile

import linux_audit as la


RHEL = """@@SECTION hostname
db01.corp.internal
@@SECTION os_release
PRETTY_NAME="Red Hat Enterprise Linux 9.3 (Plow)"
@@SECTION kernel
Linux 5.14.0-362.el9.x86_64
x86_64
@@SECTION uptime
up 5 days
0.10 0.05 0.01 1/200 1234
@@SECTION ipaddr
2: ens192 inet 172.16.4.20/22
@@SECTION disk
/dev/mapper/rhel-root xfs 50G 21G 29G 42% /
/dev/mapper/rhel-var xfs 30G 27G 3G 91% /var
@@SECTION listening
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
@@SECTION ssh_effective
permitrootlogin no
passwordauthentication no
permitemptypasswords no
maxauthtries 3
x11forwarding no
clientaliveinterval 300
logingracetime 60
@@SECTION selinux
selinux:Enforcing
apparmor:absent
@@SECTION firewall
firewalld:running
@@SECTION updates
mgr:dnf
pending:0
security:0
@@SECTION reboot_required
no
@@SECTION sysctl
kernel.randomize_va_space=2
net.ipv4.ip_forward=0
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
@@SECTION uid0
root
@@SECTION logindefs
PASS_MAX_DAYS\t90
PASS_MIN_DAYS\t7
PASS_WARN_AGE\t7
@@SECTION timesync
NTP=yes
NTPSynchronized=yes
@@SECTION file_perms
/etc/ssh/sshd_config 600 root root
/etc/passwd 644 root root
/etc/shadow 000 root root
/etc/group 644 root root
/etc/gshadow 000 root root
@@SECTION packages
bash\t5.1.8-6.el9
openssl\t3.0.7-2.el9
@@END
"""


def test_version_and_build():
    assert la.__version__
    assert la.BUILD


def test_parse_hosts(tmp_path):
    p = tmp_path / "hosts.txt"
    p.write_text("# comment\n\nweb01.example.com\nadmin@db01:2222   # inline\n")
    hosts = la.parse_hosts(str(p))
    assert len(hosts) == 2
    assert hosts[0]["target"] == "web01.example.com"
    assert hosts[1]["user"] == "admin" and hosts[1]["port"] == "2222"


def test_split_sections():
    sec = la.split_sections(RHEL)
    assert "hostname" in sec and "disk" in sec
    assert sec["hostname"][0] == "db01.corp.internal"


def test_parse_ipaddr_strips_cidr_and_loopback():
    ips = la.parse_ipaddr(["2: lo inet 127.0.0.1/8", "2: ens192 inet 172.16.4.20/22"])
    assert ips == ["172.16.4.20"]


def test_parse_disk():
    rows = la.parse_disk(["/dev/sda1 ext4 40G 37G 1.2G 97% /"])
    assert rows[0]["mount"] == "/" and rows[0]["use_pct"] == "97%"


def test_build_record_core_fields():
    rec = la.build_record("db01", RHEL)
    assert rec["distro"].startswith("Red Hat")
    assert rec["arch"] == "x86_64"
    assert "172.16.4.20" in rec["ips"]
    assert rec["root_pct"] == 42


def test_findings_flag_full_disk():
    rec = la.build_record("db01", RHEL)
    cats = [f[1] for f in rec["findings"]]
    # /var is 91% -> a High disk finding must exist
    assert any(f[0] == "High" and f[1] == "Disk" for f in rec["findings"]), cats


def test_cis_hardened_host_passes_key_checks():
    rec = la.build_record("db01", RHEL)
    results = {cid: res for cid, _desc, res, _det in rec["cis"]}
    assert results["5.2.1"] == "PASS"      # root login disabled
    assert results["1.5.1"] == "PASS"      # ASLR
    assert results["3.5.1"] == "PASS"      # firewall active
    assert results["6.2.1"] == "PASS"      # single UID 0


def test_guard_formula_forces_text():
    from openpyxl import Workbook
    wb = Workbook()
    c = wb.active.cell(row=1, column=1, value="=2")
    la._guard_formula(c)
    assert c.data_type == "s"


def test_workbook_has_no_formula_cells():
    rec = la.build_record("db01", RHEL)
    args = types.SimpleNamespace(escalate="sudo", deep=False,
                                 packages=True, host_tabs=True)
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "out.xlsx")
        args.output = out
        la.make_workbook([rec], [], args)
        z = zipfile.ZipFile(out)
        offenders = [n for n in z.namelist()
                     if n.startswith("xl/worksheets/") and n.endswith(".xml")
                     and b"<f>" in z.read(n)]
    assert offenders == [], offenders


# ── regression: firewall substring bug (v1.0.0) ─────────────────────────────
# 'inactive' contains 'active' and 'not running' contains 'running'. A naive
# substring test reported firewall-less hosts as protected: a false PASS.

def test_firewall_inactive_is_not_active():
    assert la.parse_firewall(["ufw:Status: inactive", "iptables_rules:2"])[0] is False


def test_firewall_not_running_is_not_active():
    assert la.parse_firewall(["firewalld:not running"])[0] is False


def test_firewall_active_states_detected():
    assert la.parse_firewall(["ufw:Status: active"])[0] is True
    assert la.parse_firewall(["firewalld:running"])[0] is True
    assert la.parse_firewall(["nftables_lines:40"])[0] is True
    assert la.parse_firewall(["iptables_rules:25"])[0] is True


def test_firewall_thresholds_not_tripped_by_defaults():
    assert la.parse_firewall(["nftables_lines:1"])[0] is False
    assert la.parse_firewall(["iptables_rules:3"])[0] is False


# ── remediation plan (--plan-out) ───────────────────────────────────────────

def _plan_for(raw, host="h1"):
    rec = la.build_record(host, raw)
    args = types.SimpleNamespace(output="x.xlsx", escalate="sudo", deep=False,
                                 packages=True, host_tabs=True, plan_out="p.json")
    return la.build_plan([rec], [], args), rec


def test_plan_schema_and_shape():
    plan, _ = _plan_for(RHEL)
    assert plan["schema"] == la.PLAN_SCHEMA
    assert plan["schema_version"] == la.PLAN_SCHEMA_VERSION
    assert plan["generator"]["version"] == la.__version__
    assert set(["summary", "hosts", "unreachable", "notes"]).issubset(plan)


def test_plan_hardened_host_has_no_remediation():
    plan, _ = _plan_for(RHEL)
    h = plan["hosts"][0]
    assert h["counts"]["cis_fail"] == 0
    assert h["remediation"] == []


def test_plan_os_family_detection():
    plan, _ = _plan_for(RHEL)
    assert plan["hosts"][0]["facts"]["os_family"] == "rhel"


def test_plan_is_json_serialisable():
    import json as _json
    plan, _ = _plan_for(RHEL)
    s = _json.dumps(plan)          # must not raise: no lambdas/sets may leak in
    assert _json.loads(s)["schema"] == la.PLAN_SCHEMA


def test_every_remediation_entry_is_wellformed():
    """The table is the contract with the downstream tool: police its shape."""
    for cid, spec in la.REMEDIATION.items():
        assert callable(spec["observed"]), cid
        assert "type" in spec["action"], cid
        assert isinstance(spec.get("disruptive", False), bool), cid
        assert isinstance(spec.get("reboot", False), bool), cid
        assert isinstance(spec.get("restart", []), list), cid


def test_remediation_ids_match_real_checks():
    """Every id in REMEDIATION must be produced by derive_cis, or it is dead code
    that will silently never fire."""
    _, rec = _plan_for(RHEL)
    known = {c[0] for c in rec["cis"]}
    unknown = set(la.REMEDIATION) - known
    assert not unknown, "REMEDIATION ids not emitted by derive_cis: %s" % sorted(unknown)


def test_disruptive_items_are_flagged():
    """Safety-critical: these must never be auto-applied."""
    for cid in ("3.5.1", "5.2.2", "1.10", "3.2.1"):
        assert la.REMEDIATION[cid]["disruptive"] is True, cid
        assert la.REMEDIATION[cid]["caution"], "%s needs a caution note" % cid
