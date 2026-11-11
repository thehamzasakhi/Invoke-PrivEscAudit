# Invoke-PrivEscAudit

A read-only Windows **privilege-escalation** and **credential-exposure** enumeration tool for authorized penetration tests and configuration audits. Built in the spirit of winPEAS, but rebuilt around a **structured findings model** — every check emits a severity-ranked object with evidence and remediation, so results export cleanly to JSON / CSV / HTML for reporting instead of scrolling past colored console text.

> ⚠️ **Authorized use only.** Run this only on systems you own or have explicit written permission to assess. It is strictly read-only — it enumerates and reports misconfigurations; it does **not** exploit, modify, or persist.

---

## Why this over winPEAS.ps1

| | winPEAS.ps1 | Invoke-PrivEscAudit |
|---|---|---|
| Output | `Write-Host` only | Structured `[Finding]` objects |
| Severity model | None | Info → Critical, per finding |
| Reporting | Copy/paste console | JSON / CSV / **HTML report** |
| Remediation notes | No | Yes, per finding |
| Speed control | All-or-nothing | `Quick / Standard / Deep` tiers |
| Secret scan | Always-on, whole-drive | Opt-in, scoped, **masked output** |
| `Win32_Product` risk | Uses it (can trigger MSI repairs) | Avoided |

---

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Runs as a standard or privileged user (more findings surface with higher privilege)
- No external modules or binaries required

---

## Usage

```powershell
# Default: Quick depth, console + HTML report, all severities
.\Invoke-PrivEscAudit.ps1

# Full local audit with secret scan, medium+ only, all export formats
.\Invoke-PrivEscAudit.ps1 -Depth Standard -SecretScan -MinSeverity Medium -Format Console,Json,Csv,Html

# Deep run (includes slow drive/registry sweeps + all-drive secret scan)
.\Invoke-PrivEscAudit.ps1 -Depth Deep -SecretScan

# Secret scan targeting specific server roots
.\Invoke-PrivEscAudit.ps1 -SecretScan -ScanRoots "C:\inetpub","D:\apps" -MaxFileSizeKB 4096
```

### Parameters

| Parameter | Values | Default | Description |
|---|---|---|---|
| `-Depth` | `Quick` / `Standard` / `Deep` | `Quick` | Controls scan breadth. Quick skips slow sweeps. |
| `-Format` | `Console` `Json` `Csv` `Html` | `Console,Html` | One or more output formats. |
| `-MinSeverity` | `Info` … `Critical` | `Info` | Lowest severity to display/export. |
| `-OutputPath` | path | current dir | Destination for report files. |
| `-SecretScan` | switch | off | Enables the credential/secret file scan. |
| `-ScanRoots` | path[] | common config/user dirs | Folders to scan when `-SecretScan` is set. |
| `-MaxFileSizeKB` | int | `2048` | Skip files larger than this during the secret scan. |

Report files are written as `PrivEscAudit_<HOST>_<timestamp>.{json,csv,html}`.

---

## Checks

### Privilege escalation

- **System context** — OS, build, architecture, domain membership, and hotfix recency (stale-patch signal)
- **Token privileges** — flags exploitable rights (`SeImpersonate`, `SeBackup`/`SeRestore`, `SeDebug`, `SeLoadDriver`, `SeTakeOwnership`, `SeCreateToken`, `SeTcb`, `SeManageVolume`, `SeEnableDelegation`) with the abuse path; High when enabled
- **Users & groups** — membership of Administrators, Backup Operators, RDP, Remote Management, Hyper-V Admins, DnsAdmins
- **AlwaysInstallElevated** — Critical when both HKLM + HKCU are set
- **Services** — unquoted service paths, writable service binaries, writable service registry keys (ImagePath / ServiceDll rewrite)
- **Scheduled tasks** — writable task binaries, severity weighted by run-as principal
- **Autoruns** — writable Run / RunOnce targets (HKLM vs HKCU weighted)
- **PATH** — writable directories enabling binary planting / DLL search-order hijack
- **UAC** — `EnableLUA`, consent prompt behavior, `LocalAccountTokenFilterPolicy`
- **Defender / AV** — real-time state, tamper protection, signature age, path exclusions

### Credential exposure

- Unattend / sysprep answer files (embedded admin passwords)
- Readable SAM / SYSTEM hive backups
- Winlogon autologon cleartext credentials
- Credential Manager stored targets
- Cloud credential files (AWS / Azure / GCP)
- PuTTY stored proxy passwords
- PowerShell console history with secret-like lines
- Group Policy Preferences `cpassword`

### Secret scan (`-SecretScan`)

Content scan across scoped roots with ~30 regex patterns, each severity-tagged. Matched values are **masked** in output so the report doesn't become a secret store.

- Generic assignments: `password` / `pwd` / `secret` / `api_key` / token / username
- Connection strings: SQL/ODBC/OLEDB password fields; `mongodb://` `postgres://` `redis://` `mysql://` URIs with inline credentials
- Private keys: PEM `PRIVATE KEY` blocks, PuTTY `.ppk`
- JWTs
- Cloud/vendor keys: AWS access-key IDs & secret keys, Google, Slack, GitHub, GitLab, Stripe, Twilio, SendGrid, Azure storage keys/SAS
- Windows leftovers: GPP `cpassword`, `net user /add`, `ConvertTo-SecureString -AsPlainText`

Scoped by default to `inetpub`, `ProgramData`, IIS config, user profiles, and `Users\Public` (all fixed drives under `-Depth Deep`). Extension-filtered to config/code/text; skips WinSxS, servicing, `$Recycle.Bin`, `node_modules`, `.git`.

---

## Output

- **Console** — severity-ranked summary with counts and per-finding remediation
- **HTML** — dark-themed, severity-colored report with evidence + remediation per row
- **JSON / CSV** — for ingestion into finding trackers or further processing

---

## Scope & limitations

This is a **local-host** enumeration tool. It deliberately does **not** cover:

- **Active Directory / domain** — Kerberoasting, AS-REP roasting, delegation, ACL abuse paths, ADCS (ESC1–ESC16), LAPS, SYSVOL
- **Server-role configs** — SQL Server, IIS, Exchange specifics
- **CVE / missing-patch mapping** against installed hotfixes
- **DPAPI / LSASS extraction** — it locates preconditions only; it does not decrypt or touch LSASS
- **Opsec evasion** — it uses standard WMI/registry/`whoami` calls and is not tuned to be quiet

For a complete server engagement, pair it with BloodHound / PowerView / Certify / Rubeus (AD & ADCS), WES-NG / Watson (patch CVEs), and role-specific tooling.

### False positives

Broad credential hunting inherently produces false positives — generic `password=` / `user=` matches will fire on benign config files. Findings are severity-tagged so you can filter; verify before reporting.

---

## Credit

Inspired by [PEASS-ng / winPEAS](https://github.com/peass-ng/PEASS-ng). This is an independent reimplementation, not a fork.

