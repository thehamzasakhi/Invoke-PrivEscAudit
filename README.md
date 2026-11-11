# Invoke-PrivEscAudit

Read-only **privilege-escalation** and **credential-exposure** enumeration for **Windows and Linux**, for authorized penetration tests and configuration audits. Built in the spirit of winPEAS / linPEAS, but rebuilt around a **structured findings model** — every check emits a severity-ranked finding with evidence and remediation, so results export cleanly to JSON / CSV / HTML for reporting instead of scrolling past colored console text.

| Script | Platform | Language |
|---|---|---|
| [`Invoke-PrivEscAudit.ps1`](Invoke-PrivEscAudit.ps1) | Windows | PowerShell 5.1 / 7+ |
| [`privesc-audit.sh`](privesc-audit.sh) | Linux (Ubuntu/Debian first, degrades on other distros) | bash 4.4+ |

Both scripts share the same severity model, depth tiers, masked secret scan, output formats and report file naming. Windows details come first below; see [Linux: `privesc-audit.sh`](#linux-privesc-auditsh) for the Linux script.

> ⚠️ **Authorized use only.** Run this only on systems you own or have explicit written permission to assess. It is strictly read-only — it enumerates and reports misconfigurations; it does **not** exploit, modify, or persist.

---

## Why this over winPEAS.ps1 / linPEAS.sh

| | winPEAS.ps1 | Invoke-PrivEscAudit |
|---|---|---|
| Output | `Write-Host` only | Structured `[Finding]` objects |
| Severity model | None | Info → Critical, per finding |
| Reporting | Copy/paste console | JSON / CSV / **HTML report** |
| Remediation notes | No | Yes, per finding |
| Speed control | Default / `-FullCheck` | `Quick / Standard / Deep` tiers |
| Secret scan | Username/password search of drives & registry on by default | Opt-in, scoped, **masked output** |
| Localized Windows | — | Checks keyed on SIDs / privilege names, not English UI text |

The Linux script follows the same model: structured findings with severity, evidence and remediation, JSON / CSV / HTML export, `Quick / Standard / Deep` tiers and an opt-in, scoped, masked secret scan.

---

## Requirements

**Windows (`Invoke-PrivEscAudit.ps1`)**

- Windows PowerShell 5.1 or PowerShell 7+
- Runs as a standard or privileged user (more findings surface with higher privilege)
- No external modules or binaries required

**Linux (`privesc-audit.sh`)**

- bash 4.4+ (Ubuntu 18.04+ / Debian 10+), coreutils, findutils, GNU grep
- Optional, used when present: `getcap` (libcap2-bin), `ss` or `netstat`, `systemctl`, `sudo`, `capsh`
- Runs as any user; run it as the low-privileged account under test for the attacker's-eye view

---

## Windows: running the script (execution policy)

Windows blocks `.ps1` scripts by default (`Restricted` on clients, `RemoteSigned` on servers). Use any of these. None of them permanently changes the machine's policy.

**Option 1: one-off launch (recommended)**

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-PrivEscAudit.ps1

# with parameters
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-PrivEscAudit.ps1 -Depth Standard -SecretScan -Format Console,Json,Html
```

**Option 2: current session only**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Invoke-PrivEscAudit.ps1
```

This setting ends when the window closes and does not need admin rights.

**Option 3: downloaded file**

Files downloaded from the internet carry a Mark-of-the-Web flag that `RemoteSigned` blocks. Clear it:

```powershell
Unblock-File .\Invoke-PrivEscAudit.ps1
```

**Option 4: in-memory**

```powershell
Get-Content .\Invoke-PrivEscAudit.ps1 -Raw | Invoke-Expression
```

This runs with default parameters only (Quick depth, Console + HTML).

### When it still won't run

- **AppLocker / WDAC**: application control policies can block the script regardless of execution policy.
- **Constrained Language Mode**: check with `$ExecutionContext.SessionState.LanguageMode`. If it isn't `FullLanguage`, parts of the script will fail because it uses .NET types directly.
- **Defender / AMSI**: the secret-scan patterns and privilege names may trigger detection. On an authorized engagement, agree an exclusion with the client rather than attempting to evade it.

---

## Windows: usage

```powershell
# Default: Quick depth, console + HTML report, all severities
.\Invoke-PrivEscAudit.ps1

# Full local audit with secret scan, medium+ only, all export formats
.\Invoke-PrivEscAudit.ps1 -Depth Standard -SecretScan -MinSeverity Medium -Format Console,Json,Csv,Html

# Deep run: secret scan widened to every fixed drive (slow)
.\Invoke-PrivEscAudit.ps1 -Depth Deep -SecretScan

# Secret scan targeting specific server roots
.\Invoke-PrivEscAudit.ps1 -SecretScan -ScanRoots "C:\inetpub","D:\apps" -MaxFileSizeKB 4096
```

### Parameters

| Parameter | Values | Default | Description |
|---|---|---|---|
| `-Depth` | `Quick` / `Standard` / `Deep` | `Quick` | `Standard` adds PuTTY, PowerShell history and cached GPP checks. `Deep` = Standard, plus all fixed drives as default `-SecretScan` roots (no effect without `-SecretScan`). |
| `-Format` | `Console` `Json` `Csv` `Html` | `Console,Html` | One or more output formats. |
| `-MinSeverity` | `Info` … `Critical` | `Info` | Lowest severity to display/export. |
| `-OutputPath` | path | current dir | Destination for report files. |
| `-SecretScan` | switch | off | Enables the credential/secret file scan. |
| `-ScanRoots` | path[] | common config/user dirs | Folders to scan when `-SecretScan` is set. |
| `-MaxFileSizeKB` | int | `2048` | Skip files larger than this during the secret scan. |

Report files are written as `PrivEscAudit_<HOST>_<timestamp>.{json,csv,html}`.

---

## Windows: checks

### Privilege escalation

- **System context** — OS, build, architecture, domain membership, and hotfix recency (stale-patch signal)
- **Token privileges** — flags exploitable rights (`SeImpersonate`, `SeAssignPrimaryToken`, `SeBackup`/`SeRestore`, `SeDebug`, `SeLoadDriver`, `SeTakeOwnership`, `SeCreateToken`, `SeTcb`, `SeManageVolume`, `SeEnableDelegation`) with the abuse path; High when held (a disabled privilege in the token can be enabled by its holder)
- **Users & groups** — elevation + integrity level; membership of Administrators, Backup Operators, RDP, Remote Management, Hyper-V Admins (resolved by SID), DnsAdmins
- **AlwaysInstallElevated** — Critical when both HKLM + HKCU are set
- **Services** — unquoted service paths, writable service binaries, writable service registry keys (ImagePath / ServiceDll / Performance subkey)
- **Scheduled tasks** — writable task binaries *and* script/binary paths in task arguments; High when the task runs as SYSTEM / a service account, as Administrators, or with highest privileges
- **Autoruns** — writable Run / RunOnce targets (HKLM vs HKCU weighted)
- **PATH** — writable directories on the **machine** PATH enabling binary planting / DLL search-order hijack
- **UAC** — `EnableLUA`, consent prompt behavior, `LocalAccountTokenFilterPolicy`
- **Defender / AV** — real-time state, tamper protection, signature age, path exclusions

### How writability is decided

Service, task, autorun and PATH checks evaluate the file/registry ACL against the current token's SIDs: only ACEs that apply to the object itself (inherit-only ACEs skipped), generic rights mapped to specific ones, Deny ACEs subtracted. A file counts as writable with WriteData / ChangePermissions / TakeOwnership; a missing file counts if its nearest existing folder allows creating files (or folders, when intermediate folders are missing).

When the script runs **elevated**, Administrators and SYSTEM ACEs are ignored. Otherwise nearly every ACL on the box would show as "writable". For the true low-privilege picture, run it as the low-privilege user you are assessing.

### Credential exposure

All depths:

- Unattend / sysprep answer files (embedded admin passwords)
- Readable, non-empty SAM / SYSTEM hive backups
- Winlogon autologon: cleartext `DefaultPassword` (High) vs autologon without one (Low)
- Credential Manager stored targets
- Cloud credential files (AWS / Azure / GCP) across user profiles

`-Depth Standard` or `Deep` only:

- PuTTY stored proxy passwords
- PowerShell console history with secret-like lines (current user)
- Cached Group Policy Preferences `cpassword`

### Secret scan (`-SecretScan`)

Content scan across scoped roots with 24 regex patterns, each severity-tagged. Matched values are **masked** in output: the key name is kept, plus at most the first 2 characters of the value (4 for bare tokens such as `AKIA…`), followed by a fixed-length mask. The report doesn't become a secret store and doesn't reveal secret lengths.

- Generic assignments: `password` / `pwd` / `secret` / `api_key` / token / username
- Connection strings: SQL/ODBC/OLEDB password fields; `mongodb://` `postgres://` `redis://` `mysql://` `amqp://` URIs with inline credentials
- Private keys: PEM `PRIVATE KEY` blocks, PuTTY `.ppk`
- JWTs
- Cloud/vendor keys: AWS access-key IDs & secret keys, Google, Slack, GitHub, GitLab, Stripe, Twilio, SendGrid, Azure storage keys/SAS
- Windows leftovers: GPP `cpassword`, `net user /add`, `ConvertTo-SecureString -AsPlainText`

Scoped by default to `inetpub`, `xampp`, `ProgramData`, IIS config, the **current user's** profile, and `Users\Public` (all fixed drives under `-Depth Deep`). Extension-filtered to config/code/text; skips WinSxS, servicing, `$Recycle.Bin`, `node_modules`, `.git`.

---

## Output

Both scripts produce the same outputs:

- **Console** — severity-ranked summary with counts and per-finding remediation (the Linux script also prints the first evidence lines for High / Critical)
- **HTML** — dark-themed, severity-colored report with evidence + remediation per row
- **JSON / CSV** — for ingestion into finding trackers or further processing. JSON fields: `Category`, `Title`, `Severity`, `SevRank`, `Evidence`, `Remediation`, `Timestamp`. In the Linux JSON, `Evidence` is a string of `Key: value` lines.

Report files are named `PrivEscAudit_<HOST>_<timestamp>.{json,csv,html}`. The Linux script creates them with `0600` permissions because they contain sensitive evidence.

---

## Scope & limitations

This is a **local-host** enumeration tool. It deliberately does **not** cover:

- **Active Directory / domain** — Kerberoasting, AS-REP roasting, delegation, ACL abuse paths, ADCS (ESC1–ESC16), LAPS, SYSVOL
- **Server-role configs** — SQL Server, IIS, Exchange specifics
- **CVE / missing-patch mapping** against installed hotfixes
- **DPAPI / LSASS extraction** — it locates preconditions only; it does not decrypt or touch LSASS
- **Opsec evasion** — it uses standard WMI/registry/`whoami` calls and is not tuned to be quiet

For a complete server engagement, pair it with BloodHound / PowerView / Certify / Rubeus (AD & ADCS), WES-NG / Watson (patch CVEs), and role-specific tooling.

The Linux script has the equivalent limits: no kernel / package CVE mapping (pair with linux-exploit-suggester), no exploitation, no process monitoring (use pspy to catch short-lived root jobs), and it is not tuned for opsec.

### False positives

Broad credential hunting inherently produces false positives — generic `password=` / `user=` matches will fire on benign config files. Findings are severity-tagged so you can filter; verify before reporting.

---

## Linux: `privesc-audit.sh`

### Running the script

```bash
chmod +x privesc-audit.sh
./privesc-audit.sh

# or, without the execute bit (also works on noexec mounts such as a hardened /tmp)
bash privesc-audit.sh -d Standard

# piped, nothing written to disk except the reports
cat privesc-audit.sh | bash -s -- -d Standard -s
```

Run it with `bash`, not `sh`: on Ubuntu `sh` is dash, and the script exits with a message if it isn't under bash 4.4+.

### Usage

```bash
# Default: Quick depth, console + HTML report, all severities
./privesc-audit.sh

# Full local audit with secret scan, medium+ only, all export formats
./privesc-audit.sh -d Standard -s -m Medium -f console,json,csv,html

# Deep run (full-filesystem writable sweep + capability scan + secret scan of /)
./privesc-audit.sh -d Deep -s

# Secret scan targeting specific roots, larger file limit
./privesc-audit.sh -s -r /var/www,/opt/apps -x 4096

# Skip the sudo -l probe (it is written to auth.log)
./privesc-audit.sh --no-sudo
```

### Options

| Option | Windows equivalent | Values | Default | Description |
|---|---|---|---|---|
| `-d, --depth` | `-Depth` | `Quick` / `Standard` / `Deep` | `Quick` | Controls scan breadth (case-insensitive). |
| `-f, --format` | `-Format` | comma list of `console,json,csv,html` | `console,html` | One or more output formats. |
| `-m, --min-severity` | `-MinSeverity` | `Info` … `Critical` | `Info` | Lowest severity to display/export. |
| `-o, --output-path` | `-OutputPath` | dir | current dir | Destination for report files. |
| `-s, --secret-scan` | `-SecretScan` | flag | off | Enables the credential/secret file scan. |
| `-r, --scan-roots` | `-ScanRoots` | comma list of dirs | common config/user dirs | Folders to scan; implies `-s`. |
| `-x, --max-file-size-kb` | `-MaxFileSizeKB` | int | `2048` | Skip files larger than this during the secret scan. |
| `--no-sudo` | n/a | flag | off | Don't run `sudo -n -l`. |
| `--no-color` | n/a | flag | off | Disable ANSI colors (colors are off automatically when output isn't a terminal). |
| `-v, --verbose` | `-Verbose` | flag | off | Per-section timings on stderr. |
| `-h, --help` | `Get-Help` | | | Show usage. |

### Depth tiers

| Tier | Adds |
|---|---|
| `Quick` | All core checks below. SUID search over `/` (pruning `/proc`, `/sys`, `/dev`, `/run`, `/snap`, container storage, network mounts); capability scan of standard system/app dirs. |
| `Standard` | Pending package / security updates (`apt-check` or `apt-get -s`), systemd timer list, application config credential hunt (`wp-config.php`, `.env`, `settings.py`, `tomcat-users.xml`, `*.tfstate`, `*.kdbx`...), root processes running modifiable files, writable-file sweep of `/etc`, `/opt`, `/srv`, `/usr/local`. |
| `Deep` | Writable-file sweep across `/etc`, `/usr`, `/boot`, `/bin`, `/sbin`, `/lib*`, `/var`, `/root`, `/home`; capability scan of every top-level dir; SUID search includes `/snap`; secret scan of `/` by default. |

### Checks

#### Privilege escalation

- **System context** — OS, kernel, arch, virtualization, container detection, last package change age (stale-patch signal: Low > 60 days, Medium > 120), reboot pending / running kernel older than installed
- **Sudo** — `sudo -n -l` (never prompts): `NOPASSWD: ALL` (Critical), GTFOBins-style binaries, wildcard arguments, writable command binaries, `SETENV`, `env_keep` of `LD_PRELOAD` / `LD_LIBRARY_PATH` / `PYTHONPATH`, `!env_reset`, writable `secure_path` dirs; writable `sudoers` / `sudoers.d` / `sudo.conf`; readable NOPASSWD rules
- **SUID / SGID** — writable setuid binaries (Critical), GTFOBins-style SUID/SGID binaries, non-standard setuid binaries (weighted up in `/home`, `/tmp`, `/opt`, `/usr/local`...), full inventory
- **Capabilities** — dangerous file capabilities (`cap_setuid`, `cap_dac_*`, `cap_sys_admin`, `cap_sys_ptrace`, `cap_sys_module`...; Critical on interpreters), writable binaries carrying capabilities, current process capabilities
- **Users & groups** — root-equivalent groups (`docker`, `lxd`, `lxc`, `incus-admin`, `libvirt`, `microk8s`, `disk`, `shadow`) and weaker ones (`sudo`/`admin`/`wheel`, `adm`, `systemd-journal`, `video`), non-root UID 0 accounts, hashes or empty passwords in `/etc/passwd`, listable home dirs
- **Services** — writable systemd unit files and unit directories, writable `Exec*=` binaries and script arguments, writable `EnvironmentFile=`, writable dirs in the systemd manager PATH, writable SysV init scripts / `rc.local`; severity weighted by the unit's `User=`
- **Cron** — writable `/etc/crontab`, `cron.d`, spool and `cron.{hourly,daily,...}` dirs/scripts, writable dirs in crontab `PATH`, hijackable relative commands, wildcard-injection candidates (`tar` / `chown` / `chmod` / `rsync` with `*`), readable user crontabs
- **Autoruns / login hooks / loader** — `ld.so.preload`, `ld.so.conf(.d)` and the library dirs they list, PAM, `/etc/passwd` / `group` / `shadow`, profile / bashrc / `/etc/environment`, `update-motd.d`, APT hooks, logrotate, modprobe, udev rules, NetworkManager dispatcher, sshd config, XDG autostart, other users' dotfiles / `.ssh` / `authorized_keys`
- **PATH** — `.` / empty / relative entries, writable `$PATH` dirs, writable dirs in `/etc/environment` PATH (High: affects root logins)
- **Containers & sockets** — writable docker / containerd / CRI-O / podman / LXD / Incus / BuildKit / libvirt / k3s sockets (Critical), privileged container (full capability set), readable host block devices, mounted Kubernetes service-account token, NFS exports with `no_root_squash`, network mounts
- **Processes** — credentials in process command lines (masked); root processes executing modifiable binaries/scripts (Standard+)
- **Kernel hardening** (the UAC equivalent) — `randomize_va_space`, `yama.ptrace_scope`, `kptr_restrict`, `dmesg_restrict`, `unprivileged_bpf_disabled`, unprivileged user namespaces, `protected_symlinks` / `hardlinks` / `regular`, `suid_dumpable`, `mmap_min_addr`, `/tmp` / `/dev/shm` / `/var/tmp` mount options
- **Defensive tooling** (the Defender equivalent) — AppArmor / SELinux state, auditd, ufw, common EDR/AV agents (Falcon, MDE, ClamAV, Wazuh, osquery, SentinelOne, Carbon Black, Elastic, Falco, Tetragon...)
- **Writable files sweep** (Standard+) — system paths modifiable by non-root principals

#### Credential exposure

- Readable `/etc/shadow`, `gshadow` and their backups (`shadow-`, `/var/backups/*.bak`, `opasswd`); empty passwords
- Cloud / dev credentials in every readable home: `.aws`, `.azure`, `gcloud`, `.kube/config`, `.docker/config.json`, `.git-credentials`, `.netrc`, `.pgpass`, `.my.cnf`, `.npmrc`, `.pypirc`, `gh`, Terraform, Vault, rclone, `.s3cfg`, browser profiles, keyrings, FileZilla, Remmina (High when they belong to another user)
- SSH private keys (with passphrase detection), other users' `known_hosts`
- Shell and client histories with secret-like lines (bash, zsh, mysql, psql, python, redis-cli, sqlite...)
- Root-only secrets that are readable: SSH host keys, `/etc/mysql/debian.cnf`, cloud-init user-data, OpenVPN / IPsec / PPP secrets, `krb5.keytab`, LDAP / SSSD / Samba secrets, postfix SASL, Let's Encrypt and `/etc/ssl/private` keys, k3s / kubeadm admin configs and PKI keys, Jenkins and GitLab secrets
- Credentials in `/etc/fstab` (masked) and readable mount credential files, secret-like strings in the cloud-init output log
- sshd `PermitEmptyPasswords` / `PermitRootLogin yes`
- Usable SSH agent sockets belonging to other users
- Wi-Fi / network PSKs in NetworkManager, wpa_supplicant and netplan files (the WLAN-profile equivalent)
- Application configs with credentials (Standard+)

#### Secret scan (`-s`)

A severity-tagged content scan like the Windows one: 33 regex patterns run with GNU `grep -E`. Matches are masked differently from the Windows script: each sample is cut to 60 characters and its back half replaced with `*`, so the first half of the match (usually the key name) stays visible.

- Generic assignments, connection strings and **any** `scheme://user:pass@` URI
- Private keys, PuTTY keys, JWTs
- Cloud/vendor keys: AWS, Google, Slack, GitHub, GitLab, Stripe, Twilio, SendGrid, Azure storage, HashiCorp Vault, npm, OpenAI/Anthropic-style `sk-` keys, Docker registry `auth`
- Linux leftovers (replacing the Windows-specific ones): Unix crypt / htpasswd hashes, `sshpass -p`, passwords on `mysql` / `psql` / `redis-cli` / `smbclient` / `ldapsearch` command lines, `curl -u` / `wget --password`, `echo ... | sudo -S`, `chpasswd` / `useradd -p`, WPA `psk=`

Default roots: `/etc`, `/opt`, `/srv`, `/var/www`, `/var/backups`, `/var/opt`, `/var/lib/jenkins`, `/usr/local/etc`, `/home`, `/root`, `/tmp`, `/var/tmp`, `/dev/shm`, `/mnt`, `/media` and `$HOME` (`/` under `-d Deep`). Filtered by extension and filename to config/code/text/key files. Skips `/proc`, `/sys`, `/usr/share`, `/usr/lib`, package-manager state and logs, container storage, `node_modules`, `.git`, `site-packages`, and its own reports.

### Running as root vs. a normal user

- **Normal user:** "writable" means *this account* can modify, replace (via a writable parent directory) or create the path. This is the attacker's view.
- **root:** "writable" means a *non-root principal* can modify it (world-writable, writable by a non-root group, or owned by a non-root user), so the run doubles as a configuration audit. `sudo -l` and the "other users' files" checks are skipped or reframed.

### Opsec notes

- `sudo -n -l` is recorded in `auth.log` / the journal; use `--no-sudo` where that matters.
- The script uses ordinary `find`, `grep`, `stat`, `ps`, `getcap` and `systemctl` calls and reads many files quickly, which EDR and auditd rules may flag. On an authorized engagement, agree this with the client in advance.

---

## Credit

Inspired by [PEASS-ng / winPEAS & linPEAS](https://github.com/peass-ng/PEASS-ng). This is an independent reimplementation, not a fork.

