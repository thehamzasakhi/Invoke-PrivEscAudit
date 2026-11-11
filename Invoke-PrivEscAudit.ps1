<#
.SYNOPSIS
    Invoke-PrivEscAudit - Windows local privilege-escalation & credential-exposure
    enumeration for AUTHORIZED penetration tests and configuration audits.

.DESCRIPTION
    A read-only enumeration tool in the spirit of winPEAS, rebuilt around a
    structured findings model instead of console-only output. Every check emits
    a [Finding] object with a severity, the evidence, and a remediation note, so
    results can be sorted, filtered, and exported to JSON / CSV / HTML for
    reporting. No exploitation, no modification, no persistence - it only reads
    system state and flags misconfigurations.

    Use only on systems you own or are explicitly authorized to assess.

.PARAMETER Depth
    Quick    - fast checks only (default). Skips full-drive and full-registry sweeps.
    Standard - Quick plus targeted credential-file locations and common app configs.
    Deep     - Standard plus (optional, slow) recursive drive/registry credential hunt.

.PARAMETER OutputPath
    Folder for exported reports. Defaults to the current directory.

.PARAMETER Format
    One or more of: Console, Json, Csv, Html. Default: Console, Html.

.PARAMETER MinSeverity
    Lowest severity to display/export: Info, Low, Medium, High, Critical. Default Info.

.EXAMPLE
    .\Invoke-PrivEscAudit.ps1
.EXAMPLE
    .\Invoke-PrivEscAudit.ps1 -Depth Deep -Format Console,Json,Html -MinSeverity Low
#>

[CmdletBinding()]
param(
    [ValidateSet('Quick','Standard','Deep')]
    [string]$Depth = 'Quick',

    [string]$OutputPath = (Get-Location).Path,

    [ValidateSet('Console','Json','Csv','Html')]
    [string[]]$Format = @('Console','Html'),

    [ValidateSet('Info','Low','Medium','High','Critical')]
    [string]$MinSeverity = 'Info',

    # Opt-in credential/secret scan of files. Off by default (it is the slow part).
    [switch]$SecretScan,

    # Roots to scan when -SecretScan is set. Defaults to common config/user locations,
    # NOT the whole drive, to stay fast and keep false positives down.
    [string[]]$ScanRoots,

    # Skip files larger than this (KB) during the secret scan.
    [int]$MaxFileSizeKB = 2048
)

#region ---------- Core model & helpers ----------

$script:Findings    = [System.Collections.Generic.List[object]]::new()
$script:Stopwatch   = [System.Diagnostics.Stopwatch]::StartNew()
$script:SevRank     = @{ Info = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }
$script:CurrentUser = "$env:USERDOMAIN\$env:USERNAME"

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Info','Low','Medium','High','Critical')]
        [string]$Severity = 'Info',
        [object]$Evidence,
        [string]$Remediation
    )
    $script:Findings.Add([pscustomobject]@{
        Category    = $Category
        Title       = $Title
        Severity    = $Severity
        SevRank     = $script:SevRank[$Severity]
        Evidence    = $Evidence
        Remediation = $Remediation
        Timestamp   = (Get-Date).ToString('s')
    })
}

function Write-Section {
    param([string]$Name)
    if ($Format -contains 'Console') {
        Write-Host ""
        Write-Host ("===== {0} " -f $Name).PadRight(70,'=') -ForegroundColor Cyan
    }
    Write-Verbose "[$([int]$script:Stopwatch.Elapsed.TotalSeconds)s] $Name"
}

# Return the current principal's effective identity references (user + group SIDs/names).
function Get-IdentityReferences {
    $ids = [System.Collections.Generic.List[string]]::new()
    $ids.Add($script:CurrentUser)
    try {
        $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $ids.Add($wi.User.Value)
        foreach ($g in $wi.Groups) {
            $ids.Add($g.Value)
            try { $ids.Add($g.Translate([System.Security.Principal.NTAccount]).Value) } catch {}
        }
    } catch {}
    # Well-known groups that routinely matter for writability
    'Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users' | ForEach-Object { $ids.Add($_) }
    return ($ids | Sort-Object -Unique)
}
$script:Identities = Get-IdentityReferences

# Does the current principal hold a write-class right on a filesystem path?
# Walks up the tree until an ACL is found. Returns the matched right or $null.
function Test-WritableByMe {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $target = $Path.Trim('"')
    for ($i = 0; $i -lt 12 -and $target; $i++) {
        try {
            if (Test-Path -LiteralPath $target) {
                $acl = Get-Acl -LiteralPath $target -ErrorAction Stop
                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    if ($script:Identities -notcontains $ace.IdentityReference.Value) { continue }
                    $rights = $ace.FileSystemRights.ToString()
                    if ($rights -match 'FullControl|Modify|Write|TakeOwnership|ChangePermissions|CreateFiles|AppendData') {
                        return [pscustomobject]@{
                            Path = $target; Identity = $ace.IdentityReference.Value; Rights = $rights
                        }
                    }
                }
                return $null  # ACL found, no write right -> stop
            }
        } catch {}
        $parent = Split-Path $target -Parent
        if ($parent -eq $target -or [string]::IsNullOrEmpty($parent)) { break }
        $target = $parent
    }
    return $null
}

# Extract the leading executable path from a service/command line, stripping args.
function Get-BinaryPath {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $cl = $CommandLine.Trim()
    if ($cl.StartsWith('"')) {
        $end = $cl.IndexOf('"',1)
        if ($end -gt 1) { return $cl.Substring(1,$end-1) }
    }
    if ($cl -match '^(.*?\.exe)\b') { return $Matches[1] }
    return ($cl -split ' ')[0]
}
#endregion

#region ---------- System & patch context ----------
function Invoke-SystemContext {
    Write-Section 'SYSTEM CONTEXT'
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $ev = [pscustomobject]@{
            Host         = $env:COMPUTERNAME
            OS           = $os.Caption
            Version      = $os.Version
            Build        = $os.BuildNumber
            Arch         = $os.OSArchitecture
            InstallDate  = $os.InstallDate
            LastBoot     = $os.LastBootUpTime
            Domain       = $cs.Domain
            PartOfDomain = $cs.PartOfDomain
            CurrentUser  = $script:CurrentUser
            PSVersion    = $PSVersionTable.PSVersion.ToString()
        }
        Add-Finding -Category 'System' -Title 'Host / OS context' -Severity Info -Evidence $ev
        if ($Format -contains 'Console') { $ev | Format-List | Out-String | Write-Host }
    } catch { Add-Finding -Category 'System' -Title 'OS context unavailable' -Severity Info -Evidence $_.Exception.Message }

    # Hotfix recency - stale patching is a soft privesc signal
    try {
        $last = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending |
                Select-Object -First 1
        if ($last -and $last.InstalledOn) {
            $age = (New-TimeSpan -Start $last.InstalledOn -End (Get-Date)).Days
            $sev = if ($age -gt 120) { 'Medium' } elseif ($age -gt 60) { 'Low' } else { 'Info' }
            Add-Finding -Category 'System' -Title "Most recent hotfix is $age days old" -Severity $sev `
                -Evidence ([pscustomobject]@{ HotFixID = $last.HotFixID; InstalledOn = $last.InstalledOn }) `
                -Remediation 'Confirm patch cadence; stale patching widens the kernel/privesc exploit window.'
        }
    } catch {}
}
#endregion

#region ---------- Token privileges ----------
function Invoke-TokenPrivileges {
    Write-Section 'TOKEN PRIVILEGES'
    # Privileges that routinely lead to SYSTEM when held and enabled
    $hot = @{
        SeImpersonatePrivilege       = 'Potato-family / token impersonation to SYSTEM'
        SeAssignPrimaryTokenPrivilege= 'Assign primary token - SYSTEM via created process'
        SeTcbPrivilege               = 'Act as part of the OS'
        SeBackupPrivilege            = 'Read any file (SAM/SYSTEM hive theft)'
        SeRestorePrivilege           = 'Write any file / registry (service & binary hijack)'
        SeTakeOwnershipPrivilege     = 'Take ownership of any object'
        SeDebugPrivilege             = 'Debug any process (LSASS, token theft)'
        SeLoadDriverPrivilege        = 'Load drivers (vulnerable-driver / BYOVD path)'
        SeCreateTokenPrivilege       = 'Forge arbitrary tokens'
        SeManageVolumePrivilege      = 'Full volume access -> arbitrary file read'
        SeEnableDelegationPrivilege  = 'Configure AD delegation (domain impact)'
    }
    try {
        $raw = whoami.exe /priv /fo csv 2>$null | ConvertFrom-Csv
        foreach ($p in $raw) {
            $name  = $p.'Privilege Name'
            $state = $p.State
            if ($hot.ContainsKey($name)) {
                $sev = if ($state -match 'Enabled') { 'High' } else { 'Medium' }
                Add-Finding -Category 'Token' -Title "$name held ($state)" -Severity $sev `
                    -Evidence ([pscustomobject]@{ Privilege = $name; State = $state }) `
                    -Remediation "Abuse path: $($hot[$name]). Remove from this account unless required."
            }
        }
    } catch {
        Add-Finding -Category 'Token' -Title 'Could not read token privileges' -Severity Info -Evidence $_.Exception.Message
    }
}
#endregion

#region ---------- Users, groups, admin membership ----------
function Invoke-UserContext {
    Write-Section 'USERS & GROUPS'
    try {
        $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $wp = New-Object System.Security.Principal.WindowsPrincipal($wi)
        $isAdmin = $wp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        Add-Finding -Category 'User' -Title "Running as administrator: $isAdmin" `
            -Severity $(if($isAdmin){'Info'}else{'Info'}) `
            -Evidence ([pscustomobject]@{ Admin = $isAdmin; Integrity = 'see token' })
    } catch {}

    foreach ($grp in 'Administrators','Backup Operators','Remote Desktop Users','Remote Management Users','Hyper-V Administrators','DnsAdmins') {
        try {
            $members = Get-LocalGroupMember -Name $grp -ErrorAction Stop
            if ($members) {
                Add-Finding -Category 'User' -Title "Local group '$grp' membership" -Severity Info `
                    -Evidence (@($members | Select-Object Name,PrincipalSource,ObjectClass))
            }
        } catch {}
    }
}
#endregion

#region ---------- AlwaysInstallElevated ----------
function Invoke-AlwaysInstallElevated {
    Write-Section 'AlwaysInstallElevated'
    $hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    if ($hklm -eq 1 -and $hkcu -eq 1) {
        Add-Finding -Category 'Policy' -Title 'AlwaysInstallElevated enabled (HKLM + HKCU)' -Severity Critical `
            -Evidence ([pscustomobject]@{ HKLM = $hklm; HKCU = $hkcu }) `
            -Remediation 'Any user can install an MSI as SYSTEM. Disable both policy values.'
    } elseif ($hklm -eq 1 -or $hkcu -eq 1) {
        Add-Finding -Category 'Policy' -Title 'AlwaysInstallElevated partially set' -Severity Low `
            -Evidence ([pscustomobject]@{ HKLM = $hklm; HKCU = $hkcu }) `
            -Remediation 'Both keys must be 1 to be exploitable, but this indicates policy drift.'
    }
}
#endregion

#region ---------- Services ----------
function Invoke-ServiceChecks {
    Write-Section 'SERVICES'
    $services = @()
    try { $services = Get-CimInstance Win32_Service -ErrorAction Stop } catch { return }

    foreach ($s in $services) {
        if (-not $s.PathName) { continue }

        # Unquoted service path with a space, outside %windir% - classic hijack
        $p = $s.PathName.Trim()
        if ($p -notmatch '^\s*"' -and $p -match '\s' -and $p -notmatch '(?i)\\Windows\\') {
            $firstExe = ($p -split '\.exe',2)[0]
            if ($firstExe -match '\s') {
                Add-Finding -Category 'Service' -Title "Unquoted service path: $($s.Name)" -Severity Medium `
                    -Evidence ([pscustomobject]@{ Name=$s.Name; Path=$s.PathName; StartMode=$s.StartMode; State=$s.State }) `
                    -Remediation 'Quote the ImagePath. Exploitable if a parent dir in the space-split path is writable.'
            }
        }

        # Writable service binary
        $bin = Get-BinaryPath $s.PathName
        if ($bin) {
            $w = Test-WritableByMe $bin
            if ($w) {
                Add-Finding -Category 'Service' -Title "Writable service binary: $($s.Name)" -Severity High `
                    -Evidence ([pscustomobject]@{ Name=$s.Name; Binary=$bin; Identity=$w.Identity; Rights=$w.Rights; StartMode=$s.StartMode }) `
                    -Remediation 'Replaceable service image -> code execution as the service account. Fix ACLs.'
            }
        }
    }

    # Writable service registry config (change ImagePath/binPath)
    try {
        $svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
        Get-ChildItem $svcRoot -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $acl = Get-Acl $_.PSPath -ErrorAction Stop
                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    if ($script:Identities -notcontains $ace.IdentityReference.Value) { continue }
                    if ($ace.RegistryRights -match 'FullControl|SetValue|WriteKey|TakeOwnership|ChangePermissions') {
                        Add-Finding -Category 'Service' -Title "Writable service registry key: $($_.PSChildName)" -Severity High `
                            -Evidence ([pscustomobject]@{ Key=$_.PSChildName; Identity=$ace.IdentityReference.Value; Rights=$ace.RegistryRights.ToString() }) `
                            -Remediation 'Caller can rewrite ImagePath/ServiceDll -> SYSTEM. Tighten key ACL.'
                        break
                    }
                }
            } catch {}
        }
    } catch {}
}
#endregion

#region ---------- Scheduled tasks ----------
function Invoke-ScheduledTaskChecks {
    Write-Section 'SCHEDULED TASKS'
    try {
        Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
            $task = $_
            foreach ($act in @($task.Actions)) {
                $exe = $act.Execute
                if (-not $exe) { continue }
                $resolved = [Environment]::ExpandEnvironmentVariables($exe).Trim('"')
                $w = Test-WritableByMe $resolved
                if ($w) {
                    $principal = try { $task.Principal.UserId } catch { $null }
                    $sev = if ($principal -match 'SYSTEM|Administrators') { 'High' } else { 'Medium' }
                    Add-Finding -Category 'ScheduledTask' -Title "Writable task binary: $($task.TaskName)" -Severity $sev `
                        -Evidence ([pscustomobject]@{ Task=$task.TaskName; Path=$task.TaskPath; Binary=$resolved; RunAs=$principal; Rights=$w.Rights }) `
                        -Remediation 'Replaceable task image runs as the task principal. Fix ACLs on the binary/folder.'
                }
            }
        }
    } catch {
        Add-Finding -Category 'ScheduledTask' -Title 'Scheduled-task enumeration limited' -Severity Info -Evidence $_.Exception.Message
    }
}
#endregion

#region ---------- Autoruns (registry Run keys) ----------
function Invoke-AutorunChecks {
    Write-Section 'AUTORUNS'
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }
        $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $bin = Get-BinaryPath ([Environment]::ExpandEnvironmentVariables([string]$p.Value))
            $w = Test-WritableByMe $bin
            if ($w) {
                $sev = if ($key -like 'HKLM*') { 'High' } else { 'Low' }
                Add-Finding -Category 'Autorun' -Title "Writable autorun binary: $($p.Name)" -Severity $sev `
                    -Evidence ([pscustomobject]@{ Key=$key; Name=$p.Name; Binary=$bin; Rights=$w.Rights }) `
                    -Remediation 'Autorun target is replaceable; HKLM entries run for any logon. Fix ACLs.'
            }
        }
    }
}
#endregion

#region ---------- PATH & writable directories ----------
function Invoke-PathChecks {
    Write-Section 'PATH DIRECTORIES'
    $dirs = $env:PATH -split ';' | Where-Object { $_ } | Sort-Object -Unique
    foreach ($d in $dirs) {
        $expanded = [Environment]::ExpandEnvironmentVariables($d).Trim('"')
        if (-not (Test-Path -LiteralPath $expanded -ErrorAction SilentlyContinue)) { continue }
        $w = Test-WritableByMe $expanded
        if ($w -and $w.Path -eq $expanded) {
            Add-Finding -Category 'PATH' -Title "Writable directory on PATH: $expanded" -Severity Medium `
                -Evidence $w `
                -Remediation 'Writable PATH dir enables binary planting / DLL search-order hijack. Remove or re-ACL.'
        }
    }
}
#endregion

#region ---------- UAC ----------
function Invoke-UacChecks {
    Write-Section 'UAC'
    try {
        $k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
        $ev = [pscustomobject]@{
            EnableLUA              = $k.EnableLUA
            ConsentPromptBehavior  = $k.ConsentPromptBehaviorAdmin
            PromptOnSecureDesktop  = $k.PromptOnSecureDesktop
            FilterAdministratorTok = $k.FilterAdministratorToken
            LocalAccountTokenFilter= (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
        }
        if ($k.EnableLUA -eq 0) {
            Add-Finding -Category 'UAC' -Title 'UAC disabled (EnableLUA=0)' -Severity High -Evidence $ev `
                -Remediation 'Admin-group members run fully elevated. Re-enable UAC.'
        } elseif ($k.ConsentPromptBehaviorAdmin -eq 0) {
            Add-Finding -Category 'UAC' -Title 'UAC elevates without prompt (ConsentPromptBehaviorAdmin=0)' -Severity Medium -Evidence $ev
        } else {
            Add-Finding -Category 'UAC' -Title 'UAC configuration' -Severity Info -Evidence $ev
        }
        if ($ev.LocalAccountTokenFilter -eq 1) {
            Add-Finding -Category 'UAC' -Title 'LocalAccountTokenFilterPolicy=1 (remote admin tokens not filtered)' -Severity Medium -Evidence $ev `
                -Remediation 'Local admins get full tokens over the network -> lateral movement. Review.'
        }
    } catch {}
}
#endregion

#region ---------- Defender / AV ----------
function Invoke-DefenderChecks {
    Write-Section 'DEFENDER / AV'
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $ev = [pscustomobject]@{
            RealTime      = $mp.RealTimeProtectionEnabled
            Tamper        = $mp.IsTamperProtected
            AntivirusOn   = $mp.AntivirusEnabled
            SignatureAge  = $mp.AntivirusSignatureAge
        }
        if (-not $mp.RealTimeProtectionEnabled) {
            Add-Finding -Category 'AV' -Title 'Defender real-time protection OFF' -Severity Medium -Evidence $ev
        } else {
            Add-Finding -Category 'AV' -Title 'Defender status' -Severity Info -Evidence $ev
        }
        # Attack-surface-reduction exclusions can hide payload drop locations
        $pref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($pref.ExclusionPath) {
            Add-Finding -Category 'AV' -Title 'Defender path exclusions present' -Severity Low `
                -Evidence (@($pref.ExclusionPath)) `
                -Remediation 'Excluded paths are common payload-staging locations; confirm they are justified.'
        }
    } catch {
        Add-Finding -Category 'AV' -Title 'Defender status unavailable (third-party AV or restricted)' -Severity Info -Evidence $_.Exception.Message
    }
}
#endregion

#region ---------- Credential exposure ----------
function Invoke-CredentialChecks {
    Write-Section 'CREDENTIAL EXPOSURE'

    # Unattend / sysprep answer files (may contain base64 admin password)
    @(
        "$env:windir\Panther\Unattend.xml"
        "$env:windir\Panther\Unattended.xml"
        "$env:windir\System32\Sysprep\unattend.xml"
        "$env:windir\System32\Sysprep\Panther\unattend.xml"
        "$env:windir\system32\sysprep.inf"
    ) | ForEach-Object {
        if (Test-Path $_ -ErrorAction SilentlyContinue) {
            $hasPwd = $false
            try { $hasPwd = [bool](Select-String -Path $_ -Pattern 'Password' -SimpleMatch -Quiet) } catch {}
            Add-Finding -Category 'Credential' -Title "Unattend/sysprep file: $_" -Severity $(if($hasPwd){'High'}else{'Medium'}) `
                -Evidence ([pscustomobject]@{ Path=$_; ContainsPasswordString=$hasPwd }) `
                -Remediation 'Answer files often embed a (base64) local admin password. Remove after imaging.'
        }
    }

    # SAM / SYSTEM hive backups readable
    @(
        "$env:windir\repair\SAM"
        "$env:windir\System32\config\RegBack\SAM"
        "$env:windir\repair\system"
        "$env:windir\System32\config\RegBack\SYSTEM"
    ) | ForEach-Object {
        if (Test-Path $_ -ErrorAction SilentlyContinue) {
            try { Get-Content -LiteralPath $_ -TotalCount 1 -ErrorAction Stop | Out-Null
                Add-Finding -Category 'Credential' -Title "Readable registry hive backup: $_" -Severity High `
                    -Evidence $_ -Remediation 'SAM+SYSTEM allow offline local-hash extraction. Restrict access.'
            } catch {}
        }
    }

    # Winlogon autologon credentials
    try {
        $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
        if ($wl.DefaultPassword -or ($wl.AutoAdminLogon -eq '1' -and $wl.DefaultUserName)) {
            Add-Finding -Category 'Credential' -Title 'Winlogon autologon credentials in registry' -Severity High `
                -Evidence ([pscustomobject]@{ User=$wl.DefaultUserName; Domain=$wl.DefaultDomainName; PasswordPresent=[bool]$wl.DefaultPassword }) `
                -Remediation 'DefaultPassword is stored in cleartext. Disable autologon or use LSA secrets.'
        }
    } catch {}

    # Credential Manager entries
    try {
        $cm = cmdkey.exe /list 2>$null | Select-String 'Target:'
        if ($cm) {
            Add-Finding -Category 'Credential' -Title 'Credential Manager stored targets' -Severity Low `
                -Evidence (@($cm | ForEach-Object { $_.ToString().Trim() })) `
                -Remediation 'Stored creds may be usable via runas /savecred. Review entries.'
        }
    } catch {}

    # Cloud credential files
    $cloud = @('.aws\credentials','.azure\accessTokens.json','.azure\azureProfile.json',
               'AppData\Roaming\gcloud\credentials.db','AppData\Roaming\gcloud\legacy_credentials')
    try {
        foreach ($u in (Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue)) {
            foreach ($c in $cloud) {
                $fp = Join-Path $u.FullName $c
                if (Test-Path $fp -ErrorAction SilentlyContinue) {
                    Add-Finding -Category 'Credential' -Title "Cloud credential file: $c ($($u.Name))" -Severity Medium `
                        -Evidence $fp -Remediation 'Cloud tokens/keys at rest; may enable pivot to cloud. Confirm scope.'
                }
            }
        }
    } catch {}

    # Common app configs with secrets (standard/deep)
    if ($Depth -ne 'Quick') {
        # PuTTY stored sessions (proxy passwords are obfuscated, not encrypted)
        try {
            Get-ChildItem 'HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions' -ErrorAction Stop | ForEach-Object {
                $sess = Get-ItemProperty $_.PSPath
                if ($sess.ProxyPassword) {
                    Add-Finding -Category 'Credential' -Title "PuTTY proxy password stored: $($_.PSChildName)" -Severity Medium `
                        -Evidence ([pscustomobject]@{ Session=$_.PSChildName; ProxyUser=$sess.ProxyUsername }) `
                        -Remediation 'PuTTY stores the proxy password reversibly. Clear it.'
                }
            }
        } catch {}

        # PowerShell console history with password-like lines
        $histPaths = @(
            (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath
            "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
        ) | Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) } | Sort-Object -Unique
        foreach ($h in $histPaths) {
            try {
                $hits = Select-String -Path $h -Pattern 'password|passwd|-AsPlainText|ConvertTo-SecureString|apikey|secret|token' -ErrorAction Stop
                if ($hits) {
                    Add-Finding -Category 'Credential' -Title "Secrets-like entries in PS history" -Severity Medium `
                        -Evidence ([pscustomobject]@{ File=$h; MatchCount=@($hits).Count }) `
                        -Remediation 'PowerShell history retains cleartext secrets. Clear or avoid inline secrets.'
                }
            } catch {}
        }

        # Group Policy Preferences cpassword (SYSVOL) - still appears in cached copies
        try {
            $gpp = Get-ChildItem "$env:windir\System32\GroupPolicy","$env:ALLUSERSPROFILE\Microsoft\Group Policy" -Recurse -Include *.xml -ErrorAction SilentlyContinue |
                   Select-String -Pattern 'cpassword' -List -ErrorAction SilentlyContinue
            foreach ($g in $gpp) {
                Add-Finding -Category 'Credential' -Title "GPP cpassword in $($g.Path)" -Severity High `
                    -Evidence $g.Path -Remediation 'cpassword is AES-decryptable with a public key (MS14-025). Remove.'
            }
        } catch {}
    }
}
#endregion

#region ---------- Secret / credential file scan (opt-in) ----------

# Regex bank. Each entry: a severity and a .NET regex (case-insensitive applied at match time).
# Tuned to flag assignments and well-formed secret tokens rather than any hex blob,
# to keep false positives manageable on real server filesystems.
$script:SecretPatterns = @(
    # --- Generic credential assignments (key = value / key: value) ---
    [pscustomobject]@{ Name='Password assignment';      Severity='High';   Rx='(?i)(password|passwd|pwd)\s*[:=]\s*[''"]?[^\s''"]{3,}' }
    [pscustomobject]@{ Name='Secret assignment';        Severity='High';   Rx='(?i)(secret|client[_-]?secret|api[_-]?secret)\s*[:=]\s*[''"]?[^\s''"]{6,}' }
    [pscustomobject]@{ Name='API key assignment';       Severity='Medium'; Rx='(?i)(api[_-]?key|apikey|access[_-]?key|x-api-key)\s*[:=]\s*[''"]?[A-Za-z0-9/\-_+]{8,}' }
    [pscustomobject]@{ Name='Token assignment';         Severity='Medium'; Rx='(?i)(auth[_-]?token|access[_-]?token|bearer|refresh[_-]?token)\s*[:=]\s*[''"]?[A-Za-z0-9\.\-_]{8,}' }
    [pscustomobject]@{ Name='Username assignment';      Severity='Low';    Rx='(?i)(username|user|login|uid)\s*[:=]\s*[''"]?[^\s''"]{2,}' }

    # --- Connection strings ---
    [pscustomobject]@{ Name='DB connection string pwd'; Severity='High';   Rx='(?i)(password|pwd)\s*=\s*[^;''"\s]{3,}\s*;?' }
    [pscustomobject]@{ Name='ODBC/OLEDB connstr';       Severity='Medium'; Rx='(?i)(Data Source|Server|Initial Catalog|Database)\s*=\s*[^;]+;(.*?)(User Id|Uid)\s*=' }
    [pscustomobject]@{ Name='MongoDB/Redis URI';        Severity='High';   Rx='(?i)(mongodb(\+srv)?|redis|amqp|postgres(ql)?|mysql)://[^:\s]+:[^@\s]+@' }

    # --- Private keys / certs ---
    [pscustomobject]@{ Name='Private key block';        Severity='High';   Rx='-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----' }
    [pscustomobject]@{ Name='PuTTY private key';        Severity='High';   Rx='PuTTY-User-Key-File-\d' }

    # --- JWT ---
    [pscustomobject]@{ Name='JSON Web Token';           Severity='Medium'; Rx='eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}' }

    # --- Cloud / vendor keys (high-confidence shapes) ---
    [pscustomobject]@{ Name='AWS Access Key ID';        Severity='High';   Rx='\b(AKIA|ASIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b' }
    [pscustomobject]@{ Name='AWS Secret Access Key';    Severity='High';   Rx='(?i)aws(.{0,20})?(secret|access).{0,20}?[''"][0-9a-zA-Z/+]{40}[''"]' }
    [pscustomobject]@{ Name='Google API Key';           Severity='Medium'; Rx='\bAIza[0-9A-Za-z\-_]{35}\b' }
    [pscustomobject]@{ Name='Slack token';              Severity='High';   Rx='\bxox[baprs]-[0-9A-Za-z\-]{10,}\b' }
    [pscustomobject]@{ Name='GitHub token';             Severity='High';   Rx='\b(ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b' }
    [pscustomobject]@{ Name='GitLab PAT';               Severity='High';   Rx='\bglpat-[0-9A-Za-z\-_]{20}\b' }
    [pscustomobject]@{ Name='Stripe key';               Severity='High';   Rx='\b(sk|rk)_(live|test)_[0-9a-zA-Z]{20,}\b' }
    [pscustomobject]@{ Name='Twilio key';               Severity='Medium'; Rx='\bSK[0-9a-fA-F]{32}\b' }
    [pscustomobject]@{ Name='SendGrid key';             Severity='Medium'; Rx='\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b' }
    [pscustomobject]@{ Name='Azure storage key';        Severity='High';   Rx='(?i)(AccountKey|SharedAccessSignature)\s*=\s*[^;\s]{20,}' }
    [pscustomobject]@{ Name='Private PFX reference';    Severity='Low';    Rx='(?i)\.pfx[''"\s;]' }

    # --- Windows-specific leftovers ---
    [pscustomobject]@{ Name='GPP cpassword';            Severity='High';   Rx='cpassword\s*=\s*"[^"]+"' }
    [pscustomobject]@{ Name='net user /add';            Severity='Medium'; Rx='(?i)net\s+user\s+\S+\s+\S+\s+/add' }
    [pscustomobject]@{ Name='ConvertTo-SecureString';   Severity='Medium'; Rx='(?i)ConvertTo-SecureString\s+.*-AsPlainText' }
)

function Invoke-SecretScan {
    if (-not $SecretScan) { return }
    Write-Section 'SECRET / CREDENTIAL FILE SCAN'

    if (-not $ScanRoots -or $ScanRoots.Count -eq 0) {
        $ScanRoots = @(
            "$env:SystemDrive\inetpub"
            "$env:SystemDrive\xampp"
            "$env:ProgramData"
            "$env:windir\System32\inetsrv\config"
            "$env:USERPROFILE"
            "C:\Users\Public"
        ) | Where-Object { Test-Path $_ -ErrorAction SilentlyContinue } | Sort-Object -Unique
        # In Deep depth, widen to all fixed-drive roots.
        if ($Depth -eq 'Deep') {
            $ScanRoots = (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue |
                          ForEach-Object { $_.DeviceID + '\' })
        }
    }

    # Candidate extensions - config/code/secret-bearing text. Skips binaries.
    $exts = @('*.config','*.conf','*.cnf','*.ini','*.xml','*.json','*.yml','*.yaml',
              '*.txt','*.ps1','*.psm1','*.psd1','*.bat','*.cmd','*.vbs','*.sh',
              '*.env','*.properties','*.inf','*.udl','*.rdp','*.sql','*.php',
              '*.py','*.js','*.cs','*.java','*.log','*.bak','*.old','*.pem','*.key','*.ppk')

    $maxBytes = $MaxFileSizeKB * 1KB
    $scanned = 0; $matched = 0
    $skipDirs = '(?i)\\(Windows\\(WinSxS|servicing|assembly)|\$Recycle\.Bin|node_modules|\.git)\\'

    foreach ($root in $ScanRoots) {
        Write-Verbose "Scanning $root"
        try {
            Get-ChildItem -LiteralPath $root -Recurse -File -Include $exts -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -le $maxBytes -and $_.FullName -notmatch $skipDirs } |
            ForEach-Object {
                $file = $_.FullName
                $scanned++
                try {
                    $content = Get-Content -LiteralPath $file -Raw -ErrorAction Stop
                } catch { return }
                if ([string]::IsNullOrEmpty($content)) { return }

                foreach ($pat in $script:SecretPatterns) {
                    $m = [regex]::Matches($content, $pat.Rx)
                    if ($m.Count -gt 0) {
                        $matched++
                        # Redact the matched value so the report doesn't become a secret store itself.
                        $samples = $m | Select-Object -First 3 | ForEach-Object {
                            $v = $_.Value
                            if ($v.Length -gt 60) { $v = $v.Substring(0,60) + '...' }
                            # mask the back half of the match
                            $cut = [int]($v.Length/2)
                            $v.Substring(0,$cut) + ('*' * ($v.Length - $cut))
                        }
                        Add-Finding -Category 'SecretScan' -Title "$($pat.Name) in $([System.IO.Path]::GetFileName($file))" `
                            -Severity $pat.Severity `
                            -Evidence ([pscustomobject]@{
                                File       = $file
                                Pattern    = $pat.Name
                                Hits       = $m.Count
                                MaskedSample = ($samples -join ' | ')
                            }) `
                            -Remediation 'Possible secret at rest. Verify, then remove from file / move to a secrets store.'
                    }
                }
            }
        } catch {}
    }
    Add-Finding -Category 'SecretScan' -Title "Secret scan complete: $scanned files scanned, $matched pattern hits" -Severity Info `
        -Evidence ([pscustomobject]@{ Roots = ($ScanRoots -join '; '); FilesScanned = $scanned; Hits = $matched })
}
#endregion

#region ---------- Network snapshot ----------
function Invoke-NetworkChecks {
    Write-Section 'NETWORK'
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Select-Object LocalAddress,LocalPort,OwningProcess |
            Sort-Object LocalPort -Unique
        Add-Finding -Category 'Network' -Title 'Listening TCP ports' -Severity Info -Evidence (@($listeners))
    } catch {}

    # Saved WLAN profiles - flag that cleartext keys are retrievable, without dumping them
    try {
        $profiles = (netsh.exe wlan show profiles) 2>$null | Select-String ':\s*(.+)$' |
                    ForEach-Object { ($_ -split ':',2)[1].Trim() } | Where-Object { $_ }
        if ($profiles) {
            Add-Finding -Category 'Network' -Title 'Saved WLAN profiles (keys retrievable locally)' -Severity Low `
                -Evidence (@($profiles)) `
                -Remediation 'netsh wlan show profile key=clear reveals PSKs to local users. Note for the report.'
        }
    } catch {}
}
#endregion

#region ---------- Reporting ----------
function Export-Report {
    $min = $script:SevRank[$MinSeverity]
    $results = $script:Findings | Where-Object { $_.SevRank -ge $min } |
               Sort-Object SevRank -Descending

    if ($Format -contains 'Console') {
        Write-Host ""
        Write-Host ("===== SUMMARY ").PadRight(70,'=') -ForegroundColor Cyan
        $sevColor = @{ Critical='Red'; High='Red'; Medium='Yellow'; Low='DarkYellow'; Info='Gray' }
        $script:Findings | Group-Object Severity | Sort-Object { $script:SevRank[$_.Name] } -Descending | ForEach-Object {
            Write-Host ("{0,-9}: {1}" -f $_.Name, $_.Count) -ForegroundColor $sevColor[$_.Name]
        }
        Write-Host ""
        foreach ($f in ($results | Where-Object { $_.SevRank -ge 1 })) {
            Write-Host ("[{0}] {1} / {2}" -f $f.Severity, $f.Category, $f.Title) -ForegroundColor $sevColor[$f.Severity]
            if ($f.Remediation) { Write-Host ("    -> {0}" -f $f.Remediation) -ForegroundColor DarkGray }
        }
        Write-Host ""
        Write-Host ("Completed in {0:N1}s. {1} findings total." -f $script:Stopwatch.Elapsed.TotalSeconds, $script:Findings.Count) -ForegroundColor Cyan
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $base  = Join-Path $OutputPath ("PrivEscAudit_{0}_{1}" -f $env:COMPUTERNAME,$stamp)

    if ($Format -contains 'Json') {
        $results | ConvertTo-Json -Depth 6 | Out-File "$base.json" -Encoding utf8
        Write-Verbose "JSON -> $base.json"
    }
    if ($Format -contains 'Csv') {
        $results | Select-Object Severity,Category,Title,Remediation,
            @{N='Evidence';E={ ($_.Evidence | ConvertTo-Json -Compress -Depth 4) }},Timestamp |
            Export-Csv "$base.csv" -NoTypeInformation -Encoding utf8
        Write-Verbose "CSV -> $base.csv"
    }
    if ($Format -contains 'Html') {
        Export-HtmlReport -Results $results -Path "$base.html"
        Write-Verbose "HTML -> $base.html"
        if ($Format -contains 'Console') { Write-Host "HTML report: $base.html" -ForegroundColor Green }
    }
}

function Export-HtmlReport {
    param($Results, [string]$Path)
    $sevBg = @{ Critical='#7f1d1d'; High='#b91c1c'; Medium='#b45309'; Low='#4d7c0f'; Info='#334155' }
    $counts = $script:Findings | Group-Object Severity | ForEach-Object { "$($_.Name): $($_.Count)" }
    $rows = foreach ($f in $Results) {
        $ev = [System.Web.HttpUtility]::HtmlEncode((($f.Evidence | ConvertTo-Json -Depth 4)))
        $bg = $sevBg[$f.Severity]
        @"
<tr>
  <td><span class="sev" style="background:$bg">$($f.Severity)</span></td>
  <td>$([System.Web.HttpUtility]::HtmlEncode($f.Category))</td>
  <td>$([System.Web.HttpUtility]::HtmlEncode($f.Title))</td>
  <td>$([System.Web.HttpUtility]::HtmlEncode($f.Remediation))</td>
  <td><pre>$ev</pre></td>
</tr>
"@
    }
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>PrivEsc Audit - $env:COMPUTERNAME</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px}
h1{font-size:20px} .meta{color:#94a3b8;font-size:13px;margin-bottom:16px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #1e293b;padding:8px;text-align:left;vertical-align:top}
th{background:#1e293b;position:sticky;top:0}
.sev{padding:2px 8px;border-radius:4px;color:#fff;font-weight:600;font-size:12px}
pre{margin:0;white-space:pre-wrap;color:#cbd5e1;font-size:12px;max-width:420px;overflow:auto}
tr:nth-child(even){background:#111c33}
</style></head><body>
<h1>Local Privilege-Escalation Audit</h1>
<div class="meta">Host: $env:COMPUTERNAME &nbsp;|&nbsp; User: $script:CurrentUser &nbsp;|&nbsp;
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp; Depth: $Depth<br>
Counts &nbsp; $([string]::Join(' &nbsp; ', $counts))</div>
<table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Remediation</th><th>Evidence</th></tr></thead>
<tbody>
$([string]::Join("`n", $rows))
</tbody></table>
<p class="meta">Read-only enumeration. Authorized assessment use only.</p>
</body></html>
"@
    $html | Out-File -LiteralPath $Path -Encoding utf8
}
#endregion

#region ---------- Orchestration ----------
Invoke-SystemContext
Invoke-TokenPrivileges
Invoke-UserContext
Invoke-AlwaysInstallElevated
Invoke-ServiceChecks
Invoke-ScheduledTaskChecks
Invoke-AutorunChecks
Invoke-PathChecks
Invoke-UacChecks
Invoke-DefenderChecks
Invoke-CredentialChecks
Invoke-SecretScan
Invoke-NetworkChecks
Export-Report
#endregion
