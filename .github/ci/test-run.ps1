# CI smoke test: run the audit and check the reports are complete and consistent.
$ErrorActionPreference = 'Continue'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$out  = Join-Path $env:RUNNER_TEMP ("report-" + $PSVersionTable.PSVersion.Major)
Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"

$Error.Clear()
& (Join-Path $repo 'Invoke-PrivEscAudit.ps1') -Depth Standard -SecretScan -ScanRoots $repo `
    -Format Console,Json,Csv,Html -OutputPath $out

$typeErrors = @($Error | Where-Object { "$_" -match 'Unable to find type' })
if ($typeErrors) { $typeErrors | ForEach-Object { Write-Host "::error::$_" }; exit 1 }

$json = Get-ChildItem $out -Filter *.json | Select-Object -First 1
$html = Get-ChildItem $out -Filter *.html | Select-Object -First 1
$csv  = Get-ChildItem $out -Filter *.csv  | Select-Object -First 1
if (-not ($json -and $html -and $csv)) { Write-Host '::error::Missing report file(s)'; exit 1 }

$findings = @(Get-Content $json.FullName -Raw | ConvertFrom-Json)
if ($findings.Count -eq 1 -and $findings[0] -is [array]) { $findings = $findings[0] }   # PS 5.1 quirk
$rows = ([regex]::Matches((Get-Content $html.FullName -Raw), '<tr>')).Count - 1        # minus header row
$csvRows = @(Import-Csv $csv.FullName).Count
Write-Host "JSON findings: $($findings.Count)  HTML rows: $rows  CSV rows: $csvRows"

if ($findings.Count -lt 1)          { Write-Host '::error::JSON report has no findings'; exit 1 }
if ($rows -ne $findings.Count)      { Write-Host "::error::HTML rows ($rows) != JSON findings ($($findings.Count))"; exit 1 }
if ($csvRows -ne $findings.Count)   { Write-Host "::error::CSV rows ($csvRows) != JSON findings ($($findings.Count))"; exit 1 }
Write-Host 'OK'
exit 0
