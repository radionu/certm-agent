[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$EnrollmentToken,
    [string]$ApiBase = 'https://certm.pmr.vn/api/v2',
    [string[]]$ManagedDomains = @(),
    [ValidateRange(5, 1440)][int]$IntervalMinutes = 30,
    [string]$VerifyConnectHost = '',
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell window.'
}
if (-not $ApiBase.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'ApiBase must use HTTPS.'
}
if (-not $ApiBase.TrimEnd('/').EndsWith('/api/v2', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'ApiBase must end with /api/v2.'
}
if ($EnrollmentToken.Length -lt 32) { throw 'EnrollmentToken appears invalid.' }

$root = Join-Path $env:ProgramData 'CertM'
$bin = Join-Path $root 'bin'
$configPath = Join-Path $root 'config.json'
$sourceAgent = Join-Path $PSScriptRoot 'CertM.Agent.ps1'
if (-not (Test-Path -LiteralPath $sourceAgent)) { throw "Missing agent file: $sourceAgent" }
if ((Test-Path -LiteralPath $configPath) -and -not $Force) {
    throw "CertM is already configured at $configPath. Use -Force only for an intentional re-enrollment."
}

New-Item -ItemType Directory -Path $bin -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root 'logs') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root 'staging') -Force | Out-Null
Copy-Item -LiteralPath $sourceAgent -Destination (Join-Path $bin 'CertM.Agent.ps1') -Force

& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the CertM data directory ACL.' }

$bytes = [Text.Encoding]::UTF8.GetBytes($EnrollmentToken)
$encrypted = [Security.Cryptography.ProtectedData]::Protect(
    $bytes,
    $null,
    [Security.Cryptography.DataProtectionScope]::LocalMachine
)

$config = [ordered]@{
    config_version = 2
    api_base = $ApiBase.TrimEnd('/')
    enrollment_token_protected = [Convert]::ToBase64String($encrypted)
    client_token_protected = $null
    managed_domains = @($ManagedDomains | ForEach-Object { $_.Trim().TrimEnd('.').ToLowerInvariant() })
    request_timeout_seconds = 60
    verify_timeout_seconds = 15
    verify_retry_timeout_seconds = 30
    verify_retry_interval_seconds = 2
    verify_connect_host = $VerifyConnectHost
}
$config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $configPath -Encoding UTF8

$taskName = 'CertM IIS Agent'
$agentPath = Join-Path $bin 'CertM.Agent.ps1'
$taskCommand = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$agentPath`""
& schtasks.exe /Create /TN $taskName /TR $taskCommand /SC MINUTE /MO $IntervalMinutes /RU SYSTEM /RL HIGHEST /F | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not register the CertM scheduled task.' }

Write-Host "CertM IIS Agent installed."
Write-Host "Configuration: $configPath"
Write-Host "Task: $taskName (every $IntervalMinutes minutes)"

& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $agentPath
if ($LASTEXITCODE -ne 0) {
    Write-Warning "The initial run failed. Review $root\logs\agent.log"
}
else {
    Write-Host 'Initial enrollment completed. Approve the new client in CertM, then run the task again.'
}
