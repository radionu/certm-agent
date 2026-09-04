[CmdletBinding()]
param(
    [string]$EnrollmentToken = '',
    [string]$ApiBase = 'https://certm.pmr.vn/api/v2',
    [ValidateRange(5, 1440)][int]$IntervalMinutes = 30,
    [string]$VerifyConnectHost = '',
    [switch]$Force,
    [switch]$EnableTask,
    [switch]$RunOnce
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Security -ErrorAction Stop

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell window.'
}
$root = 'C:\CertM'
$bin = Join-Path $root 'bin'
$configPath = Join-Path $root 'config.json'
$sourceAgent = Join-Path $PSScriptRoot 'CertM.Agent.ps1'
if (-not (Test-Path -LiteralPath $sourceAgent)) { throw "Missing agent file: $sourceAgent" }
$existingConfiguration = Test-Path -LiteralPath $configPath

if (-not $existingConfiguration -or $Force) {
    if (-not $ApiBase.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'ApiBase must use HTTPS.'
    }
    if (-not $ApiBase.TrimEnd('/').EndsWith('/api/v2', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'ApiBase must end with /api/v2.'
    }
    if ($EnrollmentToken.Length -eq 0) {
        throw 'A non-empty EnrollmentToken is required for a new installation or intentional re-enrollment.'
    }
}

New-Item -ItemType Directory -Path $bin -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root 'logs') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root 'staging') -Force | Out-Null
Copy-Item -LiteralPath $sourceAgent -Destination (Join-Path $bin 'CertM.Agent.ps1') -Force

& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the CertM data directory ACL.' }

if (-not $existingConfiguration -or $Force) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($EnrollmentToken)
    $encrypted = [Security.Cryptography.ProtectedData]::Protect(
        $bytes,
        $null,
        [Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    $config = [ordered]@{
        config_version = 3
        api_base = $ApiBase.TrimEnd('/')
        enrollment_token_protected = [Convert]::ToBase64String($encrypted)
        client_token_protected = $null
        request_timeout_seconds = 60
        verify_timeout_seconds = 15
        verify_retry_timeout_seconds = 30
        verify_retry_interval_seconds = 2
        verify_connect_host = $VerifyConnectHost
    }
}
else {
    $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $version = [int]$config.config_version
    if ($version -notin @(2, 3)) {
        throw "Unsupported existing config_version=$version"
    }
    $config.config_version = 3
    if ($config.PSObject.Properties.Name -contains 'managed_domains') {
        $config.PSObject.Properties.Remove('managed_domains')
    }
    Write-Host 'Existing DPAPI-protected client identity preserved.'
}
$config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $configPath -Encoding UTF8

$taskName = 'CertM IIS Agent'
$agentPath = Join-Path $bin 'CertM.Agent.ps1'
$taskCommand = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$agentPath`""
& schtasks.exe /Create /TN $taskName /TR $taskCommand /SC MINUTE /MO $IntervalMinutes /RU SYSTEM /RL HIGHEST /F | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not register the CertM scheduled task.' }

if (-not $EnableTask) {
    & schtasks.exe /Change /TN $taskName /DISABLE | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not disable the CertM scheduled task for staged validation.' }
}

Write-Host "CertM IIS Agent 1.0.0-rc.2 installed."
Write-Host "Configuration: $configPath"
if ($EnableTask) {
    Write-Host "Task: $taskName (enabled; every $IntervalMinutes minutes)"
}
else {
    Write-Host "Task: $taskName (disabled for staged validation)"
}

if ($RunOnce) {
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $agentPath
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "The requested initial run failed. Review $root\logs\agent.log"
    }
    else {
        if (-not $existingConfiguration -or $Force) {
            Write-Host 'Initial enrollment completed. Approve the new client in CertM before enabling the task.'
        }
        else {
            Write-Host 'Requested validation run completed with the existing client identity.'
        }
    }
}
else {
    Write-Host 'The agent was not run. Complete Discover, enrollment, DryRun, and a verified Run before enabling the task.'
}
