[CmdletBinding()]
param(
    [string]$ApiBase = 'https://certm.pmr.vn/api/v2',
    [ValidateLength(0, 100)][string]$DisplayName = '',
    [ValidateRange(5, 1440)][int]$IntervalMinutes = 360,
    [string]$VerifyConnectHost = '',
    [string]$ReleaseRef = 'main',
    [switch]$Force,
    [switch]$Staged
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this bootstrap from an elevated PowerShell window.'
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'certm-agent-' + [Guid]::NewGuid().ToString('N')
)
$archivePath = Join-Path $temporaryRoot 'certm-agent.zip'
$extractPath = Join-Path $temporaryRoot 'source'
$configPath = 'C:\CertM\config.json'
$needsBootstrapCredential = $Force -or -not (Test-Path -LiteralPath $configPath)
$plainCredential = $null
$credentialPointer = [IntPtr]::Zero

try {
    if ($needsBootstrapCredential) {
        $secureCredential = Read-Host 'Enter the CertM operations bootstrap credential' -AsSecureString
        if ($secureCredential.Length -eq 0) {
            throw 'The CertM operations bootstrap credential cannot be empty.'
        }
        $credentialPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
            $secureCredential
        )
        $plainCredential = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
            $credentialPointer
        )
    }

    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $extractPath -Force | Out-Null

    $encodedReleaseRef = [Uri]::EscapeDataString($ReleaseRef)
    $archiveUri = (
        'https://github.com/radionu/certm-agent/archive/' +
        $encodedReleaseRef +
        '.zip'
    )
    Write-Host "Downloading CertM IIS Agent release $ReleaseRef..."
    Invoke-WebRequest -UseBasicParsing -Uri $archiveUri -OutFile $archivePath
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath -Force

    $installer = @(
        Get-ChildItem -LiteralPath $extractPath -Filter 'Install-CertMAgent.ps1' `
            -File -Recurse
    )
    if ($installer.Count -ne 1) {
        throw "Expected one Windows installer in the release; found $($installer.Count)."
    }

    $installerDirectory = $installer[0].Directory.FullName
    foreach ($requiredFile in @('CertM.Agent.ps1', 'Uninstall-CertMAgent.ps1')) {
        if (-not (Test-Path -LiteralPath (Join-Path $installerDirectory $requiredFile))) {
            throw "Release is missing windows/$requiredFile"
        }
    }

    $installParameters = @{
        ApiBase = $ApiBase
        DisplayName = $DisplayName
        IntervalMinutes = $IntervalMinutes
        VerifyConnectHost = $VerifyConnectHost
        RunOnce = $true
        EnableTask = -not $Staged
    }
    if ($needsBootstrapCredential) {
        $installParameters.EnrollmentToken = $plainCredential
    }
    if ($Force) {
        $installParameters.Force = $true
    }

    $installerPath = $installer[0].FullName
    & $installerPath @installParameters

    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "CertM IIS Agent installer exited with code $LASTEXITCODE."
    }

    $installedConfiguration = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if (
        $installedConfiguration.PSObject.Properties.Name -contains
        'enrollment_token_protected'
    ) {
        Write-Warning (
            'Initial enrollment did not complete. The bootstrap credential remains ' +
            'DPAPI-protected for the scheduled retry and will be removed after enrollment.'
        )
    }
    else {
        Write-Host 'Bootstrap credential removed; the unique client identity is active locally.'
    }

    Write-Host 'Approve the client and assign certificates in the CertM dashboard.'
    if ($Staged) {
        Write-Host "Automation remains disabled. Enable task 'CertM IIS Agent' after validation."
    }
    else {
        Write-Host "Automation is enabled and will retry every $IntervalMinutes minutes."
    }
}
finally {
    $plainCredential = $null
    if ($credentialPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($credentialPointer)
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
