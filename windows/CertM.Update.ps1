[CmdletBinding()]
param([string]$ConfigPath = 'C:\CertM\config.json')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:UpdaterVersion = '1.0.0-rc.12'
$script:Root = 'C:\CertM'
$script:Mutex = $null
$script:Config = $null
$script:Token = $null
$script:MachineId = $null

Add-Type -AssemblyName System.Security -ErrorAction Stop
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-UpdateLog {
    param([string]$Message)
    $directory = Join-Path $script:Root 'logs'
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $line = '{0} {1}' -f [DateTimeOffset]::Now.ToString('o'), $Message
    Add-Content -LiteralPath (Join-Path $directory 'agent-update.log') -Value $line -Encoding UTF8
    Write-Host $line
}

function Unprotect-Secret {
    param([string]$ProtectedText)
    $encrypted = [Convert]::FromBase64String($ProtectedText)
    $bytes = [Security.Cryptography.ProtectedData]::Unprotect(
        $encrypted,
        $null,
        [Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    return [Text.Encoding]::UTF8.GetString($bytes)
}

function Get-MachineId {
    $machineGuid = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    return "windows:$($machineGuid.ToString().ToLowerInvariant())"
}

function Get-InstalledVersion {
    $agentPath = Join-Path $script:Root 'bin\CertM.Agent.ps1'
    if (-not (Test-Path -LiteralPath $agentPath)) { return $script:UpdaterVersion }
    $content = Get-Content -LiteralPath $agentPath -Raw -Encoding UTF8
    $match = [regex]::Match($content, "AgentVersion\s*=\s*'([^']+)'", 'IgnoreCase')
    if ($match.Success) { return $match.Groups[1].Value }
    return $script:UpdaterVersion
}

function Get-ApiHeaders {
    return @{
        Authorization = "Bearer $script:Token"
        'X-CertM-Agent-Type' = 'updater-windows'
        'X-CertM-Agent-Version' = Get-InstalledVersion
        'X-CertM-Machine-ID' = $script:MachineId
        Accept = 'application/json'
    }
}

function Invoke-UpdateApi {
    param(
        [ValidateSet('GET', 'POST')][string]$Method,
        [string]$Path,
        [AllowNull()][object]$Body
    )
    $parameters = @{
        Uri = "$($script:Config.api_base.TrimEnd('/'))$Path"
        Method = $Method
        Headers = Get-ApiHeaders
        UseBasicParsing = $true
        TimeoutSec = [int]$script:Config.request_timeout_seconds
    }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body | ConvertTo-Json -Depth 8 -Compress
    }
    return Invoke-RestMethod @parameters
}

function Send-UpdateReport {
    param([int]$ReleaseId, [string]$Status, [string]$Message, [string]$InstalledVersion = '')
    $body = [ordered]@{
        release_id = $ReleaseId
        status = $Status
        message = if ($Message.Length -gt 2000) { $Message.Substring(0, 2000) } else { $Message }
    }
    if ($InstalledVersion) { $body['installed_version'] = $InstalledVersion }
    try { Invoke-UpdateApi POST '/client/agent-update/report' $body | Out-Null }
    catch { Write-UpdateLog "Unable to report update status ${Status}: $($_.Exception.Message)" }
}

function Get-TextSha256 {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally { $sha.Dispose() }
}

function Get-TrustedKey {
    param([string]$ExpectedFingerprint)
    $metadata = Invoke-UpdateApi GET '/client/agent-update/key' $null
    if ($metadata.algorithm -ne 'RSA-SHA256') { throw 'Unsupported update signing algorithm.' }
    $fingerprint = Get-TextSha256 ([string]$metadata.pem)
    if ($fingerprint -ne [string]$metadata.fingerprint_sha256 -or $fingerprint -ne $ExpectedFingerprint) {
        throw 'Agent-update signing-key fingerprint mismatch.'
    }

    $path = Join-Path $script:Root 'update-public-key.json'
    if (Test-Path -LiteralPath $path) {
        $pinned = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]$pinned.fingerprint_sha256 -ne $fingerprint) {
            throw 'Server signing key differs from the locally pinned key.'
        }
        return $pinned
    }

    $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding UTF8
    Write-UpdateLog "Pinned agent-update public key $fingerprint"
    return $metadata
}

function Test-PackageSignature {
    param([string]$PackagePath, [string]$Signature, [object]$Key)
    $parameters = New-Object Security.Cryptography.RSAParameters
    $parameters.Modulus = [Convert]::FromBase64String([string]$Key.modulus)
    $parameters.Exponent = [Convert]::FromBase64String([string]$Key.exponent)
    $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
    try {
        $rsa.ImportParameters($parameters)
        $bytes = [IO.File]::ReadAllBytes($PackagePath)
        $signatureBytes = [Convert]::FromBase64String($Signature)
        if (-not $rsa.VerifyData($bytes, 'SHA256', $signatureBytes)) {
            throw 'Agent update RSA signature is invalid.'
        }
    }
    finally { $rsa.Dispose() }
}

function Expand-SafeArchive {
    param([string]$ArchivePath, [string]$Destination)
    $root = [IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        foreach ($entry in $archive.Entries) {
            $target = [IO.Path]::GetFullPath((Join-Path $Destination $entry.FullName))
            if (-not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Unsafe archive path: $($entry.FullName)"
            }
            if ([string]::IsNullOrEmpty($entry.Name)) {
                New-Item -ItemType Directory -Path $target -Force | Out-Null
                continue
            }
            New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
        }
    }
    finally { $archive.Dispose() }
}

function Test-Manifest {
    param([string]$Extracted, [string]$Version, [hashtable]$Targets)
    $manifestPath = Join-Path $Extracted 'manifest.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([int]$manifest.schema -ne 1 -or [string]$manifest.platform -ne 'windows') {
        throw 'Invalid Windows update manifest.'
    }
    if ([string]$manifest.version -ne $Version) { throw 'Manifest version does not match assigned release.' }

    $declared = @{}
    foreach ($item in @($manifest.files)) {
        $relative = ([string]$item.path).Replace('/', '\')
        if (-not $Targets.ContainsKey($relative) -or $declared.ContainsKey($relative)) {
            throw "Unexpected manifest file: $relative"
        }
        $path = Join-Path $Extracted $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing manifest file: $relative" }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$item.sha256) {
            throw "Manifest hash mismatch: $relative"
        }
        $declared[$relative] = $true
    }
    if ($declared.Count -ne $Targets.Count) { throw 'Manifest does not contain the complete Windows runtime.' }
    $actual = @(Get-ChildItem -LiteralPath $Extracted -File -Recurse | Where-Object { $_.Name -ne 'manifest.json' })
    if ($actual.Count -ne $declared.Count) { throw 'Archive contains undeclared files.' }
}

function Backup-Runtime {
    param([string]$Backup, [hashtable]$Targets)
    New-Item -ItemType Directory -Path $Backup -Force | Out-Null
    $existing = [ordered]@{}
    foreach ($relative in $Targets.Keys) {
        $target = $Targets[$relative]
        $exists = Test-Path -LiteralPath $target -PathType Leaf
        $existing[$relative] = $exists
        if ($exists) {
            $saved = Join-Path $Backup $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $saved) -Force | Out-Null
            Copy-Item -LiteralPath $target -Destination $saved -Force
        }
    }
    $existing | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Backup 'existing.json') -Encoding UTF8
}

function Install-Runtime {
    param([string]$Extracted, [hashtable]$Targets)
    foreach ($relative in $Targets.Keys) {
        $target = $Targets[$relative]
        $temporary = "$target.update"
        Copy-Item -LiteralPath (Join-Path $Extracted $relative) -Destination $temporary -Force
        Move-Item -LiteralPath $temporary -Destination $target -Force
    }
}

function Restore-Runtime {
    param([string]$Backup, [hashtable]$Targets)
    $existing = Get-Content -LiteralPath (Join-Path $Backup 'existing.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($relative in $Targets.Keys) {
        $target = $Targets[$relative]
        if ([bool]$existing.PSObject.Properties[$relative].Value) {
            Copy-Item -LiteralPath (Join-Path $Backup $relative) -Destination $target -Force
        }
        elseif (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
    }
}

function Test-InstalledScripts {
    param([string]$Version)
    foreach ($path in @(
        (Join-Path $script:Root 'bin\CertM.Agent.ps1'),
        (Join-Path $script:Root 'bin\CertM.Update.ps1')
    )) {
        $tokens = $null
        $errors = $null
        [void][Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) { throw "PowerShell parser rejected updated script: $path" }
    }
    if ((Get-InstalledVersion) -ne $Version) { throw 'Updated Windows agent version self-test failed.' }
    Import-Module WebAdministration -ErrorAction Stop
    [void](Get-Website)
}

function Invoke-AgentUpdate {
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return }
    $script:Config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($script:Config.PSObject.Properties.Name -notcontains 'client_token_protected') {
        Write-UpdateLog 'Client enrollment has not completed; update check skipped.'
        return
    }
    $script:Token = Unprotect-Secret ([string]$script:Config.client_token_protected)
    $script:MachineId = Get-MachineId
    $response = Invoke-UpdateApi GET '/client/agent-update' $null
    if ($null -eq $response.update) { return }
    $update = $response.update
    if ([string]$update.platform -ne 'windows') { throw 'Server assigned a non-Windows update to this client.' }

    $releaseId = [int]$update.release_id
    $version = [string]$update.version
    Send-UpdateReport $releaseId 'STARTED' "Installing Windows agent $version"
    $work = Join-Path (Join-Path $script:Root 'staging') ("agent-update-$releaseId")
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $package = Join-Path $work 'package.zip'
    $extracted = Join-Path $work 'extracted'
    $backup = Join-Path $work 'backup'
    New-Item -ItemType Directory -Path $extracted -Force | Out-Null
    $modified = $false
    $targets = @{
        'windows\CertM.Agent.ps1' = Join-Path $script:Root 'bin\CertM.Agent.ps1'
        'windows\CertM.Update.ps1' = Join-Path $script:Root 'bin\CertM.Update.ps1'
        'windows\Uninstall-CertMAgent.ps1' = Join-Path $script:Root 'bin\Uninstall-CertMAgent.ps1'
    }

    try {
        $key = Get-TrustedKey ([string]$update.signing_key_fingerprint)
        $downloadPath = [string]$update.download_path
        if (-not $downloadPath.StartsWith('/client/agent-update/download/', [StringComparison]::Ordinal)) {
            throw 'Server returned an invalid update download path.'
        }
        $downloadUri = "$($script:Config.api_base.TrimEnd('/'))$downloadPath"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUri -Headers (Get-ApiHeaders) -OutFile $package -TimeoutSec ([int]$script:Config.request_timeout_seconds)
        if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$update.sha256) {
            throw 'Downloaded package SHA-256 mismatch.'
        }
        Test-PackageSignature $package ([string]$update.signature) $key
        Expand-SafeArchive $package $extracted
        Test-Manifest $extracted $version $targets
        Backup-Runtime $backup $targets
        $modified = $true
        Install-Runtime $extracted $targets
        Test-InstalledScripts $version
        Send-UpdateReport $releaseId 'SUCCESS' "Windows agent $version installed" $version
        Write-UpdateLog "CertM Windows agent updated successfully to $version"
        Remove-Item -LiteralPath $work -Recurse -Force
    }
    catch {
        $failure = $_.Exception.Message
        Send-UpdateReport $releaseId 'FAILED' $failure
        if ($modified) {
            try {
                Restore-Runtime $backup $targets
                Send-UpdateReport $releaseId 'ROLLBACK' "Rolled back after: $failure"
            }
            catch { Write-UpdateLog "Rollback failed: $($_.Exception.Message)" }
        }
        throw
    }
}

try {
    $createdNew = $false
    $script:Mutex = [Threading.Mutex]::new($true, 'Global\CertM-IIS-Agent', [ref]$createdNew)
    if (-not $createdNew) {
        $script:Mutex.Dispose()
        $script:Mutex = $null
        Write-UpdateLog 'Another CertM agent process is running; update check skipped.'
        exit 0
    }
    Invoke-AgentUpdate
}
catch {
    Write-UpdateLog "CertM updater failed: $($_.Exception.Message)"
    exit 1
}
finally {
    if ($script:Mutex) { $script:Mutex.ReleaseMutex(); $script:Mutex.Dispose() }
}
