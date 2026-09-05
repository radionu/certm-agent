[CmdletBinding()]
param(
    [string]$ConfigPath = 'C:\CertM\config.json',
    [ValidateSet('Run', 'Discover', 'Inventory', 'DryRun')][string]$Mode = 'Run'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:AgentVersion = '1.0.0-rc.4'
$script:CertMRoot = 'C:\CertM'
$script:Mutex = $null

[void][Reflection.Assembly]::LoadWithPartialName('System.Security')
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-CertMLog {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')

    $logDirectory = Join-Path $script:CertMRoot 'logs'
    if (-not (Test-Path -LiteralPath $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    }

    $line = '{0} [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('o'), $Level, $Message
    Add-Content -LiteralPath (Join-Path $logDirectory 'agent.log') -Value $line -Encoding UTF8
}

function Normalize-Fingerprint {
    param([AllowNull()][string]$Fingerprint)
    if ([string]::IsNullOrWhiteSpace($Fingerprint)) { return $null }
    return ($Fingerprint -replace '[:\s-]', '').ToLowerInvariant()
}

function Get-Sha256Fingerprint {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($Certificate.RawData) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha.Dispose()
    }
}

function Protect-LocalMachineSecret {
    param([string]$PlainText)
    $bytes = [Text.Encoding]::UTF8.GetBytes($PlainText)
    $encrypted = [Security.Cryptography.ProtectedData]::Protect(
        $bytes,
        $null,
        [Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    return [Convert]::ToBase64String($encrypted)
}

function Unprotect-LocalMachineSecret {
    param([AllowNull()][string]$ProtectedText)
    if ([string]::IsNullOrWhiteSpace($ProtectedText)) { return $null }
    $encrypted = [Convert]::FromBase64String($ProtectedText)
    $bytes = [Security.Cryptography.ProtectedData]::Unprotect(
        $encrypted,
        $null,
        [Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    return [Text.Encoding]::UTF8.GetString($bytes)
}

function Read-JsonFile {
    param([string]$Path, [object]$Default)
    if (-not (Test-Path -LiteralPath $Path)) { return $Default }
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Write-JsonFileAtomic {
    param([string]$Path, [object]$Value)
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $temporary = "$Path.tmp"
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-MachineId {
    $machineGuid = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    return "windows:$($machineGuid.ToString().ToLowerInvariant())"
}

function Invoke-CertMApi {
    param(
        [ValidateSet('GET', 'POST')][string]$Method,
        [string]$Path,
        [string]$Token,
        [string]$MachineId,
        [AllowNull()][object]$Body,
        [switch]$AllowNotFound
    )

    $baseUrl = $script:Config.api_base.TrimEnd('/')
    $headers = @{
        Authorization = "Bearer $Token"
        'X-CertM-Machine-ID' = $MachineId
        Accept = 'application/json'
    }
    $parameters = @{
        Uri = "$baseUrl$Path"
        Method = $Method
        Headers = $headers
        UseBasicParsing = $true
        TimeoutSec = [int]$script:Config.request_timeout_seconds
    }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body | ConvertTo-Json -Depth 12 -Compress
    }

    try {
        return Invoke-RestMethod @parameters
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($AllowNotFound -and $statusCode -eq 404) { return $null }
        throw
    }
}

function Get-IisHttpsBindings {
    Import-Module WebAdministration -ErrorAction Stop
    $results = @()

    foreach ($site in Get-Website) {
        foreach ($binding in $site.Bindings.Collection) {
            if ($binding.protocol -ne 'https') { continue }
            if ($binding.bindingInformation -notmatch '^(.*):(\d+):(.*)$') {
                Write-CertMLog "Skip unrecognized IIS binding: $($binding.bindingInformation)" 'WARN'
                continue
            }

            $ipAddress = $Matches[1]
            $port = [int]$Matches[2]
            $domain = $Matches[3].Trim().TrimEnd('.').ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($domain)) {
                Write-CertMLog "Skip HTTPS binding without host name: $($site.Name) / $($binding.bindingInformation)" 'WARN'
                continue
            }

            $thumbprint = $null
            if ($binding.certificateHash) {
                if ($binding.certificateHash -is [byte[]]) {
                    $thumbprint = (($binding.certificateHash | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
                }
                else {
                    $thumbprint = ($binding.certificateHash.ToString() -replace '\s', '').ToUpperInvariant()
                }
            }

            $storeName = if ($binding.certificateStoreName) { $binding.certificateStoreName.ToString() } else { 'My' }
            $certificate = $null
            if ($thumbprint) {
                $certificate = Get-Item -LiteralPath "Cert:\LocalMachine\$storeName\$thumbprint" -ErrorAction SilentlyContinue
            }

            $results += [pscustomobject]@{
                site_name = $site.Name
                domain = $domain
                ip_address = $ipAddress
                port = $port
                protocol = 'https'
                binding_information = $binding.bindingInformation
                binding_id = "$($site.Name)|$($binding.bindingInformation)"
                ssl_flags = [int]$binding.sslFlags
                uses_central_certificate_store = (([int]$binding.sslFlags -band 2) -eq 2)
                store_name = $storeName
                thumbprint = $thumbprint
                fingerprint_sha256 = if ($certificate) { Get-Sha256Fingerprint $certificate } else { $null }
                subject = if ($certificate) { $certificate.Subject } else { $null }
                issuer = if ($certificate) { $certificate.Issuer } else { $null }
                serial_number = if ($certificate) { $certificate.SerialNumber } else { $null }
                not_before = if ($certificate) { $certificate.NotBefore.ToUniversalTime().ToString('o') } else { $null }
                not_after = if ($certificate) { $certificate.NotAfter.ToUniversalTime().ToString('o') } else { $null }
            }
        }
    }
    return $results
}

function Send-Inventory {
    param([array]$Bindings, [string]$Token, [string]$MachineId)
    $items = @($Bindings | ForEach-Object {
        $servedFingerprint = $null
        try { $servedFingerprint = Get-ServedFingerprint $_ } catch { }
        [ordered]@{
            site_name = $_.site_name
            domain = $_.domain
            port = $_.port
            protocol = $_.protocol
            subject = $_.subject
            issuer = $_.issuer
            serial_number = $_.serial_number
            fingerprint_sha256 = $_.fingerprint_sha256
            served_fingerprint_sha256 = $servedFingerprint
            not_before = $_.not_before
            not_after = $_.not_after
            cert_path = if ($_.thumbprint) { "Cert:\LocalMachine\$($_.store_name)\$($_.thumbprint)" } else { $null }
            key_path = $null
            binding_id = $_.binding_id
        }
    })
    Invoke-CertMApi POST '/client/inventory' $Token $MachineId @{
        service = 'iis'
        hostname = $env:COMPUTERNAME
        display_name = [string]$script:Config.display_name
        items = $items
    } | Out-Null
}

function Set-IisBindingCertificate {
    param([object]$Binding, [string]$Thumbprint, [string]$StoreName)
    $webBinding = Get-WebBinding -Name $Binding.site_name -Protocol 'https' |
        Where-Object { $_.bindingInformation -eq $Binding.binding_information } |
        Select-Object -First 1
    if (-not $webBinding) { throw "IIS binding disappeared: $($Binding.binding_id)" }
    $webBinding.AddSslCertificate($Thumbprint, $StoreName)
}

function Get-ServedFingerprint {
    param([object]$Binding)
    $connectHost = $script:Config.verify_connect_host
    if ([string]::IsNullOrWhiteSpace($connectHost)) {
        $connectHost = switch ($Binding.ip_address) {
            '*' { '127.0.0.1' }
            '0.0.0.0' { '127.0.0.1' }
            '::' { '::1' }
            default { $Binding.ip_address }
        }
    }

    $tcp = New-Object Net.Sockets.TcpClient
    $ssl = $null
    try {
        $async = $tcp.BeginConnect($connectHost, [int]$Binding.port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds([int]$script:Config.verify_timeout_seconds))) {
            throw "TLS connection timed out: ${connectHost}:$($Binding.port)"
        }
        $tcp.EndConnect($async)
        $callback = [Net.Security.RemoteCertificateValidationCallback]{ param($sender, $cert, $chain, $errors) return $true }
        $ssl = [Net.Security.SslStream]::new($tcp.GetStream(), $false, $callback)
        $ssl.AuthenticateAsClient($Binding.domain)
        $remoteCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        try { return Get-Sha256Fingerprint $remoteCertificate }
        finally { $remoteCertificate.Dispose() }
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        $tcp.Dispose()
    }
}

function Wait-ServedFingerprint {
    param([object]$Binding, [string]$ExpectedFingerprint)

    $deadline = (Get-Date).AddSeconds([int]$script:Config.verify_retry_timeout_seconds)
    $lastResult = $null
    do {
        try {
            $lastResult = Normalize-Fingerprint (Get-ServedFingerprint $Binding)
            if ($lastResult -eq $ExpectedFingerprint) { return $lastResult }
        }
        catch {
            $lastResult = "ERROR: $($_.Exception.Message)"
        }
        Start-Sleep -Seconds ([int]$script:Config.verify_retry_interval_seconds)
    } while ((Get-Date) -lt $deadline)

    throw "IIS did not serve the expected certificate for $($Binding.binding_id); last result: $lastResult"
}

function Send-DeploymentReport {
    param(
        [int]$DeploymentId,
        [ValidateSet('SUCCESS', 'FAILED')][string]$Status,
        [string]$Token,
        [string]$MachineId,
        [AllowNull()][string]$InstalledFingerprint,
        [AllowNull()][string]$ServedFingerprint,
        [string]$Message
    )
    $body = [ordered]@{
        deployment_id = $DeploymentId
        status = $Status
        installed_fingerprint = $InstalledFingerprint
        served_fingerprint = $ServedFingerprint
        message = $Message
    }
    Invoke-CertMApi POST '/deployment/report' $Token $MachineId $body | Out-Null
}

function Install-DeploymentGroup {
    param([array]$Plans, [string]$Token, [string]$MachineId, [object]$State)

    $desired = $Plans[0].desired
    $downloadPath = (
        '/cert/download?domain={0}&service=iis&port={1}&format=pfx' -f
        [Uri]::EscapeDataString($Plans[0].binding.domain),
        [int]$Plans[0].binding.port
    )
    $package = Invoke-CertMApi GET $downloadPath $Token $MachineId $null
    $deploymentId = [int]$package.deployment_id
    if ($deploymentId -lt 1) { throw 'CertM response does not contain a valid deployment_id.' }

    $metadata = $package.certificate
    foreach ($field in @('id', 'certificate_version_id', 'version_id', 'package_revision', 'deployment_revision', 'fingerprint_sha256')) {
        if ($null -eq $metadata.$field) { throw "PFX metadata is missing $field." }
    }
    if (
        [int]$metadata.id -ne [int]$desired.certificate_id -or
        [int]$metadata.certificate_version_id -ne [int]$desired.certificate_version_id -or
        $metadata.version_id.ToString() -ne $desired.version_id.ToString() -or
        [int]$metadata.package_revision -ne [int]$desired.package_revision -or
        $metadata.deployment_revision.ToString() -ne $desired.deployment_revision.ToString() -or
        (Normalize-Fingerprint $metadata.fingerprint_sha256) -ne (Normalize-Fingerprint $desired.fingerprint_sha256)
    ) {
        Send-DeploymentReport $deploymentId 'FAILED' $Token $MachineId $null $null 'Downloaded PFX metadata does not match the desired deployment'
        throw 'Downloaded PFX metadata does not match the desired deployment.'
    }
    if (-not $package.files.'certificate.pfx' -or -not $package.files.pfx_password) {
        Send-DeploymentReport $deploymentId 'FAILED' $Token $MachineId $null $null 'CertM response does not contain a PFX package'
        throw 'CertM response does not contain a PFX package. Update the CertM server first.'
    }

    $stagingDirectory = Join-Path $script:CertMRoot 'staging'
    New-Item -ItemType Directory -Path $stagingDirectory -Force | Out-Null
    $pfxPath = Join-Path $stagingDirectory ("{0}-{1}.pfx" -f $desired.deployment_revision, [Guid]::NewGuid().ToString('N'))
    $oldBindings = @()

    try {
        [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($package.files.'certificate.pfx'))
        $expectedFingerprint = Normalize-Fingerprint $desired.fingerprint_sha256
        $securePassword = ConvertTo-SecureString $package.files.pfx_password -AsPlainText -Force
        $importedCertificates = @(Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation 'Cert:\LocalMachine\My' -Password $securePassword -Exportable:$false)
        $imported = $importedCertificates | Where-Object {
            (Normalize-Fingerprint (Get-Sha256Fingerprint $_)) -eq $expectedFingerprint
        } | Select-Object -First 1
        if (-not $imported) { throw 'The expected leaf certificate was not imported from the PFX package.' }

        $installedFingerprint = Normalize-Fingerprint (Get-Sha256Fingerprint $imported)
        if ($installedFingerprint -ne $expectedFingerprint) {
            throw "Imported fingerprint mismatch. Expected $expectedFingerprint; received $installedFingerprint"
        }

        foreach ($plan in $Plans) {
            $oldBindings += [pscustomobject]@{
                binding = $plan.binding
                thumbprint = $plan.binding.thumbprint
                store_name = $plan.binding.store_name
            }
            Set-IisBindingCertificate $plan.binding $imported.Thumbprint 'My'
        }

        $servedFingerprint = $null
        foreach ($plan in $Plans) {
            $servedFingerprint = Wait-ServedFingerprint $plan.binding $expectedFingerprint
        }

        Send-DeploymentReport $deploymentId 'SUCCESS' $Token $MachineId $installedFingerprint $servedFingerprint 'PFX imported, IIS bindings updated, and served certificate verified'
        foreach ($plan in $Plans) {
            $State.deployments[$plan.binding.binding_id] = [ordered]@{
                domain = $plan.binding.domain
                deployment_revision = $desired.deployment_revision
                fingerprint_sha256 = $expectedFingerprint
                installed_at = (Get-Date).ToUniversalTime().ToString('o')
            }
        }
        Write-CertMLog "Installed $($desired.deployment_revision) on $($Plans.Count) IIS binding(s)."
    }
    catch {
        $failure = $_.Exception.Message
        foreach ($old in $oldBindings) {
            if ($old.thumbprint) {
                try { Set-IisBindingCertificate $old.binding $old.thumbprint $old.store_name }
                catch { Write-CertMLog "Rollback failed for $($old.binding.binding_id): $($_.Exception.Message)" 'ERROR' }
            }
        }
        try { Send-DeploymentReport $deploymentId 'FAILED' $Token $MachineId $null $null "Installation failed and rollback attempted: $failure" }
        catch { Write-CertMLog "Could not report failed deployment: $($_.Exception.Message)" 'ERROR' }
        throw
    }
    finally {
        if (Test-Path -LiteralPath $pfxPath) { Remove-Item -LiteralPath $pfxPath -Force }
    }
}

try {
    $createdNew = $false
    $script:Mutex = [Threading.Mutex]::new($true, 'Global\CertM-IIS-Agent', [ref]$createdNew)
    if (-not $createdNew) {
        $script:Mutex.Dispose()
        $script:Mutex = $null
        exit 0
    }

    if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Configuration file not found: $ConfigPath" }
    $script:Config = Read-JsonFile $ConfigPath $null
    $configVersion = [int]$script:Config.config_version
    if ($configVersion -notin @(2, 3)) { throw 'CertM IIS Agent requires config_version=3.' }
    $configChanged = $false
    if ($configVersion -eq 2) {
        $script:Config.config_version = 3
        $configChanged = $true
    }
    if ($script:Config.PSObject.Properties.Name -contains 'managed_domains') {
        $script:Config.PSObject.Properties.Remove('managed_domains')
        $configChanged = $true
    }
    if ($script:Config.PSObject.Properties.Name -notcontains 'display_name') {
        $script:Config | Add-Member -NotePropertyName display_name -NotePropertyValue ''
        $configChanged = $true
    }
    if (([string]$script:Config.display_name).Length -gt 100) {
        throw 'display_name must not exceed 100 characters.'
    }
    $hasStoredClientToken = (
        $script:Config.PSObject.Properties.Name -contains 'client_token_protected' -and
        -not [string]::IsNullOrWhiteSpace([string]$script:Config.client_token_protected)
    )
    if (
        $hasStoredClientToken -and
        $script:Config.PSObject.Properties.Name -contains 'enrollment_token_protected'
    ) {
        $script:Config.PSObject.Properties.Remove('enrollment_token_protected')
        $configChanged = $true
    }
    if ($configChanged) {
        Write-JsonFileAtomic $ConfigPath $script:Config
        Write-CertMLog 'Configuration migrated to config_version=3; IIS domains are discovered dynamically.'
    }
    if (-not $script:Config.api_base.TrimEnd('/').EndsWith('/api/v2', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'api_base must end with /api/v2.'
    }
    $machineId = Get-MachineId

    $bindings = @(Get-IisHttpsBindings)
    if ($Mode -eq 'Discover') {
        $bindings |
            Select-Object site_name, domain, ip_address, port, protocol, binding_id, `
                uses_central_certificate_store, store_name, thumbprint, `
                fingerprint_sha256, not_after |
            ConvertTo-Json -Depth 6
        Write-CertMLog "Discovery completed; found $($bindings.Count) IIS HTTPS hostname binding(s)."
        exit 0
    }

    $clientTokenProtected = $null
    if ($script:Config.PSObject.Properties.Name -contains 'client_token_protected') {
        $clientTokenProtected = $script:Config.client_token_protected
    }
    $clientToken = Unprotect-LocalMachineSecret $clientTokenProtected
    if (-not $clientToken) {
        $enrollmentTokenProtected = $null
        if ($script:Config.PSObject.Properties.Name -contains 'enrollment_token_protected') {
            $enrollmentTokenProtected = $script:Config.enrollment_token_protected
        }
        $enrollmentToken = Unprotect-LocalMachineSecret $enrollmentTokenProtected
        if (-not $enrollmentToken) { throw 'No client token or enrollment token is configured.' }
        $preflight = Invoke-CertMApi GET '/client/preflight' $enrollmentToken $machineId $null
        if ($preflight.status -ne 'enrollment_available') {
            throw "Unexpected preflight status for enrollment token: $($preflight.status)"
        }
        $os = Get-CimInstance Win32_OperatingSystem
        $enrollment = Invoke-CertMApi POST '/client/enroll' $enrollmentToken $machineId @{
            machine_id = $machineId
            hostname = $env:COMPUTERNAME
            display_name = [string]$script:Config.display_name
            agent_type = 'iis'
            agent_version = $script:AgentVersion
            os_name = $os.Caption
            os_version = $os.Version
        }
        $protectedClientToken = Protect-LocalMachineSecret $enrollment.client_token
        if ($script:Config.PSObject.Properties.Name -contains 'client_token_protected') {
            $script:Config.client_token_protected = $protectedClientToken
        }
        else {
            $script:Config | Add-Member -NotePropertyName client_token_protected -NotePropertyValue $protectedClientToken
        }
        if ($script:Config.PSObject.Properties.Name -contains 'enrollment_token_protected') {
            $script:Config.PSObject.Properties.Remove('enrollment_token_protected')
        }
        Write-JsonFileAtomic $ConfigPath $script:Config
        Write-CertMLog "Enrolled as client $($enrollment.client_id); waiting for administrator approval."
        exit 0
    }

    $preflight = Invoke-CertMApi GET '/client/preflight' $clientToken $machineId $null
    if ($preflight.status -eq 'pending_approval') {
        Write-CertMLog "Client $($preflight.client_id) is waiting for administrator approval."
        exit 0
    }
    if ($preflight.status -ne 'active') { throw "CertM denied client identity: $($preflight.status)" }

    $status = Invoke-CertMApi GET '/client/status' $clientToken $machineId $null
    if ($status.status -ne 'active') { throw "Client is not ACTIVE: $($status.status)" }

    Send-Inventory $bindings $clientToken $machineId
    if ($Mode -eq 'Inventory') {
        Write-CertMLog "Inventory-only run completed; submitted $($bindings.Count) binding(s)."
        exit 0
    }

    $statePath = Join-Path $script:CertMRoot 'state.json'
    $state = Read-JsonFile $statePath ([pscustomobject]@{ deployments = @{} })
    if (-not $state.deployments) { $state | Add-Member -NotePropertyName deployments -NotePropertyValue @{} -Force }
    elseif ($state.deployments -isnot [Collections.IDictionary]) {
        $table = @{}
        foreach ($property in $state.deployments.PSObject.Properties) { $table[$property.Name] = $property.Value }
        $state.deployments = $table
    }

    $plans = @()
    foreach ($binding in $bindings) {
        if ($binding.uses_central_certificate_store) {
            Write-CertMLog "Skip IIS Central Certificate Store binding: $($binding.binding_id)" 'WARN'
            continue
        }
        $path = '/cert/desired?domain={0}' -f [Uri]::EscapeDataString($binding.domain)
        $desired = Invoke-CertMApi GET $path $clientToken $machineId $null -AllowNotFound
        if (-not $desired) { continue }

        $saved = $state.deployments[$binding.binding_id]
        $isCurrent = $saved -and
            $saved.deployment_revision -eq $desired.deployment_revision -and
            (Normalize-Fingerprint $binding.fingerprint_sha256) -eq (Normalize-Fingerprint $desired.fingerprint_sha256)
        if (-not $isCurrent) {
            $plans += [pscustomobject]@{ binding = $binding; desired = $desired }
        }
    }

    foreach ($group in ($plans | Group-Object { "$($_.desired.certificate_id):$($_.desired.deployment_revision)" })) {
        if ($Mode -eq 'DryRun') {
            $domains = ($group.Group | ForEach-Object { $_.binding.domain }) -join ', '
            Write-CertMLog "DRY RUN would install $($group.Group[0].desired.deployment_revision) for $domains"
            continue
        }
        Install-DeploymentGroup @($group.Group) $clientToken $machineId $state
        Write-JsonFileAtomic $statePath $state
    }

    if ($plans.Count -eq 0) {
        Write-CertMLog "Inventory sent; $($bindings.Count) IIS HTTPS binding(s) are current."
    }
    elseif ($Mode -eq 'DryRun') {
        Write-CertMLog "Dry run completed; planned $($plans.Count) IIS binding update(s)."
    }
}
catch {
    try { Write-CertMLog $_.Exception.ToString() 'ERROR' } catch { }
    exit 1
}
finally {
    if ($script:Mutex) { $script:Mutex.ReleaseMutex(); $script:Mutex.Dispose() }
}
