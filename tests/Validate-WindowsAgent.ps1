$ErrorActionPreference = 'Stop'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$agentPath = Join-Path $repositoryRoot 'windows\CertM.Agent.ps1'
$installerPath = Join-Path $repositoryRoot 'windows\Install-CertMAgent.ps1'
$bootstrapPath = Join-Path $repositoryRoot 'windows\Bootstrap-CertMAgent.ps1'
$updaterPath = Join-Path $repositoryRoot 'windows\CertM.Update.ps1'
$configPath = Join-Path $repositoryRoot 'windows\config.example.json'

$agent = Get-Content -LiteralPath $agentPath -Raw -Encoding UTF8
$installer = Get-Content -LiteralPath $installerPath -Raw -Encoding UTF8
$bootstrap = Get-Content -LiteralPath $bootstrapPath -Raw -Encoding UTF8
$updater = Get-Content -LiteralPath $updaterPath -Raw -Encoding UTF8
$uninstaller = Get-Content -LiteralPath (Join-Path $repositoryRoot 'windows\Uninstall-CertMAgent.ps1') -Raw -Encoding UTF8
$config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json

Assert-True ($config.config_version -eq 3) 'Windows example config must use config_version=3.'
Assert-True ($config.PSObject.Properties.Name -contains 'display_name') `
    'Windows example config must expose an optional display_name.'
Assert-True ($config.PSObject.Properties.Name -contains 'enrollment_token_protected') `
    'Windows pre-enrollment config must contain the bootstrap credential.'
Assert-True ($config.PSObject.Properties.Name -notcontains 'client_token_protected') `
    'Windows pre-enrollment config must not contain a client-token placeholder.'
Assert-True ($config.PSObject.Properties.Name -notcontains 'managed_domains') `
    'Windows example config must not contain managed_domains.'
Assert-True ($agent -notmatch 'function\s+Test-DomainAllowed') `
    'The IIS agent must not filter dynamically discovered domains.'
Assert-True ($agent -notmatch 'Test-DomainAllowed\s+\$binding\.domain') `
    'The IIS deployment loop must evaluate every discovered hostname binding.'
Assert-True ($installer -notmatch '\[string\[\]\]\$ManagedDomains') `
    'The IIS installer must not accept a static ManagedDomains list.'
Assert-True ($installer -notmatch 'EnrollmentToken\.Length\s+-lt') `
    'The IIS installer must not impose a minimum bootstrap enrollment-key length.'
Assert-True ($installer -match 'EnrollmentToken\.Length\s+-eq\s+0') `
    'The IIS installer must reject only an empty bootstrap enrollment key.'
Assert-True ($agent -match "AgentVersion\s*=\s*'1\.0\.0-rc\.21'") `
    'The IIS agent release candidate version is missing.'
Assert-True ($agent -match 'LogTimeOffset\s*=\s*\[TimeSpan\]::FromHours\(7\)') `
    'The IIS log timestamp must use the fixed UTC+07:00 offset.'
Assert-True ($agent -match '\[DateTimeOffset\]::UtcNow\.ToOffset') `
    'The IIS logger must render timestamps through DateTimeOffset.'
Assert-True ($agent -match "ValidateSet\('Run', 'Discover', 'Inventory', 'DryRun'\)") `
    'The IIS agent must expose safe discovery and dry-run modes.'
Assert-True ($installer -match 'Existing DPAPI-protected client identity preserved') `
    'The IIS upgrade path must preserve the existing client identity.'
Assert-True ($bootstrap -match "Read-Host 'Enter the CertM operations bootstrap credential' -AsSecureString") `
    'The one-command bootstrap must read its bootstrap credential without command-line exposure.'
Assert-True ($bootstrap -notmatch '\[string\]\$EnrollmentToken') `
    'The one-command bootstrap must not accept a plaintext enrollment token parameter.'
Assert-True ($bootstrap -match '\[int\]\$IntervalMinutes\s*=\s*360') `
    'The one-command bootstrap must default to the production six-hour interval.'
Assert-True ($bootstrap -match "needsInitialEnrollment[\s\S]+enrollment_token_protected") `
    'The one-command bootstrap must recognize and resume a partial pre-enrollment installation.'
Assert-True ($bootstrap -match 'if \(\$needsInitialEnrollment\)[\s\S]+RunOnce\s*=\s*\$true') `
    'The one-command bootstrap must perform initial enrollment for new and partial installations.'
Assert-True ($bootstrap -match 'elseif \(\$needsInitialEnrollment\)[\s\S]+EnableTask\s*=\s*\$true') `
    'The one-command bootstrap must enable certificate automation after completing initial installation.'
Assert-True ($bootstrap -match "PSBoundParameters\.ContainsKey\('DisplayName'\)") `
    'The one-command bootstrap must preserve an existing display name unless explicitly changed.'
Assert-True ($bootstrap -match 'ZeroFreeBSTR') `
    'The one-command bootstrap must clear the plaintext credential buffer.'
Assert-True ($installer -match 'Copy-Item[^\r\n]+\$sourceUninstaller') `
    'The installer must retain the uninstaller with the installed agent.'
Assert-True ($installer -match 'Copy-Item[^\r\n]+\$sourceUpdater') `
    'The installer must retain the software updater.'
Assert-True ($installer -notmatch '/SC MINUTE /MO 15') `
    'The installer must not register a separate 15-minute update task.'
Assert-True ($installer -match '\$legacyUpdateTaskName[\s\S]+Unregister-ScheduledTask') `
    'The installer must retire the legacy software-update task.'
Assert-True ($agent -match '\[switch\]\$SkipUpdateCheck') `
    'The IIS agent must support a non-recursive combined run.'
Assert-True ($agent -match 'CertM\.Update\.ps1[\s\S]+certificate work will continue') `
    'The IIS task must check updates first without blocking certificate work.'
Assert-True ($agent -match 'ip_pending_approval[\s\S]+source_ip') `
    'The IIS agent must explain source-IP approval blocks.'
Assert-True ($updater -match 'ip_pending_approval[\s\S]+source_ip') `
    'The Windows updater must explain source-IP approval blocks.'
Assert-True ($updater -match 'Remove-LegacyUpdateTask') `
    'The managed updater must retire the legacy 15-minute task after RC13 installs.'
Assert-True ($updater -match '\[Threading\.Mutex\]::new\(\$true, ''Global\\CertM-IIS-Agent''') `
    'The updater and certificate agent must share the same mutex.'
Assert-True ($updater -match 'VerifyData\(\$bytes, ''SHA256''') `
    'The updater must verify the package RSA-SHA256 signature.'
Assert-True ($updater -match "'ROLLBACK'") `
    'The updater must report rollback after a failed installation.'
Assert-True ($bootstrap -match "'CertM.Update.ps1'") `
    'The bootstrap must require the updater in every release.'
Assert-True ($installer -match '\[string\]\$DisplayName') `
    'The IIS installer must accept a friendly display name.'
Assert-True ($agent -match 'hostname\s*=\s*\$env:COMPUTERNAME') `
    'The IIS agent must report the current OS hostname.'
Assert-True ($agent -match 'display_name\s*=\s*\[string\]\$script:Config\.display_name') `
    'The IIS agent must report its configured display name.'
Assert-True ($agent -match "'X-CertM-Agent-Type'\s*=\s*'iis'") `
    'Every IIS API request must report the agent type.'
Assert-True ($agent -match '''X-CertM-Agent-Version''\s*=\s*\$script:AgentVersion') `
    'Every IIS API request must report the running agent version.'
Assert-True ($agent -match 'agent_version\s*=\s*\$script:AgentVersion') `
    'IIS inventory must report the running agent version.'
Assert-True ($agent -match 'site_state\s*=\s*\[string\]\$site\.State') `
    'IIS discovery must record whether each site is started or stopped.'
Assert-True ($agent -match 'site_state\s*=\s*\$_\.site_state') `
    'IIS inventory must report the discovered site state.'
Assert-True ($agent -match 'if \(\$binding\.site_state -ne ''Started''\)') `
    'IIS deployment must skip bindings that belong to inactive sites.'
Assert-True ($agent -match 'Skip certificate deployment for inactive IIS site') `
    'IIS deployment must log every inactive binding that it skips.'
Assert-True ($agent -match 'if \(\$_\.site_state -eq ''Started''\)') `
    'IIS inventory must not attempt live TLS verification for inactive sites.'
Assert-True ($agent -match 'postDeploymentBindings\s*=\s*@\(Get-IisHttpsBindings\)[\s\S]+Send-Inventory\s+\$postDeploymentBindings') `
    'IIS must refresh inventory after changing one or more certificate bindings.'
Assert-True ($agent -match 'Post-deployment inventory failed:[\s\S]+''WARN''') `
    'A post-deployment inventory failure must be logged without invalidating a successful certificate deployment.'
Assert-True ($agent -match 'function\s+Set-IisBindingSslFlags[\s\S]+Set-WebBinding[\s\S]+-PropertyName\s+''sslFlags''') `
    'IIS hostname binding updates must be able to enable SNI through the WebAdministration module.'
Assert-True ($agent -match '\$newSslFlags\s*=\s*\(\[int\]\$plan\.binding\.ssl_flags\s+-bor\s+1\)') `
    'IIS deployment must add the SNI flag without discarding other SSL flags.'
Assert-True ($agent -match 'ssl_flags\s*=\s*\[int\]\$plan\.binding\.ssl_flags') `
    'IIS deployment must retain the original SSL flags for rollback.'
Assert-True ($agent -match 'Set-IisBindingSslFlags\s+\$old\.binding\s+\(\[int\]\$old\.ssl_flags\)') `
    'IIS rollback must restore the original SSL flags.'
Assert-True ($agent -match 'TLS_INTERCEPTION_DETECTED') `
    'IIS verification must classify recognized local TLS inspection.'
Assert-True ($agent -match 'Kaspersky Endpoint Security Personal Certification Authority') `
    'IIS verification must recognize the confirmed Kaspersky interception issuer.'
Assert-True ($agent -match 'served_certificate_subject\s*=\s*\$ServedCertificateSubject') `
    'Failed deployment reports must include the observed certificate subject.'
Assert-True ($agent -match 'served_certificate_issuer\s*=\s*\$ServedCertificateIssuer') `
    'Failed deployment reports must include the observed certificate issuer.'
Assert-True ($agent -match 'InstalledFingerprint\s*=\s*\$installedFingerprint') `
    'Failed deployment reports must preserve the imported certificate fingerprint.'
Assert-True ($agent -match "TLS interception was recorded[\s\S]+exit 0") `
    'A handled TLS interception must not leave the Windows scheduled task failed.'
Assert-True ($agent -match "Properties\.Remove\('enrollment_token_protected'\)") `
    'The IIS agent must remove the bootstrap credential after enrollment.'
Assert-True ($installer -match "Properties\.Remove\('enrollment_token_protected'\)") `
    'The IIS upgrade path must remove an obsolete bootstrap credential.'
Assert-True ($installer -match '\[switch\]\$EnableTask') `
    'The IIS installer must require an explicit switch to enable its scheduled task.'
Assert-True ($installer -match '\[switch\]\$RunOnce') `
    'The IIS installer must require an explicit switch for its initial agent run.'
Assert-True ($installer -match 'Register-ScheduledTask[\s\S]+-Principal \$taskPrincipal') `
    'The IIS installer must register its task through the ScheduledTasks module.'
Assert-True ($installer -match 'Disable-ScheduledTask -TaskName \$taskName') `
    'The IIS installer must disable the scheduled task during staged installation.'
Assert-True (($installer + $uninstaller) -notmatch 'schtasks\.exe') `
    'Windows setup scripts must not depend on schtasks.exe.'
Assert-True ($installer -match 'if \(\$RunOnce\)') `
    'The IIS installer must guard the initial agent execution with RunOnce.'
Assert-True ($installer -match 'if \(-not \$runHasStoredClientToken\)[\s\S]+agentArguments \+= ''-SkipUpdateCheck''') `
    'Initial enrollment must skip the update check until a client identity exists.'
Assert-True ($installer -match 'initialRunExitCode[\s\S]+lastAgentError[\s\S]+Last agent error') `
    'The installer must surface the final agent error when the requested initial run fails.'
Assert-True ($bootstrap -notmatch 'installer exited with code') `
    'The bootstrap must not replace a specific installer exception with a stale native exit code.'
Assert-True ($agent -match 'Unable to connect to CertM API[\s\S]+outbound TCP 443') `
    'Windows API connection failures must include actionable network checks.'
Assert-True ($agent -match 'CertM agent failed:') `
    'The Windows agent must log a concise top-level failure message.'
Assert-True ($installer -match 'existingTaskWasEnabled') `
    'The IIS upgrade path must preserve the existing certificate-task state.'
$assemblyLoad = $installer.IndexOf('Add-Type -AssemblyName System.Security')
$dpapiUse = $installer.IndexOf('[Security.Cryptography.ProtectedData]::Protect')
Assert-True ($assemblyLoad -ge 0 -and $dpapiUse -gt $assemblyLoad) `
    'The IIS installer must load System.Security before using DPAPI on Windows PowerShell 5.1.'
Assert-True ($agent -match "ConfigPath\s*=\s*'C:\\CertM\\config\.json'") `
    'The IIS agent configuration must default to C:\CertM\config.json.'
Assert-True ($agent -match "CertMRoot\s*=\s*'C:\\CertM'") `
    'The IIS agent runtime root must be C:\CertM.'
Assert-True ($installer -match '\$root\s*=\s*''C:\\CertM''') `
    'The IIS installer root must be C:\CertM.'
Assert-True ($uninstaller -match '\$root\s*=\s*''C:\\CertM''') `
    'The IIS uninstaller root must be C:\CertM.'
Assert-True (($agent + $installer + $bootstrap + $updater + $uninstaller) -notmatch 'ProgramData') `
    'Windows agent scripts must not use the obsolete ProgramData installation root.'

Write-Host 'Windows agent contract validation passed.'
