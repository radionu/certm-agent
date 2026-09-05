$ErrorActionPreference = 'Stop'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$agentPath = Join-Path $repositoryRoot 'windows\CertM.Agent.ps1'
$installerPath = Join-Path $repositoryRoot 'windows\Install-CertMAgent.ps1'
$bootstrapPath = Join-Path $repositoryRoot 'windows\Bootstrap-CertMAgent.ps1'
$configPath = Join-Path $repositoryRoot 'windows\config.example.json'

$agent = Get-Content -LiteralPath $agentPath -Raw -Encoding UTF8
$installer = Get-Content -LiteralPath $installerPath -Raw -Encoding UTF8
$bootstrap = Get-Content -LiteralPath $bootstrapPath -Raw -Encoding UTF8
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
Assert-True ($agent -match "AgentVersion\s*=\s*'1\.0\.0-rc\.7'") `
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
Assert-True ($bootstrap -match 'RunOnce\s*=\s*\$true') `
    'The one-command bootstrap must perform initial enrollment immediately.'
Assert-True ($bootstrap -match 'EnableTask\s*=\s*-not\s+\$Staged') `
    'The one-command bootstrap must enable automation unless staged mode is requested.'
Assert-True ($bootstrap -match "PSBoundParameters\.ContainsKey\('DisplayName'\)") `
    'The one-command bootstrap must preserve an existing display name unless explicitly changed.'
Assert-True ($bootstrap -match 'ZeroFreeBSTR') `
    'The one-command bootstrap must clear the plaintext credential buffer.'
Assert-True ($installer -match 'Copy-Item[^\r\n]+\$sourceUninstaller') `
    'The installer must retain the uninstaller with the installed agent.'
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
Assert-True ($agent -match "Properties\.Remove\('enrollment_token_protected'\)") `
    'The IIS agent must remove the bootstrap credential after enrollment.'
Assert-True ($installer -match "Properties\.Remove\('enrollment_token_protected'\)") `
    'The IIS upgrade path must remove an obsolete bootstrap credential.'
Assert-True ($installer -match '\[switch\]\$EnableTask') `
    'The IIS installer must require an explicit switch to enable its scheduled task.'
Assert-True ($installer -match '\[switch\]\$RunOnce') `
    'The IIS installer must require an explicit switch for its initial agent run.'
Assert-True ($installer -match 'schtasks\.exe /Change /TN \$taskName /DISABLE') `
    'The IIS installer must disable the scheduled task during staged installation.'
Assert-True ($installer -match 'if \(\$RunOnce\)') `
    'The IIS installer must guard the initial agent execution with RunOnce.'
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
Assert-True (($agent + $installer + $bootstrap + $uninstaller) -notmatch 'ProgramData') `
    'Windows agent scripts must not use the obsolete ProgramData installation root.'

Write-Host 'Windows agent contract validation passed.'
