$ErrorActionPreference = 'Stop'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$agentPath = Join-Path $repositoryRoot 'windows\CertM.Agent.ps1'
$installerPath = Join-Path $repositoryRoot 'windows\Install-CertMAgent.ps1'
$configPath = Join-Path $repositoryRoot 'windows\config.example.json'

$agent = Get-Content -LiteralPath $agentPath -Raw -Encoding UTF8
$installer = Get-Content -LiteralPath $installerPath -Raw -Encoding UTF8
$uninstaller = Get-Content -LiteralPath (Join-Path $repositoryRoot 'windows\Uninstall-CertMAgent.ps1') -Raw -Encoding UTF8
$config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json

Assert-True ($config.config_version -eq 3) 'Windows example config must use config_version=3.'
Assert-True ($config.PSObject.Properties.Name -notcontains 'managed_domains') `
    'Windows example config must not contain managed_domains.'
Assert-True ($agent -notmatch 'function\s+Test-DomainAllowed') `
    'The IIS agent must not filter dynamically discovered domains.'
Assert-True ($agent -notmatch 'Test-DomainAllowed\s+\$binding\.domain') `
    'The IIS deployment loop must evaluate every discovered hostname binding.'
Assert-True ($installer -notmatch '\[string\[\]\]\$ManagedDomains') `
    'The IIS installer must not accept a static ManagedDomains list.'
Assert-True ($agent -match "AgentVersion\s*=\s*'1\.0\.0-rc\.2'") `
    'The IIS agent release candidate version is missing.'
Assert-True ($agent -match "ValidateSet\('Run', 'Discover', 'Inventory', 'DryRun'\)") `
    'The IIS agent must expose safe discovery and dry-run modes.'
Assert-True ($installer -match 'Existing DPAPI-protected client identity preserved') `
    'The IIS upgrade path must preserve the existing client identity.'
Assert-True ($installer -match '\[switch\]\$EnableTask') `
    'The IIS installer must require an explicit switch to enable its scheduled task.'
Assert-True ($installer -match '\[switch\]\$RunOnce') `
    'The IIS installer must require an explicit switch for its initial agent run.'
Assert-True ($installer -match 'schtasks\.exe /Change /TN \$taskName /DISABLE') `
    'The IIS installer must disable the scheduled task during staged installation.'
Assert-True ($installer -match 'if \(\$RunOnce\)') `
    'The IIS installer must guard the initial agent execution with RunOnce.'
Assert-True ($agent -match "ConfigPath\s*=\s*'C:\\CertM\\config\.json'") `
    'The IIS agent configuration must default to C:\CertM\config.json.'
Assert-True ($agent -match "CertMRoot\s*=\s*'C:\\CertM'") `
    'The IIS agent runtime root must be C:\CertM.'
Assert-True ($installer -match '\$root\s*=\s*''C:\\CertM''') `
    'The IIS installer root must be C:\CertM.'
Assert-True ($uninstaller -match '\$root\s*=\s*''C:\\CertM''') `
    'The IIS uninstaller root must be C:\CertM.'
Assert-True (($agent + $installer + $uninstaller) -notmatch 'ProgramData') `
    'Windows agent scripts must not use the obsolete ProgramData installation root.'

Write-Host 'Windows agent contract validation passed.'
