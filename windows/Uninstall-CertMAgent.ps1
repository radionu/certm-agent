[CmdletBinding()]
param([switch]$RemoveData)

$ErrorActionPreference = 'Stop'
$root = 'C:\CertM'

& schtasks.exe /Delete /TN 'CertM IIS Agent' /F 2>$null | Out-Null
& schtasks.exe /Delete /TN 'CertM Agent Update' /F 2>$null | Out-Null
if ($RemoveData -and (Test-Path -LiteralPath $root)) {
    Remove-Item -LiteralPath $root -Recurse -Force
    Write-Host 'CertM IIS Agent, configuration, state, and logs were removed.'
}
else {
    $bin = Join-Path $root 'bin'
    if (Test-Path -LiteralPath $bin) { Remove-Item -LiteralPath $bin -Recurse -Force }
    Write-Host "CertM IIS Agent was removed. Configuration and logs remain in $root"
}
[CmdletBinding()]
param([switch]$RemoveData)

$ErrorActionPreference = 'Stop'
$root = 'C:\CertM'

Import-Module ScheduledTasks -ErrorAction Stop
foreach ($taskName in @('CertM IIS Agent', 'CertM Agent Update')) {
    if ($null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
        Unregister-ScheduledTask `
            -TaskName $taskName `
            -Confirm:$false `
            -ErrorAction Stop
    }
}
if ($RemoveData -and (Test-Path -LiteralPath $root)) {
    Remove-Item -LiteralPath $root -Recurse -Force
    Write-Host 'CertM IIS Agent, configuration, state, and logs were removed.'
}
else {
    $bin = Join-Path $root 'bin'
    if (Test-Path -LiteralPath $bin) { Remove-Item -LiteralPath $bin -Recurse -Force }
    Write-Host "CertM IIS Agent was removed. Configuration and logs remain in $root"
}
