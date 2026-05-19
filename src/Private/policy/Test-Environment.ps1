Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PSVersion { return $PSVersionTable.PSVersion }

function Test-Environment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Certificate','Secret','Delegated')] [string] $AuthMethod,
        [Parameter(Mandatory)][bool] $RequireExchange
    )

    $failures = [System.Collections.Generic.List[string]]::new()

    $psVer = Get-PSVersion
    if ($psVer -lt [Version]'7.2') {
        $failures.Add("PowerShell 7.2+ required. Found: $psVer")
    }

    if ($RequireExchange) {
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            $failures.Add('ExchangeOnlineManagement module not found')
        }
    }

    return [PSCustomObject]@{
        IsValid  = ($failures.Count -eq 0)
        Failures = $failures.ToArray()
    }
}
