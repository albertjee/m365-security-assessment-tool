Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-ExchangePermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $RequiredRoles,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $GrantedRoles
    )
    $missing = $RequiredRoles | Where-Object { $_ -notin $GrantedRoles }
    return [PSCustomObject]@{
        IsValid = (@($missing).Count -eq 0)
        Missing = @($missing)
    }
}
