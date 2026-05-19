Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-GraphPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $RequiredPermissions,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $GrantedScopes
    )
    $grantedLower = $GrantedScopes | ForEach-Object { $_.ToLower() }
    $missing = $RequiredPermissions | Where-Object { $_.ToLower() -notin $grantedLower }
    return [PSCustomObject]@{
        IsValid = (@($missing).Count -eq 0)
        Missing = @($missing)
    }
}
