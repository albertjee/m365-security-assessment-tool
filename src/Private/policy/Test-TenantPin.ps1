Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-TenantIdFromToken {
    param([Parameter(Mandatory)] $GraphGateway)
    $token = $GraphGateway.AccessToken
    if (-not $token) { throw 'No access token available on GraphGateway.' }
    $payload = $token.Split('.')[1]
    $payload = $payload.Replace('-', '+').Replace('_', '/')
    $padded  = $payload + ('=' * ((4 - $payload.Length % 4) % 4))
    $json    = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded))
    $claims  = $json | ConvertFrom-Json
    return $claims.tid
}

function Get-TenantIdFromOrganization {
    param([Parameter(Mandatory)] $GraphGateway)
    $response = Invoke-GraphRequest -GraphGateway $GraphGateway -Uri '/organization' -Method 'GET' -OperationType 'Read' -Caller 'TenantPin'
    return $response.Result.value[0].id
}

function Test-TenantPin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string] $RequestedTenantId,
        [Parameter(Mandatory)] $GraphGateway
    )

    if ([string]::IsNullOrWhiteSpace($RequestedTenantId)) {
        return [PSCustomObject]@{ Match=$false; MismatchReason='RequestedTenantMissing'; TokenTenantId=$null; OrganizationTenantId=$null }
    }

    $tokenTid = $null
    $orgTid   = $null
    $tokenOk  = $false
    $orgOk    = $false

    try { $tokenTid = Get-TenantIdFromToken -GraphGateway $GraphGateway; $tokenOk = $true } catch {}
    try { $orgTid   = Get-TenantIdFromOrganization -GraphGateway $GraphGateway; $orgOk = $true } catch {}

    if (-not $tokenOk -and -not $orgOk) {
        return [PSCustomObject]@{ Match=$false; MismatchReason='UnableToResolveTenant'; TokenTenantId=$null; OrganizationTenantId=$null }
    }

    if ($tokenOk -and $tokenTid -ne $RequestedTenantId) {
        return [PSCustomObject]@{ Match=$false; MismatchReason='TokenTenantMismatch'; TokenTenantId=$tokenTid; OrganizationTenantId=$orgTid }
    }

    if ($orgOk -and $orgTid -ne $RequestedTenantId) {
        return [PSCustomObject]@{ Match=$false; MismatchReason='OrganizationTenantMismatch'; TokenTenantId=$tokenTid; OrganizationTenantId=$orgTid }
    }

    return [PSCustomObject]@{ Match=$true; MismatchReason=$null; TokenTenantId=$tokenTid; OrganizationTenantId=$orgTid }
}
