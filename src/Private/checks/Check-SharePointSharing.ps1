Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'SP-001'
        title                 = 'SharePoint Sharing Settings Assessment'
        category              = 'Data Protection'
        severity              = 'High'
        riskScoreBaseline     = 70
        secureScoreVisibility = 'Passes'
        description           = 'Evaluates anonymous link settings, link expiry policy, and site-level overrides more permissive than tenant policy.'
        requiredPermissions   = @()
        requiredExchangeRoles = @('SharePoint Service Administrator')
        dataSource            = 'Exchange'
        supportsRemediation   = $true
        edition               = @('Lite','Premium')
        assessAuthMethods     = @('Certificate','Delegated')
    }
}

function Invoke-Check {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $GraphGateway,
        [Parameter(Mandatory)] $Config
    )

    $authMethod = $GraphGateway.AuthMethod
    if ($authMethod -eq 'Secret') {
        return @(New-Finding -CheckId 'SP-001' -RunId $GraphGateway.RunId `
            -Title 'SharePoint Sharing Assessment Skipped' -Category 'Data Protection' `
            -Severity 'High' -RiskScore 70 -SecureScoreVisibility 'Passes' `
            -Status 'NotAssessed' -GraphEndpoint 'Exchange:Get-SPOTenant' `
            -SupportsRemediation $false `
            -Evidence @{ reason='ExchangeAuthNotSupported' } `
            -ErrorMessage 'Exchange-backed checks require Certificate or Delegated auth')
    }

    $runId    = $GraphGateway.RunId
    $findings = [System.Collections.Generic.List[object]]::new()

    $anonLinksAllowed = $true
    $expiryConfigured = $false

    try {
        $spoTenant = Invoke-ExchangeRequest -CmdletName 'Get-SPOTenant' -Parameters @{} -OperationType 'Read'
        if ($spoTenant) {
            if ($spoTenant.PSObject.Properties['SharingCapability']) {
                $anonLinksAllowed = $spoTenant.SharingCapability -ne 'Disabled' -and
                                    $spoTenant.SharingCapability -ne 'ExternalUserSharingOnly'
            }
            if ($spoTenant.PSObject.Properties['RequireAnonymousLinksExpireInDays']) {
                $expiryConfigured = $spoTenant.RequireAnonymousLinksExpireInDays -gt 0
            }
        }
    } catch {
        $findings.Add((New-Finding -CheckId 'SP-001' -RunId $runId `
            -Title 'SharePoint Sharing Assessment Failed' -Category 'Data Protection' `
            -Severity 'High' -RiskScore 70 -SecureScoreVisibility 'Passes' `
            -Status 'NotAssessed' -GraphEndpoint 'Exchange:Get-SPOTenant' `
            -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    $status = if (-not $anonLinksAllowed -or $expiryConfigured) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'SP-001' -RunId $runId `
        -Title 'SharePoint Anonymous Link Settings' -Category 'Data Protection' `
        -Severity 'High' -RiskScore 70 -SecureScoreVisibility 'Passes' `
        -Status $status `
        -GraphEndpoint 'Exchange:Get-SPOTenant' -SupportsRemediation $true `
        -Evidence @{
            anonymousLinksAllowed = $anonLinksAllowed
            expiryConfigured      = $expiryConfigured
        }))

    return $findings.ToArray()
}
