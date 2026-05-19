Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'SMTP-001'
        title                 = 'SMTP AUTH Configuration Assessment'
        category              = 'Email Security'
        severity              = 'High'
        riskScoreBaseline     = 70
        secureScoreVisibility = 'NotFlagged'
        description           = 'Evaluates SMTP AUTH at tenant and mailbox level. SMTP AUTH enables password spray attacks and MFA bypass for legacy email clients.'
        requiredPermissions   = @()
        requiredExchangeRoles = @('View-Only Configuration')
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
        return @(New-Finding -CheckId 'SMTP-001' -RunId $GraphGateway.RunId `
            -Title 'SMTP AUTH Assessment Skipped' -Category 'Email Security' `
            -Severity 'High' -RiskScore 70 -SecureScoreVisibility 'NotFlagged' `
            -Status 'NotAssessed' -GraphEndpoint 'Exchange:Get-TransportConfig' `
            -SupportsRemediation $false `
            -Evidence @{ reason='ExchangeAuthNotSupported' } `
            -ErrorMessage 'Exchange-backed checks require Certificate or Delegated auth')
    }

    $runId    = $GraphGateway.RunId
    $findings = [System.Collections.Generic.List[object]]::new()

    $smtpEnabled = $true
    try {
        $transportConfig = Invoke-ExchangeRequest -CmdletName 'Get-TransportConfig' -Parameters @{} -OperationType 'Read'
        if ($transportConfig -and $transportConfig.PSObject.Properties['SmtpClientAuthenticationDisabled']) {
            $smtpEnabled = -not $transportConfig.SmtpClientAuthenticationDisabled
        }
    } catch {
        $findings.Add((New-Finding -CheckId 'SMTP-001' -RunId $runId `
            -Title 'SMTP AUTH Assessment Failed' -Category 'Email Security' `
            -Severity 'High' -RiskScore 70 -SecureScoreVisibility 'NotFlagged' `
            -Status 'NotAssessed' -GraphEndpoint 'Exchange:Get-TransportConfig' `
            -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    $status = if (-not $smtpEnabled) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'SMTP-001' -RunId $runId `
        -Title 'SMTP AUTH Tenant Configuration' -Category 'Email Security' `
        -Severity 'High' -RiskScore 70 -SecureScoreVisibility 'NotFlagged' `
        -Status $status `
        -GraphEndpoint 'Exchange:Get-TransportConfig' -SupportsRemediation $true `
        -Evidence @{
            smtpAuthEnabled = $smtpEnabled
        }))

    return $findings.ToArray()
}
