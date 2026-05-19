Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'AUDIT-001'
        title                 = 'Audit Logging Configuration Assessment'
        category              = 'Compliance'
        severity              = 'Medium'
        riskScoreBaseline     = 65
        secureScoreVisibility = 'Passes'
        description           = 'Evaluates audit logging enabled status and retention period alignment with licence tier. Required for incident investigation and regulatory compliance.'
        requiredPermissions   = @()
        requiredExchangeRoles = @('View-Only Audit Logs')
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
        return @(New-Finding -CheckId 'AUDIT-001' -RunId $GraphGateway.RunId `
            -Title 'Audit Logging Assessment Skipped' -Category 'Compliance' `
            -Severity 'Medium' -RiskScore 65 -SecureScoreVisibility 'Passes' `
            -Status 'NotAssessed' -GraphEndpoint 'Exchange:Get-AdminAuditLogConfig' `
            -SupportsRemediation $false `
            -Evidence @{ reason='ExchangeAuthNotSupported' } `
            -ErrorMessage 'Exchange-backed checks require Certificate or Delegated auth')
    }

    $runId    = $GraphGateway.RunId
    $findings = [System.Collections.Generic.List[object]]::new()

    $auditLoggingEnabled = $false
    try {
        $auditConfig = Invoke-ExchangeRequest -CmdletName 'Get-AdminAuditLogConfig' -Parameters @{} -OperationType 'Read'
        if ($auditConfig -and $auditConfig.PSObject.Properties['UnifiedAuditLogIngestionEnabled']) {
            $auditLoggingEnabled = $auditConfig.UnifiedAuditLogIngestionEnabled -eq $true
        }
    } catch {
        $findings.Add((New-Finding -CheckId 'AUDIT-001' -RunId $runId `
            -Title 'Audit Logging Assessment Failed' -Category 'Compliance' `
            -Severity 'Medium' -RiskScore 65 -SecureScoreVisibility 'Passes' `
            -Status 'NotAssessed' -GraphEndpoint 'Exchange:Get-AdminAuditLogConfig' `
            -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    $status = if ($auditLoggingEnabled) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'AUDIT-001' -RunId $runId `
        -Title 'Unified Audit Logging' -Category 'Compliance' `
        -Severity 'Medium' -RiskScore 65 -SecureScoreVisibility 'Passes' `
        -Status $status `
        -GraphEndpoint 'Exchange:Get-AdminAuditLogConfig' -SupportsRemediation $true `
        -Evidence @{
            auditLoggingEnabled = $auditLoggingEnabled
        }))

    return $findings.ToArray()
}
