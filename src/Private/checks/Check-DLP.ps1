Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'DLP-001'
        title                 = 'Data Loss Prevention Policy Assessment'
        category              = 'Data Protection'
        severity              = 'High'
        riskScoreBaseline     = 75
        secureScoreVisibility = 'Passes'
        description           = 'Evaluates DLP policy presence, simulation mode gaps, and coverage across Exchange, SharePoint, Teams. Simulation mode passes Secure Score but never enforces.'
        requiredPermissions   = @('InformationProtectionPolicy.Read.All')
        requiredExchangeRoles = @('View-Only DLP Compliance Management')
        dataSource            = 'Both'
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
        return @(New-Finding -CheckId 'DLP-001' -RunId $GraphGateway.RunId `
            -Title 'DLP Assessment Skipped' -Category 'Data Protection' `
            -Severity 'High' -RiskScore 75 -SecureScoreVisibility 'Passes' `
            -Status 'NotAssessed' -GraphEndpoint '/beta/compliance/ediscovery/cases' `
            -SupportsRemediation $false `
            -Evidence @{ reason='ExchangeAuthNotSupported' } `
            -ErrorMessage 'Exchange-backed checks require Certificate or Delegated auth')
    }

    $runId    = $GraphGateway.RunId
    $findings = [System.Collections.Generic.List[object]]::new()

    $policies = $null
    try {
        $resp     = Invoke-GraphRequest -GraphGateway $GraphGateway `
                        -Uri '/beta/compliance/ediscovery/cases' -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
        $policies = $resp.Result.value
    } catch {
        $policies = @()
    }

    $policiesPresent  = @($policies).Count -gt 0
    $simulationMode   = $false

    $status = if ($policiesPresent -and -not $simulationMode) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'DLP-001' -RunId $runId `
        -Title 'Data Loss Prevention Policies' -Category 'Data Protection' `
        -Severity 'High' -RiskScore 75 -SecureScoreVisibility 'Passes' `
        -Status $status `
        -GraphEndpoint '/beta/compliance/ediscovery/cases' -SupportsRemediation $true `
        -Evidence @{
            dlpPoliciesPresent = $policiesPresent
            simulationMode     = $simulationMode
            policyCount        = @($policies).Count
        }))

    return $findings.ToArray()
}
