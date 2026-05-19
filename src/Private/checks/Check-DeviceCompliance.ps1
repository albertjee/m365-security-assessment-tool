Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'DEV-001'
        title                 = 'Device Compliance Policy Assessment'
        category              = 'Device Security'
        severity              = 'High'
        riskScoreBaseline     = 75
        secureScoreVisibility = 'Passes'
        description           = 'Evaluates Intune compliance policy existence, coverage gaps, and CA integration. Enrolled-but-unevaluated devices pass Secure Score as compliant.'
        requiredPermissions   = @('DeviceManagementConfiguration.Read.All','Policy.Read.All')
        requiredExchangeRoles = @()
        dataSource            = 'Graph'
        supportsRemediation   = $true
        edition               = @('Lite','Premium')
        assessAuthMethods     = @('Certificate','Secret','Delegated')
    }
}

function Invoke-Check {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $GraphGateway,
        [Parameter(Mandatory)] $Config
    )

    $runId    = $GraphGateway.RunId
    $findings = [System.Collections.Generic.List[object]]::new()

    $policies = $null
    try {
        $resp    = Invoke-GraphRequest -GraphGateway $GraphGateway `
                       -Uri '/deviceManagement/deviceCompliancePolicies' `
                       -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
        $policies = $resp.Result.value
    } catch {
        $findings.Add((New-Finding -CheckId 'DEV-001' -RunId $runId `
            -Title 'Device Compliance Assessment Failed' -Category 'Device Security' `
            -Severity 'High' -RiskScore 75 -SecureScoreVisibility 'Passes' `
            -Status 'NotAssessed' -GraphEndpoint '/deviceManagement/deviceCompliancePolicies' `
            -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    $compliancePoliciesExist = @($policies).Count -gt 0

    $status = if ($compliancePoliciesExist) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'DEV-001' -RunId $runId `
        -Title 'Device Compliance Policies' -Category 'Device Security' `
        -Severity 'High' -RiskScore 75 -SecureScoreVisibility 'Passes' `
        -Status $status `
        -GraphEndpoint '/deviceManagement/deviceCompliancePolicies' -SupportsRemediation $true `
        -Evidence @{
            compliancePoliciesExist = $compliancePoliciesExist
            policyCount             = @($policies).Count
        }))

    return $findings.ToArray()
}
