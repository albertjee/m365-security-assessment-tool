Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'DLP-001'
        title                 = 'Data Loss Prevention Assessment'
        category              = 'Data Protection'
        severity              = 'High'
        riskScoreBaseline     = 78
        secureScoreVisibility = 'Passes'
        description           = 'Evaluates DLP compliance policies across workloads. Identifies absent policies, simulation-mode-only coverage, and workload gaps. DLP policies in AuditAndNotify mode pass Secure Score but do not enforce.'
        requiredPermissions   = @('InformationProtectionPolicy.Read.All')
        requiredExchangeRoles = @('Compliance Management')
        dataSource            = 'Exchange'
        supportsRemediation   = $true
        edition               = @('Lite', 'Premium')
        assessAuthMethods     = @('Certificate', 'Delegated')
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
    $exGw     = if ($Config -is [hashtable]) { $Config['ExchangeGateway'] } else { $Config.ExchangeGateway }

    if ($GraphGateway.AuthMethod -eq 'Secret') {
        $findings.Add((New-Finding -CheckId 'DLP-001' -RunId $runId `
            -Title 'DLP Assessment Unavailable' `
            -Category 'Data Protection' -Severity 'High' -RiskScore 78 `
            -SecureScoreVisibility 'Passes' -Status 'NotAssessed' `
            -Evidence @{} -GraphEndpoint 'Exchange:Get-DlpCompliancePolicy' -SupportsRemediation $false `
            -ErrorMessage 'ExchangeAuthNotSupported'))
        return $findings.ToArray()
    }

    $policies = @()
    try {
        $result   = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                        -CmdletName 'Get-DlpCompliancePolicy' -Parameters @{} `
                        -OperationType 'Read' -Caller 'Auditor'
        $policies = @($result.Result)
    } catch {
        $findings.Add((New-Finding -CheckId 'DLP-001' -RunId $runId `
            -Title 'DLP Assessment Failed' `
            -Category 'Data Protection' -Severity 'High' -RiskScore 78 `
            -SecureScoreVisibility 'Passes' -Status 'NotAssessed' `
            -Evidence @{} -GraphEndpoint 'Exchange:Get-DlpCompliancePolicy' -SupportsRemediation $false `
            -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    $absentStatus = if ($policies.Count -gt 0) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'DLP-001' -RunId $runId `
        -Title 'No DLP Compliance Policies Configured' `
        -Category 'Data Protection' -Severity 'High' -RiskScore 78 `
        -SecureScoreVisibility 'Passes' -Status $absentStatus `
        -Evidence @{
            policyCount        = $policies.Count
            dlpPoliciesPresent = ($policies.Count -gt 0)
        } `
        -GraphEndpoint 'Exchange:Get-DlpCompliancePolicy' -SupportsRemediation $true))

    if ($policies.Count -eq 0) { return $findings.ToArray() }

    $enforcedPolicies   = @($policies | Where-Object { $_.Mode -eq 'Enable' })
    $simulationPolicies = @($policies | Where-Object { $_.Mode -in @('AuditAndNotify', 'TestWithNotifications', 'Disable') })
    $simStatus = if ($enforcedPolicies.Count -gt 0) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'DLP-001' -RunId $runId `
        -Title 'DLP Policies in Simulation Mode Only (Not Enforced)' `
        -Category 'Data Protection' -Severity 'High' -RiskScore 72 `
        -SecureScoreVisibility 'Passes' -Status $simStatus `
        -Evidence @{
            totalPolicies       = $policies.Count
            enforcedCount       = $enforcedPolicies.Count
            simulationModeCount = $simulationPolicies.Count
            simulationNames     = @($simulationPolicies | Select-Object -ExpandProperty Name)
        } `
        -GraphEndpoint 'Exchange:Get-DlpCompliancePolicy' -SupportsRemediation $true))

    $requiredWorkloads = @('Exchange', 'SharePoint', 'Teams')
    $coveredWorkloads  = @()
    foreach ($policy in $policies) {
        if ($policy.PSObject.Properties['Workload'] -and $policy.Workload) {
            $coveredWorkloads += $policy.Workload -split ','
        }
    }
    $coveredWorkloads = @($coveredWorkloads | Select-Object -Unique)
    $missingWorkloads = @($requiredWorkloads | Where-Object { $_ -notin $coveredWorkloads })
    $coverageStatus   = if ($missingWorkloads.Count -eq 0) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'DLP-001' -RunId $runId `
        -Title 'DLP Policy Coverage Gaps Across Key Workloads' `
        -Category 'Data Protection' -Severity 'High' -RiskScore 68 `
        -SecureScoreVisibility 'Passes' -Status $coverageStatus `
        -Evidence @{
            requiredWorkloads = $requiredWorkloads
            coveredWorkloads  = $coveredWorkloads
            missingWorkloads  = $missingWorkloads
        } `
        -GraphEndpoint 'Exchange:Get-DlpCompliancePolicy' -SupportsRemediation $true))

    return $findings.ToArray()
}
