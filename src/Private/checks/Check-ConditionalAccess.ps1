Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'CA-001'
        title                 = 'Conditional Access Policy Assessment'
        category              = 'Identity Security'
        severity              = 'Critical'
        riskScoreBaseline     = 90
        secureScoreVisibility = 'Passes'
        description           = 'Evaluates CA policies for legacy auth blocking, MFA enforcement, break-glass exclusions, and report-only gaps that pass Secure Score but do not enforce.'
        requiredPermissions   = @('Policy.Read.All')
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
                       -Uri '/identity/conditionalAccess/policies' `
                       -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
        $policies = $resp.Result.value
    } catch {
        $findings.Add((New-Finding -CheckId 'CA-001' -RunId $runId `
            -Title 'CA Policy Assessment Failed' -Category 'Identity Security' `
            -Severity 'Critical' -RiskScore 90 -SecureScoreVisibility 'Passes' `
            -Status 'NotAssessed' -GraphEndpoint '/identity/conditionalAccess/policies' `
            -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    $enabledPolicies = @($policies | Where-Object { $_.state -eq 'enabled' })

    # --- Finding 1: Legacy Authentication Block ---
    $legacyBlockPolicy = $enabledPolicies | Where-Object {
        $appTypes = $_.conditions.clientAppTypes
        $appTypes -and
        $appTypes -contains 'exchangeActiveSync' -and
        $appTypes -contains 'other' -and
        $_.grantControls.builtInControls -contains 'block'
    } | Select-Object -First 1

    $reportOnlyLegacy = @($policies | Where-Object {
        $_.state -eq 'enabledForReportingButNotEnforced' -and
        $_.conditions.clientAppTypes -and
        $_.conditions.clientAppTypes -contains 'exchangeActiveSync'
    })

    $legacyStatus = if ($legacyBlockPolicy) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'CA-001' -RunId $runId `
        -Title 'Legacy Authentication Not Blocked' `
        -Category 'Identity Security' -Severity 'Critical' -RiskScore 95 `
        -SecureScoreVisibility 'Passes' -Status $legacyStatus `
        -Evidence @{
            legacyAuthPolicyFound = [bool]$legacyBlockPolicy
            reportOnlyFound       = ($reportOnlyLegacy.Count -gt 0)
            reportOnlyPolicyCount = $reportOnlyLegacy.Count
            totalPolicies         = $policies.Count
        } `
        -GraphEndpoint '/identity/conditionalAccess/policies' `
        -SupportsRemediation $true))

    # --- Finding 2: MFA All Users ---
    $mfaAllUsers = $enabledPolicies | Where-Object {
        $_.conditions.users.includeUsers -contains 'All' -and
        $_.grantControls.builtInControls -contains 'mfa'
    } | Select-Object -First 1

    $mfaStatus = if ($mfaAllUsers) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'CA-001' -RunId $runId `
        -Title 'MFA Not Enforced for All Users' `
        -Category 'Identity Security' -Severity 'Critical' -RiskScore 90 `
        -SecureScoreVisibility 'Passes' -Status $mfaStatus `
        -Evidence @{
            mfaPolicyFound = [bool]$mfaAllUsers
            totalPolicies  = $policies.Count
        } `
        -GraphEndpoint '/identity/conditionalAccess/policies' `
        -SupportsRemediation $true))

    # --- Finding 3: Break-Glass Exclusions ---
    $breakGlassExclusion = $enabledPolicies | Where-Object {
        $_.conditions.users.excludeUsers.Count -gt 0 -or
        $_.conditions.users.excludeGroups.Count -gt 0
    } | Select-Object -First 1

    $bgStatus = if ($breakGlassExclusion) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'CA-001' -RunId $runId `
        -Title 'No Break-Glass Account Exclusions Found in CA Policies' `
        -Category 'Identity Security' -Severity 'Critical' -RiskScore 92 `
        -SecureScoreVisibility 'NotFlagged' -Status $bgStatus `
        -Evidence @{
            breakGlassFound        = [bool]$breakGlassExclusion
            policiesWithExclusions = @($enabledPolicies | Where-Object {
                $_.conditions.users.excludeUsers.Count -gt 0 -or
                $_.conditions.users.excludeGroups.Count -gt 0
            }).Count
        } `
        -GraphEndpoint '/identity/conditionalAccess/policies' `
        -SupportsRemediation $false))

    return $findings.ToArray()
}
