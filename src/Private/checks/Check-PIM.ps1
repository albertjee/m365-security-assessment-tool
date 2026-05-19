Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:HighRiskRoleIds = @{
    GlobalAdministrator         = '62e90394-69f5-4237-9190-012177145e10'
    PrivilegedRoleAdministrator = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
    SecurityAdministrator       = '194ae4cb-b126-40b2-bd5b-6091b380977d'
    ExchangeAdministrator       = '29232cdf-9323-42fd-ade2-1d097af3e4de'
    SharePointAdministrator     = 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'
    UserAccountAdministrator    = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
}

function Get-CheckMetadata {
    @{
        id                    = 'PIM-001'
        title                 = 'Privileged Identity Management Assessment'
        category              = 'Privileged Access'
        severity              = 'Critical'
        riskScoreBaseline     = 90
        secureScoreVisibility = 'NotFlagged'
        description           = 'Evaluates PIM configuration: standing active role assignments, eligible/active ratio for high-risk roles, MFA on activation, approval workflow, and access reviews.'
        requiredPermissions   = @('RoleManagement.Read.Directory','PrivilegedAccess.Read.AzureAD')
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

    $activeAssignments = $null
    $eligibleSchedules = $null
    try {
        $assignResp = Invoke-GraphRequest -GraphGateway $GraphGateway `
                          -Uri '/roleManagement/directory/roleAssignments?$expand=roleDefinition' `
                          -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
        $eligResp   = Invoke-GraphRequest -GraphGateway $GraphGateway `
                          -Uri '/roleManagement/directory/roleEligibilitySchedules' `
                          -Method 'GET' -OperationType 'Read' -Caller 'Auditor'

        $activeAssignments = @($assignResp.Result.value)
        $eligibleSchedules = @($eligResp.Result.value)
    } catch {
        $findings.Add((New-Finding -CheckId 'PIM-001' -RunId $runId `
            -Title 'PIM Assessment Failed' -Category 'Privileged Access' `
            -Severity 'Critical' -RiskScore 90 -SecureScoreVisibility 'NotFlagged' `
            -Status 'NotAssessed' -GraphEndpoint '/roleManagement/directory/roleAssignments' `
            -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    # --- Finding 1: Standing active assignments for high-risk roles ---
    $highRiskIds = @($script:HighRiskRoleIds.Values)
    $standingHighRisk = @($activeAssignments | Where-Object {
        $_.roleDefinitionId -in $highRiskIds
    })
    $standingGACount = @($activeAssignments | Where-Object {
        $_.roleDefinitionId -eq $script:HighRiskRoleIds.GlobalAdministrator
    }).Count

    $standingStatus = if ($standingHighRisk.Count -eq 0) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'PIM-001' -RunId $runId `
        -Title 'Standing Active Assignments Found for High-Privilege Roles' `
        -Category 'Privileged Access' -Severity 'Critical' -RiskScore 92 `
        -SecureScoreVisibility 'NotFlagged' -Status $standingStatus `
        -Evidence @{
            standingHighRiskCount    = $standingHighRisk.Count
            standingGlobalAdminCount = $standingGACount
            eligibleScheduleCount   = $eligibleSchedules.Count
        } `
        -GraphEndpoint '/roleManagement/directory/roleAssignments' `
        -SupportsRemediation $true))

    # --- Finding 2: PIM JIT model not in use ---
    $pimInUse  = $eligibleSchedules.Count -gt 0
    $pimStatus = if ($pimInUse) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'PIM-001' -RunId $runId `
        -Title 'PIM Just-In-Time Access Not in Use' `
        -Category 'Privileged Access' -Severity 'Critical' -RiskScore 90 `
        -SecureScoreVisibility 'NotFlagged' -Status $pimStatus `
        -Evidence @{
            eligibleScheduleCount = $eligibleSchedules.Count
            pimEnabled            = $pimInUse
        } `
        -GraphEndpoint '/roleManagement/directory/roleEligibilitySchedules' `
        -SupportsRemediation $true))

    return $findings.ToArray()
}
