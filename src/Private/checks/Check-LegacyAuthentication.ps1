Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'LA-001'
        title                 = 'Legacy Authentication Assessment'
        category              = 'Identity Security'
        severity              = 'Critical'
        riskScoreBaseline     = 90
        secureScoreVisibility = 'Passes'
        description           = 'Evaluates whether legacy authentication protocols are blocked at tenant level and via Conditional Access. Legacy auth enables MFA bypass.'
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

    $authPolicy = $null
    $caPolicies = @()

    try {
        $authResp = Invoke-GraphRequest -GraphGateway $GraphGateway `
                        -Uri '/policies/authorizationPolicy' `
                        -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
        $authPolicy = $authResp.Result.value | Select-Object -First 1

        $caResp = Invoke-GraphRequest -GraphGateway $GraphGateway `
                      -Uri '/identity/conditionalAccess/policies' `
                      -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
        $caPolicies = @($caResp.Result.value)
    } catch {
        $findings.Add((New-Finding -CheckId 'LA-001' -RunId $runId `
            -Title 'Legacy Authentication Assessment Failed' -Category 'Identity Security' `
            -Severity 'Critical' -RiskScore 90 -SecureScoreVisibility 'Passes' `
            -Status 'NotAssessed' -GraphEndpoint '/policies/authorizationPolicy' `
            -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    $tenantBlocked = $authPolicy -and [bool]($authPolicy.blockLegacyAuthentication)

    $caLegacyBlock = @($caPolicies | Where-Object {
        $null -ne $_.PSObject.Properties['state'] -and
        $_.state -eq 'enabled' -and
        $null -ne $_.PSObject.Properties['conditions'] -and
        $_.conditions.clientAppTypes -contains 'exchangeActiveSync' -and
        $_.conditions.clientAppTypes -contains 'other' -and
        $null -ne $_.PSObject.Properties['grantControls'] -and
        $_.grantControls.builtInControls -contains 'block'
    })

    $caReportOnly = @($caPolicies | Where-Object {
        $null -ne $_.PSObject.Properties['state'] -and
        $_.state -eq 'enabledForReportingButNotEnforced' -and
        $null -ne $_.PSObject.Properties['conditions'] -and
        $_.conditions.clientAppTypes -contains 'exchangeActiveSync'
    })

    $isBlocked = $tenantBlocked -or ($caLegacyBlock.Count -gt 0)
    $status    = if ($isBlocked) { 'Pass' } else { 'Fail' }

    $findings.Add((New-Finding -CheckId 'LA-001' -RunId $runId `
        -Title 'Legacy Authentication Not Blocked at Tenant or CA Level' `
        -Category 'Identity Security' -Severity 'Critical' -RiskScore 90 `
        -SecureScoreVisibility 'Passes' -Status $status `
        -Evidence @{
            tenantLevelBlocked   = $tenantBlocked
            caBlockPolicyPresent = ($caLegacyBlock.Count -gt 0)
            caBlockPolicyCount   = $caLegacyBlock.Count
            caReportOnlyCount    = $caReportOnly.Count
            effectivelyBlocked   = $isBlocked
        } `
        -GraphEndpoint '/policies/authorizationPolicy' `
        -SupportsRemediation $true))

    return $findings.ToArray()
}
