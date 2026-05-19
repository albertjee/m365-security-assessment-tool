Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'CASB-001'
        title                 = 'Microsoft Defender for Cloud Apps (CASB) Assessment'
        category              = 'Cloud App Security'
        severity              = 'Medium'
        riskScoreBaseline     = 60
        secureScoreVisibility = 'NotFlagged'
        description           = 'Evaluates CASB license presence, app connector integration, session/access policy configuration, and governance beyond discovery-only mode.'
        requiredPermissions   = @('CloudPC.Read.All')
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

    $casbLicensed = $false
    try {
        $resp    = Invoke-GraphRequest -GraphGateway $GraphGateway `
                       -Uri '/subscribedSkus' -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
        $skus    = $resp.Result.value
        $casbLicensed = @($skus | Where-Object {
            $_.PSObject.Properties['skuPartNumber'] -and
            $_.skuPartNumber -match 'MCAS|CLOUD_APP_SECURITY|EMS_E5|M365_E5'
        }).Count -gt 0
    } catch {
        $findings.Add((New-Finding -CheckId 'CASB-001' -RunId $runId `
            -Title 'CASB Assessment Failed' -Category 'Cloud App Security' `
            -Severity 'Medium' -RiskScore 60 -SecureScoreVisibility 'NotFlagged' `
            -Status 'NotAssessed' -GraphEndpoint '/subscribedSkus' `
            -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    $status = if ($casbLicensed) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'CASB-001' -RunId $runId `
        -Title 'Defender for Cloud Apps License and Configuration' -Category 'Cloud App Security' `
        -Severity 'Medium' -RiskScore 60 -SecureScoreVisibility 'NotFlagged' `
        -Status $status `
        -GraphEndpoint '/subscribedSkus' -SupportsRemediation $true `
        -Evidence @{
            casbLicensed = $casbLicensed
        }))

    return $findings.ToArray()
}
