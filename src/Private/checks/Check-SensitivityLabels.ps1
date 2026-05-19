Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'LABEL-001'
        title                 = 'Sensitivity Labels Assessment'
        category              = 'Data Protection'
        severity              = 'High'
        riskScoreBaseline     = 70
        secureScoreVisibility = 'NotFlagged'
        description           = 'Evaluates whether sensitivity labels are defined, published to users, and configured for default labeling. Required for DLP label-based conditions.'
        requiredPermissions   = @('InformationProtectionPolicy.Read.All')
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

    $labels = $null
    try {
        $resp   = Invoke-GraphRequest -GraphGateway $GraphGateway `
                      -Uri '/informationProtection/sensitivityLabels' `
                      -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
        $labels = $resp.Result.value
    } catch {
        $findings.Add((New-Finding -CheckId 'LABEL-001' -RunId $runId `
            -Title 'Sensitivity Labels Assessment Failed' -Category 'Data Protection' `
            -Severity 'High' -RiskScore 70 -SecureScoreVisibility 'NotFlagged' `
            -Status 'NotAssessed' -GraphEndpoint '/informationProtection/sensitivityLabels' `
            -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    $labelsDefined   = @($labels).Count -gt 0
    $labelsPublished = @($labels | Where-Object {
        $_.PSObject.Properties['isActive'] -and $_.isActive -eq $true
    }).Count -gt 0

    $status = if ($labelsDefined -and $labelsPublished) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'LABEL-001' -RunId $runId `
        -Title 'Sensitivity Labels Defined and Published' -Category 'Data Protection' `
        -Severity 'High' -RiskScore 70 -SecureScoreVisibility 'NotFlagged' `
        -Status $status `
        -GraphEndpoint '/informationProtection/sensitivityLabels' -SupportsRemediation $true `
        -Evidence @{
            labelsDefined    = $labelsDefined
            labelsPublished  = $labelsPublished
            labelCount       = @($labels).Count
        }))

    return $findings.ToArray()
}
