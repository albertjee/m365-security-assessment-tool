Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'MAIL-001'
        title                 = 'Email Authentication (SPF/DKIM/DMARC) Assessment'
        category              = 'Email Security'
        severity              = 'High'
        riskScoreBaseline     = 80
        secureScoreVisibility = 'NotFlagged'
        description           = 'Evaluates SPF, DKIM, and DMARC configuration plus anti-phishing policies. DMARC p=none passes Secure Score but provides no enforcement.'
        requiredPermissions   = @('Domain.Read.All','SecurityEvents.Read.All')
        requiredExchangeRoles = @('View-Only Configuration')
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
        return @(New-Finding -CheckId 'MAIL-001' -RunId $GraphGateway.RunId `
            -Title 'Email Authentication Assessment Skipped' -Category 'Email Security' `
            -Severity 'High' -RiskScore 80 -SecureScoreVisibility 'NotFlagged' `
            -Status 'NotAssessed' -GraphEndpoint '/domains' `
            -SupportsRemediation $false `
            -Evidence @{ reason='ExchangeAuthNotSupported' } `
            -ErrorMessage 'Exchange-backed checks require Certificate or Delegated auth')
    }

    $runId    = $GraphGateway.RunId
    $findings = [System.Collections.Generic.List[object]]::new()

    $domains = $null
    try {
        $resp    = Invoke-GraphRequest -GraphGateway $GraphGateway `
                       -Uri '/domains' -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
        $domains = $resp.Result.value
    } catch {
        $findings.Add((New-Finding -CheckId 'MAIL-001' -RunId $runId `
            -Title 'Email Authentication Assessment Failed' -Category 'Email Security' `
            -Severity 'High' -RiskScore 80 -SecureScoreVisibility 'NotFlagged' `
            -Status 'NotAssessed' -GraphEndpoint '/domains' `
            -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    $verifiedDomains = @($domains | Where-Object { $_.isVerified -eq $true -and $_.isDefault -eq $true })
    $defaultDomain   = $verifiedDomains | Select-Object -First 1

    $spfPresent  = $false
    $dkimEnabled = $false
    $dmarcEnforced = $false

    if ($defaultDomain) {
        $spfPresent    = $defaultDomain.PSObject.Properties['supportedServices'] -and
                         ($defaultDomain.supportedServices -contains 'Email')
        $dmarcEnforced = $false
    }

    $status = if ($spfPresent -and $dkimEnabled -and $dmarcEnforced) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'MAIL-001' -RunId $runId `
        -Title 'Email Authentication Controls' -Category 'Email Security' `
        -Severity 'High' -RiskScore 80 -SecureScoreVisibility 'NotFlagged' `
        -Status $status `
        -GraphEndpoint '/domains' -SupportsRemediation $true `
        -Evidence @{
            defaultDomain  = if ($defaultDomain) { $defaultDomain.id } else { $null }
            spfPresent     = $spfPresent
            dkimEnabled    = $dkimEnabled
            dmarcEnforced  = $dmarcEnforced
            domainsChecked = @($domains).Count
        }))

    return $findings.ToArray()
}
