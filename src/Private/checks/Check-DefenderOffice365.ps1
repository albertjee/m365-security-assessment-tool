Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'DEF-001'
        title                 = 'Microsoft Defender for Office 365 Assessment'
        category              = 'Email Security'
        severity              = 'High'
        riskScoreBaseline     = 75
        secureScoreVisibility = 'Passes'
        description           = 'Evaluates anti-phishing preset policies, Safe Links, and Safe Attachments. Default preset passes Secure Score but is weaker than Standard or Strict.'
        requiredPermissions   = @()
        requiredExchangeRoles = @('View-Only Configuration')
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
        return @(New-Finding -CheckId 'DEF-001' -RunId $GraphGateway.RunId `
            -Title 'Defender for Office 365 Assessment Skipped' -Category 'Email Security' `
            -Severity 'High' -RiskScore 75 -SecureScoreVisibility 'Passes' `
            -Status 'NotAssessed' -GraphEndpoint 'Exchange:Get-AntiPhishPolicy' `
            -SupportsRemediation $false `
            -Evidence @{ reason='ExchangeAuthNotSupported' } `
            -ErrorMessage 'Exchange-backed checks require Certificate or Delegated auth')
    }

    $runId    = $GraphGateway.RunId
    $findings = [System.Collections.Generic.List[object]]::new()

    $antiPhishPreset = 'Default'
    $safeLinksEnabled       = $false
    $safeAttachmentsEnabled = $false

    try {
        $antiPhish = Invoke-ExchangeRequest -CmdletName 'Get-AntiPhishPolicy' -Parameters @{} -OperationType 'Read'
        if ($antiPhish) {
            $policies = @($antiPhish)
            $standardOrStrict = $policies | Where-Object {
                $_.PSObject.Properties['Identity'] -and
                ($_.Identity -match 'Standard|Strict')
            }
            if ($standardOrStrict) { $antiPhishPreset = 'Standard' }
        }

        $safeLinksPolicy = Invoke-ExchangeRequest -CmdletName 'Get-SafeLinksPolicy' -Parameters @{} -OperationType 'Read'
        $safeLinksEnabled = @($safeLinksPolicy | Where-Object {
            $_.PSObject.Properties['IsEnabled'] -and $_.IsEnabled -eq $true
        }).Count -gt 0

        $safeAttachPolicy = Invoke-ExchangeRequest -CmdletName 'Get-SafeAttachmentPolicy' -Parameters @{} -OperationType 'Read'
        $safeAttachmentsEnabled = @($safeAttachPolicy | Where-Object {
            $_.PSObject.Properties['Enable'] -and $_.Enable -eq $true
        }).Count -gt 0
    } catch {
        $findings.Add((New-Finding -CheckId 'DEF-001' -RunId $runId `
            -Title 'Defender for Office 365 Assessment Failed' -Category 'Email Security' `
            -Severity 'High' -RiskScore 75 -SecureScoreVisibility 'Passes' `
            -Status 'NotAssessed' -GraphEndpoint 'Exchange:Get-AntiPhishPolicy' `
            -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    $pass = $antiPhishPreset -ne 'Default' -and $safeLinksEnabled -and $safeAttachmentsEnabled

    $status = if ($pass) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'DEF-001' -RunId $runId `
        -Title 'Defender for Office 365 Preset and ATP Policies' -Category 'Email Security' `
        -Severity 'High' -RiskScore 75 -SecureScoreVisibility 'Passes' `
        -Status $status `
        -GraphEndpoint 'Exchange:Get-AntiPhishPolicy' -SupportsRemediation $true `
        -Evidence @{
            antiPhishPreset         = $antiPhishPreset
            safeLinksEnabled        = $safeLinksEnabled
            safeAttachmentsEnabled  = $safeAttachmentsEnabled
        }))

    return $findings.ToArray()
}
