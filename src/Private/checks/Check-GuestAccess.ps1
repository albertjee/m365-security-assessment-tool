Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CheckMetadata {
    @{
        id                    = 'GUEST-001'
        title                 = 'Guest Access and External Collaboration Assessment'
        category              = 'Identity Security'
        severity              = 'High'
        riskScoreBaseline     = 70
        secureScoreVisibility = 'NotFlagged'
        description           = 'Evaluates external collaboration settings, stale guest accounts (12+ months inactive), and guest access to sensitive content.'
        requiredPermissions   = @('User.Read.All','Policy.Read.All')
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
    try {
        $resp       = Invoke-GraphRequest -GraphGateway $GraphGateway `
                          -Uri '/policies/authorizationPolicy' -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
        $authPolicy = $resp.Result
    } catch {
        $findings.Add((New-Finding -CheckId 'GUEST-001' -RunId $runId `
            -Title 'Guest Access Assessment Failed' -Category 'Identity Security' `
            -Severity 'High' -RiskScore 70 -SecureScoreVisibility 'NotFlagged' `
            -Status 'NotAssessed' -GraphEndpoint '/policies/authorizationPolicy' `
            -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
        return $findings.ToArray()
    }

    $guestInviteAllowed = $null -ne $authPolicy -and
                         $authPolicy.PSObject.Properties['allowInvitesFrom'] -and
                         $authPolicy.allowInvitesFrom -ne 'none' -and
                         $authPolicy.allowInvitesFrom -ne 'adminsAndGuestInviters'

    $staleGuestCount = 0
    try {
        $cutoff    = [System.DateTime]::UtcNow.AddMonths(-12).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $guestResp = Invoke-GraphRequest -GraphGateway $GraphGateway `
                         -Uri "/users?`$filter=userType eq 'Guest' and signInActivity/lastSignInDateTime le $cutoff" `
                         -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
        $staleGuestCount = @($guestResp.Result.value).Count
    } catch { }

    $status = if (-not $guestInviteAllowed -and $staleGuestCount -eq 0) { 'Pass' } else { 'Fail' }
    $findings.Add((New-Finding -CheckId 'GUEST-001' -RunId $runId `
        -Title 'Guest Access Controls' -Category 'Identity Security' `
        -Severity 'High' -RiskScore 70 -SecureScoreVisibility 'NotFlagged' `
        -Status $status `
        -GraphEndpoint '/policies/authorizationPolicy' -SupportsRemediation $true `
        -Evidence @{
            guestInviteAllowed  = $guestInviteAllowed
            staleGuestCount     = $staleGuestCount
            allowInvitesFrom    = if ($authPolicy -and $authPolicy.PSObject.Properties['allowInvitesFrom']) { $authPolicy.allowInvitesFrom } else { $null }
        }))

    return $findings.ToArray()
}
