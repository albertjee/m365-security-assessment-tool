Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Rules {
    @(
        [PSCustomObject]@{
            ruleId          = 'CC-001'
            appliesToAction = 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='CAFrameworkPresent'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-CA-BASELINE'; blockIfUnsatisfied=$false; reason='CA framework should be in place before PIM activation to enforce MFA on role activation' }
            priority        = 2; category='CrossControl'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'CC-002'
            appliesToAction = 'ACT-DEV-ENFORCE-COMPLIANCE'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='CAFrameworkPresent'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-CA-BASELINE'; blockIfUnsatisfied=$false; reason='Device compliance enforcement requires CA policies to gate access based on compliance state' }
            priority        = 2; category='CrossControl'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'CC-003'
            appliesToAction = 'ACT-DLP-ENFORCE'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='CAFrameworkPresent'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-CA-BASELINE'; blockIfUnsatisfied=$false; reason='DLP enforcement is more effective when CA controls are already limiting lateral movement' }
            priority        = 1; category='CrossControl'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'CC-004'
            appliesToAction = 'ACT-CA-ENABLE-MFA'
            type            = 'Block'
            condition       = [PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$false }
            effect          = [PSCustomObject]@{ dependency=$null; blockIfUnsatisfied=$true; reason='Lockout protection: break-glass accounts must exist before any MFA enforcement policy is enabled' }
            priority        = 15; category='CrossControl'; version='1.0.0'
        }
    )
}
