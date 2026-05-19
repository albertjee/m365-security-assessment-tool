Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Rules {
    @(
        [PSCustomObject]@{
            ruleId          = 'CA-DEP-001'
            appliesToAction = 'ACT-CA-ENABLE-MFA'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-CA-EXCLUDE-BREAKGLASS'; blockIfUnsatisfied=$true; reason='Break-glass accounts must be excluded before enabling MFA policy' }
            priority        = 1; category='Identity'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'CA-BLOCK-001'
            appliesToAction = 'ACT-CA-ENABLE-MFA'
            type            = 'Block'
            condition       = [PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$false }
            effect          = [PSCustomObject]@{ dependency=$null; blockIfUnsatisfied=$true; reason='Cannot enable MFA policy: no break-glass accounts present. Lockout risk.' }
            priority        = 10; category='Identity'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'CA-DEP-002'
            appliesToAction = 'ACT-CA-ENFORCE-MFA'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='LegacyAuthBlocked'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-CA-BLOCK-LEGACYAUTH'; blockIfUnsatisfied=$false; reason='Legacy auth block should precede MFA enforcement for clean audit trail' }
            priority        = 2; category='Identity'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'CA-CONFLICT-001'
            appliesToAction = 'ACT-CA-BLOCK-ALL'
            type            = 'Conflict'
            condition       = [PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ conflictsWith='ACT-CA-REQUIRE-MFA'; blockIfUnsatisfied=$false; reason='Block-all policy conflicts with per-user MFA grant policy' }
            priority        = 5; category='Identity'; version='1.0.0'
        }
    )
}
