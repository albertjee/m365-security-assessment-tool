Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Rules {
    @(
        [PSCustomObject]@{
            ruleId          = 'LA-DEP-001'
            appliesToAction = 'ACT-LA-BLOCK-PROTOCOLS'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='CAFrameworkPresent'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-CA-BASELINE'; blockIfUnsatisfied=$true; reason='Conditional Access framework must exist before blocking legacy auth protocols at policy layer' }
            priority        = 2; category='Identity'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'LA-ADV-001'
            appliesToAction = 'ACT-LA-BLOCK-PROTOCOLS'
            type            = 'Advisory'
            condition       = [PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency=$null; blockIfUnsatisfied=$false; reason='Advisory: review sign-in logs for legacy auth usage before blocking — prevents unexpected client lockout' }
            priority        = 1; category='Identity'; version='1.0.0'
        }
    )
}
