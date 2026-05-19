Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Rules {
    @(
        [PSCustomObject]@{
            ruleId          = 'PIM-DEP-001'
            appliesToAction = 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='PIMEnabled'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency=$null; blockIfUnsatisfied=$true; reason='PIM must be licensed and enabled before converting role assignments' }
            priority        = 1; category='PrivilegedAccess'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'PIM-BLOCK-001'
            appliesToAction = 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE'
            type            = 'Block'
            condition       = [PSCustomObject]@{ fact='PIMEnabled'; operator='Equals'; value=$false }
            effect          = [PSCustomObject]@{ dependency=$null; blockIfUnsatisfied=$true; reason='PIM not enabled — all PIM remediation blocked' }
            priority        = 10; category='PrivilegedAccess'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'PIM-DEP-002'
            appliesToAction = 'ACT-PIM-CONFIGURE-ROLE-SETTINGS'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='PIMConversionComplete'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE'; blockIfUnsatisfied=$false; reason='Role settings should be configured after active-to-eligible conversion' }
            priority        = 2; category='PrivilegedAccess'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'PIM-DEP-003'
            appliesToAction = 'ACT-PIM-ENABLE-TIER0-ROLE'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='ApprovalWorkflowConfigured'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-PIM-CONFIGURE-APPROVAL-WORKFLOW'; blockIfUnsatisfied=$true; reason='Tier-0 role activation requires approval workflow before enablement' }
            priority        = 3; category='PrivilegedAccess'; version='1.0.0'
        }
    )
}
