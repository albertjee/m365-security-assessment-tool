Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Rules {
    @(
        [PSCustomObject]@{
            ruleId          = 'CC-001'
            appliesToAction = 'ACT-CA-ENFORCE-MFA'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='PIMEnabled'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-PIM-CONFIGURE-ROLE-SETTINGS'; blockIfUnsatisfied=$false
                                  reason='MFA enforcement for admins is stronger when PIM high-risk roles are already secured (CC-001)' }
            priority        = 3; category='CrossDomain'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'CC-002'
            appliesToAction = 'ACT-CA-REQUIRE-COMPLIANT-DEVICE'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='DeviceCompliancePoliciesExist'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-DEV-BASELINE-COMPLIANCE'; blockIfUnsatisfied=$true
                                  reason='Device compliance CA condition requires at least one compliance policy to exist (CC-002)' }
            priority        = 4; category='CrossDomain'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'CC-003'
            appliesToAction = 'ACT-DLP-ENFORCE'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-CA-IDENTITY-BASELINE'; blockIfUnsatisfied=$false
                                  reason='DLP enforcement (Phase 4) must follow identity baseline (Phase 2) to ensure data access is identity-gated before data controls apply (CC-003)' }
            priority        = 5; category='CrossDomain'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'CC-004'
            appliesToAction = 'ACT-CA-BLOCK-ALL-EXTERNAL'
            type            = 'Block'
            condition       = [PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency=$null; blockIfUnsatisfied=$true
                                  reason='ACT-CA-BLOCK-ALL-EXTERNAL blocked: EmergencyAccessTested fact not verified. Risk of complete tenant lockout (CC-004)' }
            priority        = 10; category='CrossDomain'; version='1.0.0'
        }
    )
}
