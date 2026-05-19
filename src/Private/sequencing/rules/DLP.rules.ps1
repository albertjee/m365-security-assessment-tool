Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Rules {
    @(
        [PSCustomObject]@{
            ruleId          = 'DLP-DEP-001'
            appliesToAction = 'ACT-DLP-ENABLE-POLICY'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='AuditLoggingEnabled'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-AUDIT-ENABLE'; blockIfUnsatisfied=$true
                                  reason='DLP policy enforcement requires audit logging enabled to capture policy match events' }
            priority        = 2; category='DataGovernance'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'DLP-DEP-002'
            appliesToAction = 'ACT-DLP-ENABLE-POLICY'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='SensitivityLabelsDefined'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-LABEL-PUBLISH'; blockIfUnsatisfied=$false
                                  reason='DLP label-based conditions require sensitivity labels to be defined and published first' }
            priority        = 1; category='DataGovernance'; version='1.0.0'
        }
    )
}
