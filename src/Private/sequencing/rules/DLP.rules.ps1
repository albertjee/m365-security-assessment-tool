Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Rules {
    @(
        [PSCustomObject]@{
            ruleId          = 'DLP-DEP-001'
            appliesToAction = 'ACT-DLP-DEPLOY-BASELINE'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='SensitivityLabelsDefined'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-LABEL-PUBLISH'; blockIfUnsatisfied=$false; reason='Sensitivity labels should be defined before deploying DLP policies to enable label-based conditions' }
            priority        = 2; category='DataProtection'; version='1.0.0'
        }
        [PSCustomObject]@{
            ruleId          = 'DLP-DEP-002'
            appliesToAction = 'ACT-DLP-ENFORCE'
            type            = 'Dependency'
            condition       = [PSCustomObject]@{ fact='AuditLoggingEnabled'; operator='Equals'; value=$true }
            effect          = [PSCustomObject]@{ dependency='ACT-AUDIT-ENABLE'; blockIfUnsatisfied=$true; reason='Audit logging must be enabled before DLP enforcement to capture policy match events' }
            priority        = 3; category='DataProtection'; version='1.0.0'
        }
    )
}
