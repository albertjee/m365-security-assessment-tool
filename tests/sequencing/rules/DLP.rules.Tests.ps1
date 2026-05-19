BeforeAll {
    . "$PSScriptRoot/../../../src/Private/sequencing/DependencyRulesEngine.ps1"
    . "$PSScriptRoot/../../../src/Private/sequencing/rules/DLP.rules.ps1"
    $script:rules = Get-Rules
}

Describe 'DLP.rules — DLP-DEP-001 (AuditLogging dependency)' {
    It 'has ruleId DLP-DEP-001' {
        $r = $script:rules | Where-Object { $_.ruleId -eq 'DLP-DEP-001' }
        $r | Should -Not -BeNullOrEmpty
    }

    It 'applies to ACT-DLP-ENABLE-POLICY' {
        $r = $script:rules | Where-Object { $_.ruleId -eq 'DLP-DEP-001' }
        $r.appliesToAction | Should -Be 'ACT-DLP-ENABLE-POLICY'
    }

    It 'fact is AuditLoggingEnabled' {
        $r = $script:rules | Where-Object { $_.ruleId -eq 'DLP-DEP-001' }
        $r.condition.fact | Should -Be 'AuditLoggingEnabled'
    }

    It 'type is Dependency' {
        $r = $script:rules | Where-Object { $_.ruleId -eq 'DLP-DEP-001' }
        $r.type | Should -Be 'Dependency'
    }

    It 'blocks ACT-DLP-ENABLE-POLICY when AuditLoggingEnabled=false (blockIfUnsatisfied=true)' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-DLP-ENABLE-POLICY' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $findings = @(
            [PSCustomObject]@{ checkId='AUDIT-001'; status='Fail'; evidence=@{ auditLoggingEnabled=$false } }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:rules -Findings $findings
        $result[0].result.status | Should -Be 'Blocked'
    }

    It 'adds ACT-AUDIT-ENABLE dependency when AuditLoggingEnabled=true' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-DLP-ENABLE-POLICY' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $findings = @(
            [PSCustomObject]@{ checkId='AUDIT-001'; status='Pass'; evidence=@{ auditLoggingEnabled=$true } }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:rules -Findings $findings
        $result[0].sequence.dependencies | Should -Contain 'ACT-AUDIT-ENABLE'
    }
}

Describe 'DLP.rules — DLP-DEP-002 (SensitivityLabels dependency)' {
    It 'has ruleId DLP-DEP-002' {
        $r = $script:rules | Where-Object { $_.ruleId -eq 'DLP-DEP-002' }
        $r | Should -Not -BeNullOrEmpty
    }

    It 'applies to ACT-DLP-ENABLE-POLICY' {
        $r = $script:rules | Where-Object { $_.ruleId -eq 'DLP-DEP-002' }
        $r.appliesToAction | Should -Be 'ACT-DLP-ENABLE-POLICY'
    }

    It 'fact is SensitivityLabelsDefined' {
        $r = $script:rules | Where-Object { $_.ruleId -eq 'DLP-DEP-002' }
        $r.condition.fact | Should -Be 'SensitivityLabelsDefined'
    }

    It 'adds ACT-LABEL-PUBLISH dependency when SensitivityLabelsDefined=true' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-DLP-ENABLE-POLICY' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $findings = @(
            [PSCustomObject]@{ checkId='LABEL-001'; status='Pass'; evidence=@{ labelsDefined=$true } }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:rules -Findings $findings
        $result[0].sequence.dependencies | Should -Contain 'ACT-LABEL-PUBLISH'
    }

    It 'does NOT block when SensitivityLabelsDefined=false (blockIfUnsatisfied=false)' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-DLP-ENABLE-POLICY' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        # Audit must be enabled so DEP-001 does not block; only testing DEP-002 behaviour here
        $findings = @(
            [PSCustomObject]@{ checkId='AUDIT-001'; status='Pass'; evidence=@{ auditLoggingEnabled=$true } }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:rules -Findings $findings
        $result[0].result.status | Should -BeNullOrEmpty
    }
}
