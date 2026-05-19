BeforeAll {
    . "$PSScriptRoot/../../../src/Private/sequencing/DependencyRulesEngine.ps1"
    . "$PSScriptRoot/../../../src/Private/sequencing/rules/DLP.rules.ps1"
    $script:rules = Get-Rules
}

Describe 'DLP.rules — DLP-DEP-001 (SensitivityLabels dependency)' {
    It 'has ruleId DLP-DEP-001' {
        $r = $script:rules | Where-Object { $_.ruleId -eq 'DLP-DEP-001' }
        $r | Should -Not -BeNullOrEmpty
    }

    It 'applies to ACT-DLP-DEPLOY-BASELINE' {
        $r = $script:rules | Where-Object { $_.ruleId -eq 'DLP-DEP-001' }
        $r.appliesToAction | Should -Be 'ACT-DLP-DEPLOY-BASELINE'
    }

    It 'type is Dependency' {
        $r = $script:rules | Where-Object { $_.ruleId -eq 'DLP-DEP-001' }
        $r.type | Should -Be 'Dependency'
    }

    It 'adds ACT-LABEL-PUBLISH dependency when SensitivityLabelsDefined=true' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-DLP-DEPLOY-BASELINE' }
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
            action   = [PSCustomObject]@{ actionId='ACT-DLP-DEPLOY-BASELINE' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:rules -Findings @()
        $result[0].result.status | Should -BeNullOrEmpty
    }
}

Describe 'DLP.rules — DLP-DEP-002 (AuditLogging dependency)' {
    It 'has ruleId DLP-DEP-002' {
        $r = $script:rules | Where-Object { $_.ruleId -eq 'DLP-DEP-002' }
        $r | Should -Not -BeNullOrEmpty
    }

    It 'blocks ACT-DLP-ENFORCE when AuditLoggingEnabled=false' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-DLP-ENFORCE' }
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
            action   = [PSCustomObject]@{ actionId='ACT-DLP-ENFORCE' }
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
