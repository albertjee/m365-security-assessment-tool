BeforeAll {
    . "$PSScriptRoot/../../../src/Private/sequencing/DependencyRulesEngine.ps1"
    . "$PSScriptRoot/../../../src/Private/sequencing/rules/CA.rules.ps1"
    $script:caRules = Get-Rules
    . "$PSScriptRoot/../../../src/Private/sequencing/rules/CrossCheck.rules.ps1"
    $script:ccRules = Get-Rules
}

Describe 'CrossCheck.rules — CC-001 (CA+PIM)' {
    It 'has ruleId CC-001 applying to ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE' {
        $r = $script:ccRules | Where-Object { $_.ruleId -eq 'CC-001' }
        $r.appliesToAction | Should -Be 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE'
    }

    It 'adds ACT-CA-BASELINE dependency when CAFrameworkPresent=true' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $findings = @(
            [PSCustomObject]@{ checkId='CA-001'; status='Pass'; evidence=@{ totalPolicies=3 } }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:ccRules -Findings $findings
        $result[0].sequence.dependencies | Should -Contain 'ACT-CA-BASELINE'
    }
}

Describe 'CrossCheck.rules — CC-004 (lockout protection)' {
    It 'blocks ACT-CA-ENABLE-MFA when BreakGlassAccountsPresent=false (highest priority=15)' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-CA-ENABLE-MFA' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $findings = @(
            [PSCustomObject]@{ checkId='CA-001'; status='Fail'; evidence=@{ breakGlassFound=$false; totalPolicies=0 } }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:ccRules -Findings $findings
        $result[0].result.status | Should -Be 'Blocked'
    }

    It 'does NOT block ACT-CA-ENABLE-MFA when BreakGlassAccountsPresent=true' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-CA-ENABLE-MFA' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $findings = @(
            [PSCustomObject]@{ checkId='CA-001'; status='Pass'; evidence=@{ breakGlassFound=$true; totalPolicies=2 } }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:ccRules -Findings $findings
        $result[0].result.status | Should -BeNullOrEmpty
    }
}

Describe 'CrossCheck.rules — CC-002, CC-003' {
    It 'CC-002 adds ACT-CA-BASELINE dependency for ACT-DEV-ENFORCE-COMPLIANCE when CA present' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-DEV-ENFORCE-COMPLIANCE' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $findings = @(
            [PSCustomObject]@{ checkId='CA-001'; status='Pass'; evidence=@{ totalPolicies=4 } }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:ccRules -Findings $findings
        $result[0].sequence.dependencies | Should -Contain 'ACT-CA-BASELINE'
    }

    It 'CC-003 adds ACT-CA-BASELINE dependency for ACT-DLP-ENFORCE when CA present' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-DLP-ENFORCE' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $findings = @(
            [PSCustomObject]@{ checkId='CA-001'; status='Pass'; evidence=@{ totalPolicies=2 } }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:ccRules -Findings $findings
        $result[0].sequence.dependencies | Should -Contain 'ACT-CA-BASELINE'
    }
}
