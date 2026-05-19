BeforeAll {
    . "$PSScriptRoot/../../src/Private/sequencing/rules/CA.rules.ps1"
    . "$PSScriptRoot/../../src/Private/sequencing/DependencyRulesEngine.ps1"

    function New-TestAction {
        param([string]$Id)
        [PSCustomObject]@{
            action       = [PSCustomObject]@{ actionId=$Id }
            sequence     = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result       = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
    }

    $script:caBlockFalseFindings = @(
        [PSCustomObject]@{
            checkId='CA-001'; status='Fail'
            evidence=@{ breakGlassFound=$false; legacyAuthPolicyFound=$false }
        }
    )
    $script:caBlockTrueFindings = @(
        [PSCustomObject]@{
            checkId='CA-001'; status='Fail'
            evidence=@{ breakGlassFound=$true; legacyAuthPolicyFound=$false }
        }
    )
}

Describe 'Get-FactValue' {
    It 'returns false for BreakGlassAccountsPresent when evidence shows breakGlassFound=false' {
        Get-FactValue -FactName 'BreakGlassAccountsPresent' -Findings $script:caBlockFalseFindings | Should -BeFalse
    }
    It 'returns true for BreakGlassAccountsPresent when evidence shows breakGlassFound=true' {
        Get-FactValue -FactName 'BreakGlassAccountsPresent' -Findings $script:caBlockTrueFindings | Should -BeTrue
    }
    It 'returns false for unknown fact (UNSATISFIED rule)' {
        Get-FactValue -FactName 'SomeMadeUpFact' -Findings @() | Should -BeFalse
    }
    It 'returns true for Always fact' {
        Get-FactValue -FactName 'Always' -Findings @() | Should -BeTrue
    }
}

Describe 'Test-RuleCondition' {
    It 'returns true when fact matches Equals condition' {
        $cond = [PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
        Test-RuleCondition -Condition $cond -Findings @() | Should -BeTrue
    }
    It 'returns false when fact does not match Equals condition' {
        $cond = [PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$true }
        Test-RuleCondition -Condition $cond -Findings $script:caBlockFalseFindings | Should -BeFalse
    }
}

Describe 'Invoke-DependencyRules — Block rule' {
    It 'marks action Blocked when Block condition satisfied' {
        $action = New-TestAction 'ACT-CA-ENABLE-MFA'
        $rules  = @(
            [PSCustomObject]@{
                ruleId='CA-BLOCK-001'; appliesToAction='ACT-CA-ENABLE-MFA'; type='Block'; priority=10
                condition=[PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$false }
                effect=[PSCustomObject]@{ blockIfUnsatisfied=$true; reason='No break-glass' }
            }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $rules -Findings $script:caBlockFalseFindings
        $result[0].result.status | Should -Be 'Blocked'
        $result[0].rulesApplied.ruleId | Should -Contain 'CA-BLOCK-001'
    }

    It 'does NOT block action when Block condition is not satisfied' {
        $action = New-TestAction 'ACT-CA-ENABLE-MFA'
        $rules  = @(
            [PSCustomObject]@{
                ruleId='CA-BLOCK-001'; appliesToAction='ACT-CA-ENABLE-MFA'; type='Block'; priority=10
                condition=[PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$false }
                effect=[PSCustomObject]@{ blockIfUnsatisfied=$true; reason='No break-glass' }
            }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $rules -Findings $script:caBlockTrueFindings
        $result[0].result.status | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-DependencyRules — Dependency rule' {
    It 'adds dependency to action when Dependency condition satisfied' {
        $action = New-TestAction 'ACT-CA-ENABLE-MFA'
        $rules  = @(
            [PSCustomObject]@{
                ruleId='CA-DEP-001'; appliesToAction='ACT-CA-ENABLE-MFA'; type='Dependency'; priority=1
                condition=[PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$true }
                effect=[PSCustomObject]@{ dependency='ACT-CA-EXCLUDE-BREAKGLASS'; blockIfUnsatisfied=$false; reason='dep' }
            }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $rules -Findings $script:caBlockTrueFindings
        $result[0].sequence.dependencies | Should -Contain 'ACT-CA-EXCLUDE-BREAKGLASS'
    }
}

Describe 'Invoke-DependencyRules — rule precedence' {
    It 'Block outcome wins over Dependency for same action' {
        $action = New-TestAction 'ACT-CA-ENABLE-MFA'
        $rules  = @(
            [PSCustomObject]@{
                ruleId='CA-DEP-X'; appliesToAction='ACT-CA-ENABLE-MFA'; type='Dependency'; priority=1
                condition=[PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
                effect=[PSCustomObject]@{ dependency='ACT-SOME-DEP'; blockIfUnsatisfied=$false; reason='dep' }
            }
            [PSCustomObject]@{
                ruleId='CA-BLOCK-X'; appliesToAction='ACT-CA-ENABLE-MFA'; type='Block'; priority=10
                condition=[PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
                effect=[PSCustomObject]@{ blockIfUnsatisfied=$true; reason='blocked' }
            }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $rules -Findings @()
        $result[0].result.status | Should -Be 'Blocked'
    }
}

Describe 'Get-FactValue — PIM facts resolve from PIM-001 evidence' {
    It 'PIMConversionComplete returns true when pimConversionComplete=true in PIM-001 evidence' {
        $findings = @(
            [PSCustomObject]@{ checkId='PIM-001'; status='Pass'; evidence=@{ pimConversionComplete=$true } }
        )
        Get-FactValue -FactName 'PIMConversionComplete' -Findings $findings | Should -BeTrue
    }

    It 'PIMConversionComplete returns false when pimConversionComplete=false in PIM-001 evidence' {
        $findings = @(
            [PSCustomObject]@{ checkId='PIM-001'; status='Pass'; evidence=@{ pimConversionComplete=$false } }
        )
        Get-FactValue -FactName 'PIMConversionComplete' -Findings $findings | Should -BeFalse
    }

    It 'ApprovalWorkflowConfigured returns true when approvalWorkflowConfigured=true in PIM-001 evidence' {
        $findings = @(
            [PSCustomObject]@{ checkId='PIM-001'; status='Pass'; evidence=@{ approvalWorkflowConfigured=$true } }
        )
        Get-FactValue -FactName 'ApprovalWorkflowConfigured' -Findings $findings | Should -BeTrue
    }

    It 'ApprovalWorkflowConfigured returns false when approvalWorkflowConfigured=false in PIM-001 evidence' {
        $findings = @(
            [PSCustomObject]@{ checkId='PIM-001'; status='Pass'; evidence=@{ approvalWorkflowConfigured=$false } }
        )
        Get-FactValue -FactName 'ApprovalWorkflowConfigured' -Findings $findings | Should -BeFalse
    }

    It 'PIMConversionComplete returns false when PIM-001 finding absent' {
        Get-FactValue -FactName 'PIMConversionComplete' -Findings @() | Should -BeFalse
    }

    It 'ApprovalWorkflowConfigured returns false when PIM-001 finding absent' {
        Get-FactValue -FactName 'ApprovalWorkflowConfigured' -Findings @() | Should -BeFalse
    }
}

Describe 'Test-EvidenceContract' {
    It 'returns IsValid=true when present finding has all required evidence keys' {
        $findings = @(
            [PSCustomObject]@{ checkId='CA-001'; status='Pass'; evidence=@{ breakGlassFound=$true; totalPolicies=5 } }
        )
        $result = Test-EvidenceContract -Findings $findings
        $result.IsValid           | Should -BeTrue
        $result.Violations.Count  | Should -Be 0
    }

    It 'returns violation when a non-NotAssessed finding is missing a required evidence key' {
        $findings = @(
            [PSCustomObject]@{ checkId='CA-001'; status='Fail'; evidence=@{ totalPolicies=0 } }
        )
        $result = Test-EvidenceContract -Findings $findings
        $result.IsValid | Should -BeFalse
        ($result.Violations | Where-Object { $_.factName -eq 'BreakGlassAccountsPresent' }) |
            Should -Not -BeNullOrEmpty
    }

    It 'does not flag NotAssessed findings even when evidence keys are absent' {
        $findings = @(
            [PSCustomObject]@{ checkId='CA-001'; status='NotAssessed'; evidence=@{} }
        )
        $result = Test-EvidenceContract -Findings $findings
        $result.IsValid          | Should -BeTrue
        $result.Violations.Count | Should -Be 0
    }
}

Describe 'Invoke-DependencyRules — unknown fact defaults false' {
    It 'Block condition with unknown fact = false -> condition NOT satisfied -> not blocked' {
        $action = New-TestAction 'ACT-TEST'
        $rules  = @(
            [PSCustomObject]@{
                ruleId='TST-BLOCK-001'; appliesToAction='ACT-TEST'; type='Block'; priority=5
                condition=[PSCustomObject]@{ fact='NonExistentFact'; operator='Equals'; value=$true }
                effect=[PSCustomObject]@{ blockIfUnsatisfied=$true; reason='test' }
            }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $rules -Findings @()
        $result[0].result.status | Should -BeNullOrEmpty
    }
}
