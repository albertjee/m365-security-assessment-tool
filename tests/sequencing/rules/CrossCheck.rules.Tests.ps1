BeforeAll {
    . "$PSScriptRoot/../../../src/Private/sequencing/DependencyRulesEngine.ps1"
    . "$PSScriptRoot/../../../src/Private/sequencing/rules/CA.rules.ps1"
    $script:caRules = Get-Rules
    . "$PSScriptRoot/../../../src/Private/sequencing/rules/CrossCheck.rules.ps1"
    $script:ccRules = Get-Rules
}

Describe 'CrossCheck.rules — structure' {
    It 'contains CC-001' { $script:ccRules.ruleId | Should -Contain 'CC-001' }
    It 'contains CC-002' { $script:ccRules.ruleId | Should -Contain 'CC-002' }
    It 'contains CC-003' { $script:ccRules.ruleId | Should -Contain 'CC-003' }
    It 'contains CC-004' { $script:ccRules.ruleId | Should -Contain 'CC-004' }
    It 'CC-001 is type Dependency' {
        ($script:ccRules | Where-Object { $_.ruleId -eq 'CC-001' }).type | Should -Be 'Dependency'
    }
    It 'CC-004 is type Block' {
        ($script:ccRules | Where-Object { $_.ruleId -eq 'CC-004' }).type | Should -Be 'Block'
    }
    It 'CC-003 appliesToAction ACT-DLP-ENFORCE' {
        ($script:ccRules | Where-Object { $_.ruleId -eq 'CC-003' }).appliesToAction | Should -Be 'ACT-DLP-ENFORCE'
    }
}

Describe 'CrossCheck.rules — CC-001 (MFA + PIM)' {
    It 'applies to ACT-CA-ENFORCE-MFA' {
        ($script:ccRules | Where-Object { $_.ruleId -eq 'CC-001' }).appliesToAction | Should -Be 'ACT-CA-ENFORCE-MFA'
    }

    It 'adds ACT-PIM-CONFIGURE-ROLE-SETTINGS dependency when PIMEnabled=true' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-CA-ENFORCE-MFA' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $findings = @(
            [PSCustomObject]@{ checkId='PIM-001'; status='Pass'; evidence=@{ pimEnabled=$true } }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:ccRules -Findings $findings
        $result[0].sequence.dependencies | Should -Contain 'ACT-PIM-CONFIGURE-ROLE-SETTINGS'
    }

    It 'does NOT block when PIMEnabled=false (blockIfUnsatisfied=false)' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-CA-ENFORCE-MFA' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:ccRules -Findings @()
        $result[0].result.status | Should -BeNullOrEmpty
    }
}

Describe 'CrossCheck.rules — CC-002 (Compliant Device + Compliance Policies)' {
    It 'applies to ACT-CA-REQUIRE-COMPLIANT-DEVICE' {
        ($script:ccRules | Where-Object { $_.ruleId -eq 'CC-002' }).appliesToAction | Should -Be 'ACT-CA-REQUIRE-COMPLIANT-DEVICE'
    }

    It 'blocks ACT-CA-REQUIRE-COMPLIANT-DEVICE when DeviceCompliancePoliciesExist=false' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-CA-REQUIRE-COMPLIANT-DEVICE' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $findings = @(
            [PSCustomObject]@{ checkId='DEV-001'; status='Fail'; evidence=@{ compliancePoliciesExist=$false } }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:ccRules -Findings $findings
        $result[0].result.status | Should -Be 'Blocked'
    }

    It 'adds ACT-DEV-BASELINE-COMPLIANCE dependency when DeviceCompliancePoliciesExist=true' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-CA-REQUIRE-COMPLIANT-DEVICE' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $findings = @(
            [PSCustomObject]@{ checkId='DEV-001'; status='Pass'; evidence=@{ compliancePoliciesExist=$true } }
        )
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:ccRules -Findings $findings
        $result[0].sequence.dependencies | Should -Contain 'ACT-DEV-BASELINE-COMPLIANCE'
    }
}

Describe 'CrossCheck.rules — CC-003 (DLP after identity baseline)' {
    It 'always adds ACT-CA-IDENTITY-BASELINE dependency for ACT-DLP-ENFORCE (fact=Always)' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-DLP-ENFORCE' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:ccRules -Findings @()
        $result[0].sequence.dependencies | Should -Contain 'ACT-CA-IDENTITY-BASELINE'
    }
}

Describe 'CrossCheck.rules — CC-004 (lockout protection for external block)' {
    It 'blocks ACT-CA-BLOCK-ALL-EXTERNAL always (fact=Always, type=Block)' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-CA-BLOCK-ALL-EXTERNAL' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:ccRules -Findings @()
        $result[0].result.status | Should -Be 'Blocked'
    }

    It 'block reason mentions lockout risk' {
        $action = [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId='ACT-CA-BLOCK-ALL-EXTERNAL' }
            sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
        $result = Invoke-DependencyRules -Actions @($action) -Rules $script:ccRules -Findings @()
        $result[0].result.reason | Should -Match 'lockout'
    }
}
