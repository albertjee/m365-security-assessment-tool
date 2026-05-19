BeforeAll { . "$PSScriptRoot/../../../src/Private/sequencing/rules/CA.rules.ps1" }

Describe 'CA.rules — structure' {
    BeforeAll { $script:rules = Get-Rules }

    It 'returns non-empty array' {
        $script:rules.Count | Should -BeGreaterThan 0
    }

    It 'each rule has required fields' {
        foreach ($r in $script:rules) {
            $r.ruleId             | Should -Not -BeNullOrEmpty
            $r.appliesToAction    | Should -Not -BeNullOrEmpty
            $r.type               | Should -BeIn @('Dependency','Block','Conflict','Advisory')
            $r.condition.fact     | Should -Not -BeNullOrEmpty
            $r.condition.operator | Should -Not -BeNullOrEmpty
            $r.priority           | Should -BeGreaterThan 0
            $r.version            | Should -Be '1.0.0'
        }
    }

    It 'contains CA-DEP-001'      { $script:rules.ruleId | Should -Contain 'CA-DEP-001' }
    It 'contains CA-BLOCK-001'    { $script:rules.ruleId | Should -Contain 'CA-BLOCK-001' }
    It 'contains CA-DEP-002'      { $script:rules.ruleId | Should -Contain 'CA-DEP-002' }
    It 'contains CA-CONFLICT-001' { $script:rules.ruleId | Should -Contain 'CA-CONFLICT-001' }

    It 'CA-BLOCK-001 is type Block' {
        ($script:rules | Where-Object { $_.ruleId -eq 'CA-BLOCK-001' }).type | Should -Be 'Block'
    }

    It 'CA-DEP-001 effect has dependency field' {
        $r = $script:rules | Where-Object { $_.ruleId -eq 'CA-DEP-001' }
        $r.effect.dependency | Should -Not -BeNullOrEmpty
    }
}
