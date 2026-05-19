BeforeAll { . "$PSScriptRoot/../../../src/Private/sequencing/rules/PIM.rules.ps1" }

Describe 'PIM.rules — structure' {
    BeforeAll { $script:rules = Get-Rules }
    It 'returns non-empty array' { $script:rules.Count | Should -BeGreaterThan 0 }
    It 'contains PIM-DEP-001'  { $script:rules.ruleId | Should -Contain 'PIM-DEP-001' }
    It 'contains PIM-BLOCK-001' { $script:rules.ruleId | Should -Contain 'PIM-BLOCK-001' }
    It 'PIM-BLOCK-001 is type Block' {
        ($script:rules | Where-Object { $_.ruleId -eq 'PIM-BLOCK-001' }).type | Should -Be 'Block'
    }
}
