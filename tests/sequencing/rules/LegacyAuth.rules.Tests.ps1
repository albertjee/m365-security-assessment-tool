BeforeAll { . "$PSScriptRoot/../../../src/Private/sequencing/rules/LegacyAuth.rules.ps1" }

Describe 'LegacyAuth.rules — structure' {
    BeforeAll { $script:rules = Get-Rules }
    It 'returns non-empty array' { $script:rules.Count | Should -BeGreaterThan 0 }
    It 'contains LA-DEP-001' { $script:rules.ruleId | Should -Contain 'LA-DEP-001' }
    It 'contains LA-ADV-001' { $script:rules.ruleId | Should -Contain 'LA-ADV-001' }
    It 'LA-ADV-001 is type Advisory' {
        ($script:rules | Where-Object { $_.ruleId -eq 'LA-ADV-001' }).type | Should -Be 'Advisory'
    }
}
