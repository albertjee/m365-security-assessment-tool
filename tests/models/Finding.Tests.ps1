BeforeAll { . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1" }

Describe 'New-Finding' {
    BeforeAll {
        $script:base = @{
            CheckId               = 'CA-001'
            RunId                 = 'run-001'
            Title                 = 'Legacy Auth Not Blocked'
            Category              = 'Identity Security'
            Severity              = 'Critical'
            RiskScore             = 95
            SecureScoreVisibility = 'Passes'
            Status                = 'Fail'
            GraphEndpoint         = '/identity/conditionalAccess/policies'
            SupportsRemediation   = $true
        }
    }

    It 'returns object with all required fields' {
        $f = New-Finding @script:base
        $f.id              | Should -Match '^FIND-'
        $f.checkId         | Should -Be 'CA-001'
        $f.runId           | Should -Be 'run-001'
        $f.severity        | Should -Be 'Critical'
        $f.riskScore       | Should -Be 95
        $f.status          | Should -Be 'Fail'
        $f.timestampUtc    | Should -Not -BeNullOrEmpty
        $f.evidence        | Should -Not -Be $null
    }

    It 'id is unique per call' {
        $f1 = New-Finding @script:base
        $f2 = New-Finding @script:base
        $f1.id | Should -Not -Be $f2.id
    }

    It 'throws if Severity invalid' {
        { New-Finding @script:base -Severity 'Unknown' } | Should -Throw
    }

    It 'throws if Status invalid' {
        { New-Finding @script:base -Status 'Maybe' } | Should -Throw
    }

    It 'throws if RiskScore out of range' {
        { New-Finding @script:base -RiskScore 101 } | Should -Throw
    }

    It 'evidence defaults to empty hashtable' {
        $f = New-Finding @script:base
        $f.evidence | Should -BeOfType [hashtable]
    }
}

Describe 'Assert-FindingValid' {
    It 'does not throw for a valid finding' {
        $f = New-Finding -CheckId 'CA-001' -RunId 'r1' -Title 't' -Category 'c' -Severity 'High' `
             -RiskScore 75 -SecureScoreVisibility 'NotFlagged' -Status 'Pass' -GraphEndpoint '/test' -SupportsRemediation $false
        { Assert-FindingValid -Finding $f } | Should -Not -Throw
    }

    It 'throws if required field missing' {
        $f = [PSCustomObject]@{ id = 'FIND-001' }
        { Assert-FindingValid -Finding $f } | Should -Throw
    }
}
