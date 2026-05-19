BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-ConditionalAccess.ps1"

    function Invoke-GraphRequest { throw 'Invoke-GraphRequest stub — must be mocked per test' }
    Remove-Alias -Name Invoke-GraphRequest -Force -ErrorAction SilentlyContinue

    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-test-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'returns id CA-001' { (Get-CheckMetadata).id | Should -Be 'CA-001' }
    It 'severity is Critical' { (Get-CheckMetadata).severity | Should -Be 'Critical' }
    It 'dataSource is Graph' { (Get-CheckMetadata).dataSource | Should -Be 'Graph' }
    It 'has requiredPermissions' { (Get-CheckMetadata).requiredPermissions | Should -Contain 'Policy.Read.All' }
    It 'passes Test-CheckContract' {
        . "$PSScriptRoot/../../src/Private/policy/Test-CheckContract.ps1"
        $result = Test-CheckContract -ModulePath "$PSScriptRoot/../../src/Private/checks/Check-ConditionalAccess.ps1"
        $result.IsValid | Should -BeTrue -Because ($result.Violations -join '; ')
    }
}

Describe 'Invoke-Check — legacy auth finding' {
    BeforeAll {
        $script:blockPolicy = [PSCustomObject]@{
            id    = 'pol-001'
            state = 'enabled'
            displayName = 'Block Legacy Auth'
            conditions = [PSCustomObject]@{
                clientAppTypes = @('exchangeActiveSync','other')
                users = [PSCustomObject]@{ includeUsers = @('All'); excludeUsers = @(); excludeGroups = @() }
            }
            grantControls = [PSCustomObject]@{ operator = 'OR'; builtInControls = @('block') }
        }
    }

    It 'returns Fail finding when no legacy auth block policy exists' {
        $gw = New-MockGateway
        Mock Invoke-GraphRequest {
            [PSCustomObject]@{ Result = @{ value = @() } }
        }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $legacyFinding = $findings | Where-Object { $_.checkId -eq 'CA-001' -and $_.title -match 'Legacy' }
        $legacyFinding | Should -Not -BeNullOrEmpty
        $legacyFinding.status   | Should -Be 'Fail'
        $legacyFinding.severity | Should -Be 'Critical'
    }

    It 'returns Pass finding when enabled legacy auth block policy exists' {
        $gw = New-MockGateway
        $bp = $script:blockPolicy
        Mock Invoke-GraphRequest {
            [PSCustomObject]@{ Result = @{ value = @($bp) } }
        }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $legacyFinding = $findings | Where-Object { $_.title -match 'Legacy' }
        $legacyFinding.status | Should -Be 'Pass'
    }
}

Describe 'Invoke-Check — report-only policies' {
    It 'returns Fail when legacy auth policy is report-only (not enforced)' {
        $gw = New-MockGateway
        $reportOnly = [PSCustomObject]@{
            id    = 'pol-002'
            state = 'enabledForReportingButNotEnforced'
            displayName = 'Block Legacy Auth'
            conditions = [PSCustomObject]@{
                clientAppTypes = @('exchangeActiveSync','other')
                users = [PSCustomObject]@{ includeUsers = @('All'); excludeUsers = @(); excludeGroups = @() }
            }
            grantControls = [PSCustomObject]@{ operator = 'OR'; builtInControls = @('block') }
        }
        Mock Invoke-GraphRequest {
            [PSCustomObject]@{ Result = @{ value = @($reportOnly) } }
        }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $legacyFinding = $findings | Where-Object { $_.title -match 'Legacy' }
        $legacyFinding.status | Should -Be 'Fail'
        $legacyFinding.evidence.reportOnlyFound | Should -BeTrue
    }
}

Describe 'Invoke-Check — MFA finding' {
    It 'returns Fail when no MFA policy covers all users' {
        $gw = New-MockGateway
        Mock Invoke-GraphRequest { [PSCustomObject]@{ Result = @{ value = @() } } }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $mfaFinding = $findings | Where-Object { $_.title -match 'MFA' }
        $mfaFinding.status | Should -Be 'Fail'
    }
}

Describe 'Invoke-Check — error handling' {
    It 'returns NotAssessed finding when GraphGateway throws' {
        $gw = New-MockGateway
        Mock Invoke-GraphRequest { throw 'Gateway error' }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $findings | Should -Not -BeNullOrEmpty
        $findings[0].status | Should -Be 'NotAssessed'
    }
}
