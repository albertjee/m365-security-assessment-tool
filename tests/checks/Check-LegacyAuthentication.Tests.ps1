BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-LegacyAuthentication.ps1"

    function Invoke-GraphRequest { throw 'Invoke-GraphRequest stub — must be mocked per test' }
    Remove-Alias -Name Invoke-GraphRequest -Force -ErrorAction SilentlyContinue

    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-test-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'id is LA-001' { (Get-CheckMetadata).id | Should -Be 'LA-001' }
    It 'severity is Critical' { (Get-CheckMetadata).severity | Should -Be 'Critical' }
    It 'passes Test-CheckContract' {
        . "$PSScriptRoot/../../src/Private/policy/Test-CheckContract.ps1"
        $result = Test-CheckContract -ModulePath "$PSScriptRoot/../../src/Private/checks/Check-LegacyAuthentication.ps1"
        $result.IsValid | Should -BeTrue -Because ($result.Violations -join '; ')
    }
}

Describe 'Invoke-Check — legacy auth enabled at tenant' {
    BeforeAll {
        $script:authPolicyBlocked  = [PSCustomObject]@{ blockLegacyAuthentication = $true }
        $script:authPolicyAllowed  = [PSCustomObject]@{ blockLegacyAuthentication = $false }
    }

    It 'returns Fail when blockLegacyAuthentication is false' {
        $gw = New-MockGateway
        $ap = $script:authPolicyAllowed
        Mock Invoke-GraphRequest {
            param($Uri)
            if ($Uri -match 'authorizationPolicy') {
                return [PSCustomObject]@{ Result = @{ value = @($ap) } }
            }
            return [PSCustomObject]@{ Result = @{ value = @() } }
        }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $f = $findings | Where-Object { $_.title -match 'Legacy' }
        $f.status | Should -Be 'Fail'
        $f.evidence.tenantLevelBlocked | Should -BeFalse
    }

    It 'returns Pass when blockLegacyAuthentication is true' {
        $gw = New-MockGateway
        $ap = $script:authPolicyBlocked
        Mock Invoke-GraphRequest {
            [PSCustomObject]@{ Result = @{ value = @($ap) } }
        }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $f = $findings | Where-Object { $_.title -match 'Legacy' }
        $f.status | Should -Be 'Pass'
    }
}

Describe 'Invoke-Check — CA coverage cross-check' {
    It 'returns Fail evidence when no CA policy blocks legacy auth' {
        $gw = New-MockGateway
        $ap = [PSCustomObject]@{ blockLegacyAuthentication = $false }
        Mock Invoke-GraphRequest {
            param($Uri)
            if ($Uri -match 'authorizationPolicy') { return [PSCustomObject]@{ Result = @{ value = @($ap) } } }
            if ($Uri -match 'conditionalAccess')   { return [PSCustomObject]@{ Result = @{ value = @() } } }
            return [PSCustomObject]@{ Result = @{ value = @() } }
        }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $f = $findings | Where-Object { $_.title -match 'Legacy' }
        $f.evidence.caBlockPolicyPresent | Should -BeFalse
    }
}

Describe 'Invoke-Check — error handling' {
    It 'returns NotAssessed when gateway throws' {
        $gw = New-MockGateway
        Mock Invoke-GraphRequest { throw 'auth error' }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
    }
}
