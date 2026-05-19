BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-DeviceCompliance.ps1"
    function Invoke-GraphRequest { param($GraphGateway,$Uri,$Method,$OperationType,$Caller) throw 'stub' }
    Remove-Alias -Name Invoke-GraphRequest -Force -ErrorAction SilentlyContinue
    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'returns id=DEV-001' { (Get-CheckMetadata).id | Should -Be 'DEV-001' }
    It 'returns severity=High' { (Get-CheckMetadata).severity | Should -Be 'High' }
}

Describe 'Invoke-Check — policies present' {
    It 'returns Pass when compliance policies exist' {
        Mock Invoke-GraphRequest {
            return [PSCustomObject]@{ Result=[PSCustomObject]@{ value=@(
                [PSCustomObject]@{ id='policy-001'; displayName='Windows Compliance' }
            ) } }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Pass'
        $findings[0].evidence.compliancePoliciesExist | Should -BeTrue
    }

    It 'returns Fail when no compliance policies' {
        Mock Invoke-GraphRequest { return [PSCustomObject]@{ Result=[PSCustomObject]@{ value=@() } } }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Fail'
    }

    It 'returns NotAssessed when Graph throws' {
        Mock Invoke-GraphRequest { throw 'Forbidden 403' }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
    }
}
