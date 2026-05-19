BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-DLP.ps1"
    function Invoke-GraphRequest { param($GraphGateway,$Uri,$Method,$OperationType,$Caller) throw 'stub' }
    Remove-Alias -Name Invoke-GraphRequest -Force -ErrorAction SilentlyContinue
    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' } }
    function New-SecretGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Secret'; Connected=$true; RunId='run-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'returns id=DLP-001' { (Get-CheckMetadata).id | Should -Be 'DLP-001' }
    It 'returns dataSource=Both' { (Get-CheckMetadata).dataSource | Should -Be 'Both' }
}

Describe 'Invoke-Check — Secret auth returns NotAssessed' {
    It 'returns NotAssessed when AuthMethod=Secret' {
        $findings = Invoke-Check -GraphGateway (New-SecretGateway) -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
    }
}

Describe 'Invoke-Check — DLP policy detection' {
    It 'returns Fail when no policies' {
        Mock Invoke-GraphRequest { return [PSCustomObject]@{ Result=[PSCustomObject]@{ value=@() } } }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Fail'
        $findings[0].evidence.dlpPoliciesPresent | Should -BeFalse
    }

    It 'checkId is DLP-001' {
        Mock Invoke-GraphRequest { return [PSCustomObject]@{ Result=[PSCustomObject]@{ value=@() } } }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].checkId | Should -Be 'DLP-001'
    }
}
