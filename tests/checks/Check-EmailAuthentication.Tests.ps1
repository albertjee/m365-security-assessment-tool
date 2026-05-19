BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-EmailAuthentication.ps1"
    function Invoke-GraphRequest { param($GraphGateway,$Uri,$Method,$OperationType,$Caller) throw 'stub' }
    Remove-Alias -Name Invoke-GraphRequest -Force -ErrorAction SilentlyContinue
    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' } }
    function New-SecretGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Secret'; Connected=$true; RunId='run-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'returns id=MAIL-001' { (Get-CheckMetadata).id | Should -Be 'MAIL-001' }
    It 'returns severity=High' { (Get-CheckMetadata).severity | Should -Be 'High' }
    It 'returns dataSource=Both' { (Get-CheckMetadata).dataSource | Should -Be 'Both' }
}

Describe 'Invoke-Check — Secret auth returns NotAssessed' {
    It 'returns NotAssessed with ExchangeAuthNotSupported when AuthMethod=Secret' {
        $findings = Invoke-Check -GraphGateway (New-SecretGateway) -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
        $findings[0].evidence.reason | Should -Be 'ExchangeAuthNotSupported'
    }
}

Describe 'Invoke-Check — domain assessment' {
    It 'returns Fail when domain has no email support' {
        Mock Invoke-GraphRequest {
            return [PSCustomObject]@{ Result=[PSCustomObject]@{ value=@(
                [PSCustomObject]@{ id='contoso.com'; isVerified=$true; isDefault=$true; supportedServices=@('OfficeCommunicationsOnline') }
            ) } }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Fail'
        $findings[0].checkId | Should -Be 'MAIL-001'
    }

    It 'returns NotAssessed when Graph throws' {
        Mock Invoke-GraphRequest { throw 'Graph error' }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
    }
}
