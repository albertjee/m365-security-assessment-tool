BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-SharePointSharing.ps1"
    function Invoke-ExchangeRequest { param($CmdletName,$Parameters,$OperationType) throw 'stub' }
    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' } }
    function New-SecretGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Secret'; Connected=$true; RunId='run-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'returns id=SP-001' { (Get-CheckMetadata).id | Should -Be 'SP-001' }
    It 'returns dataSource=Exchange' { (Get-CheckMetadata).dataSource | Should -Be 'Exchange' }
}

Describe 'Invoke-Check — Secret auth returns NotAssessed' {
    It 'returns NotAssessed when AuthMethod=Secret' {
        $findings = Invoke-Check -GraphGateway (New-SecretGateway) -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
        $findings[0].evidence.reason | Should -Be 'ExchangeAuthNotSupported'
    }
}

Describe 'Invoke-Check — sharing settings' {
    It 'returns Fail when anonymous links allowed with no expiry' {
        Mock Invoke-ExchangeRequest {
            return [PSCustomObject]@{ SharingCapability='ExternalUserAndGuestSharing'; RequireAnonymousLinksExpireInDays=0 }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Fail'
        $findings[0].evidence.anonymousLinksAllowed | Should -BeTrue
    }

    It 'returns Pass when sharing disabled' {
        Mock Invoke-ExchangeRequest {
            return [PSCustomObject]@{ SharingCapability='Disabled'; RequireAnonymousLinksExpireInDays=0 }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Pass'
    }

    It 'returns NotAssessed when Exchange throws' {
        Mock Invoke-ExchangeRequest { throw 'SPO error' }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
    }
}
