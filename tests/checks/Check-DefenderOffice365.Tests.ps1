BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-DefenderOffice365.ps1"
    function Invoke-ExchangeRequest { param($CmdletName,$Parameters,$OperationType) throw 'stub' }
    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' } }
    function New-SecretGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Secret'; Connected=$true; RunId='run-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'returns id=DEF-001' { (Get-CheckMetadata).id | Should -Be 'DEF-001' }
    It 'returns dataSource=Exchange' { (Get-CheckMetadata).dataSource | Should -Be 'Exchange' }
}

Describe 'Invoke-Check — Secret auth returns NotAssessed' {
    It 'returns NotAssessed when AuthMethod=Secret' {
        $findings = Invoke-Check -GraphGateway (New-SecretGateway) -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
        $findings[0].evidence.reason | Should -Be 'ExchangeAuthNotSupported'
    }
}

Describe 'Invoke-Check — defender policy assessment' {
    It 'returns Fail when only default preset and no Safe Links/Attachments' {
        Mock Invoke-ExchangeRequest {
            if ($CmdletName -eq 'Get-AntiPhishPolicy') { return @([PSCustomObject]@{ Identity='Default Preset Policy' }) }
            return @()
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Fail'
        $findings[0].evidence.antiPhishPreset | Should -Be 'Default'
    }

    It 'returns NotAssessed when Exchange throws' {
        Mock Invoke-ExchangeRequest { throw 'EXO error' }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
    }
}
