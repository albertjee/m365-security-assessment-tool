BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-SmtpAuth.ps1"
    function Invoke-ExchangeRequest { param($CmdletName,$Parameters,$OperationType) throw 'stub' }
    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' } }
    function New-SecretGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Secret'; Connected=$true; RunId='run-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'returns id=SMTP-001' { (Get-CheckMetadata).id | Should -Be 'SMTP-001' }
    It 'returns dataSource=Exchange' { (Get-CheckMetadata).dataSource | Should -Be 'Exchange' }
}

Describe 'Invoke-Check — Secret auth returns NotAssessed' {
    It 'returns NotAssessed when AuthMethod=Secret' {
        $findings = Invoke-Check -GraphGateway (New-SecretGateway) -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
        $findings[0].evidence.reason | Should -Be 'ExchangeAuthNotSupported'
    }
}

Describe 'Invoke-Check — SMTP AUTH state' {
    It 'returns Pass when SmtpClientAuthenticationDisabled=true' {
        Mock Invoke-ExchangeRequest {
            return [PSCustomObject]@{ SmtpClientAuthenticationDisabled=$true }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Pass'
        $findings[0].evidence.smtpAuthEnabled | Should -BeFalse
    }

    It 'returns Fail when SmtpClientAuthenticationDisabled=false' {
        Mock Invoke-ExchangeRequest {
            return [PSCustomObject]@{ SmtpClientAuthenticationDisabled=$false }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Fail'
        $findings[0].evidence.smtpAuthEnabled | Should -BeTrue
    }
}
