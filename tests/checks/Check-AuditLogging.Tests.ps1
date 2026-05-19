BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-AuditLogging.ps1"
    function Invoke-ExchangeRequest { param($CmdletName,$Parameters,$OperationType) throw 'stub' }
    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' } }
    function New-SecretGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Secret'; Connected=$true; RunId='run-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'returns id=AUDIT-001' { (Get-CheckMetadata).id | Should -Be 'AUDIT-001' }
    It 'returns severity=Medium' { (Get-CheckMetadata).severity | Should -Be 'Medium' }
    It 'returns dataSource=Exchange' { (Get-CheckMetadata).dataSource | Should -Be 'Exchange' }
}

Describe 'Invoke-Check — Secret auth returns NotAssessed' {
    It 'returns NotAssessed with ExchangeAuthNotSupported when AuthMethod=Secret' {
        $findings = Invoke-Check -GraphGateway (New-SecretGateway) -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
        $findings[0].evidence.reason | Should -Be 'ExchangeAuthNotSupported'
    }
}

Describe 'Invoke-Check — audit logging enabled' {
    It 'returns Pass when UnifiedAuditLogIngestionEnabled=true' {
        Mock Invoke-ExchangeRequest {
            return [PSCustomObject]@{ UnifiedAuditLogIngestionEnabled=$true }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Pass'
        $findings[0].evidence.auditLoggingEnabled | Should -BeTrue
    }

    It 'returns Fail when UnifiedAuditLogIngestionEnabled=false' {
        Mock Invoke-ExchangeRequest {
            return [PSCustomObject]@{ UnifiedAuditLogIngestionEnabled=$false }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Fail'
    }

    It 'returns NotAssessed when Exchange throws' {
        Mock Invoke-ExchangeRequest { throw 'EXO error' }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
    }
}
