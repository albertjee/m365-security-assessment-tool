BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-CloudAppSecurity.ps1"
    function Invoke-GraphRequest { param($GraphGateway,$Uri,$Method,$OperationType,$Caller) throw 'stub' }
    Remove-Alias -Name Invoke-GraphRequest -Force -ErrorAction SilentlyContinue
    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'returns id=CASB-001' { (Get-CheckMetadata).id | Should -Be 'CASB-001' }
    It 'returns severity=Medium' { (Get-CheckMetadata).severity | Should -Be 'Medium' }
}

Describe 'Invoke-Check — CASB license detection' {
    It 'returns Pass when MCAS SKU present' {
        Mock Invoke-GraphRequest {
            return [PSCustomObject]@{ Result=[PSCustomObject]@{ value=@(
                [PSCustomObject]@{ skuPartNumber='MCAS'; skuId='abc-001' }
            ) } }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Pass'
        $findings[0].evidence.casbLicensed | Should -BeTrue
    }

    It 'returns Fail when no CASB SKU' {
        Mock Invoke-GraphRequest {
            return [PSCustomObject]@{ Result=[PSCustomObject]@{ value=@(
                [PSCustomObject]@{ skuPartNumber='EXO_P1'; skuId='xyz-002' }
            ) } }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Fail'
    }
}
