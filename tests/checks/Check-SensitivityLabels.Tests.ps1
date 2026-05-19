BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-SensitivityLabels.ps1"
    function Invoke-GraphRequest { param($GraphGateway,$Uri,$Method,$OperationType,$Caller) throw 'stub' }
    Remove-Alias -Name Invoke-GraphRequest -Force -ErrorAction SilentlyContinue
    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'returns id=LABEL-001' { (Get-CheckMetadata).id | Should -Be 'LABEL-001' }
    It 'returns dataSource=Graph' { (Get-CheckMetadata).dataSource | Should -Be 'Graph' }
}

Describe 'Invoke-Check — labels defined and published' {
    It 'returns Pass when labels defined and active' {
        Mock Invoke-GraphRequest {
            return [PSCustomObject]@{ Result=[PSCustomObject]@{ value=@(
                [PSCustomObject]@{ id='lbl-001'; name='Confidential'; isActive=$true }
            ) } }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Pass'
        $findings[0].evidence.labelsDefined | Should -BeTrue
        $findings[0].evidence.labelsPublished | Should -BeTrue
    }

    It 'returns Fail when no labels defined' {
        Mock Invoke-GraphRequest { return [PSCustomObject]@{ Result=[PSCustomObject]@{ value=@() } } }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Fail'
    }

    It 'returns Fail when labels defined but not published (isActive=false)' {
        Mock Invoke-GraphRequest {
            return [PSCustomObject]@{ Result=[PSCustomObject]@{ value=@(
                [PSCustomObject]@{ id='lbl-001'; name='Confidential'; isActive=$false }
            ) } }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Fail'
        $findings[0].evidence.labelsDefined   | Should -BeTrue
        $findings[0].evidence.labelsPublished | Should -BeFalse
    }
}
