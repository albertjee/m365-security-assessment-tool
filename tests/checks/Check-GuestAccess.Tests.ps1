BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-GuestAccess.ps1"
    function Invoke-GraphRequest { param($GraphGateway,$Uri,$Method,$OperationType,$Caller) throw 'stub' }
    Remove-Alias -Name Invoke-GraphRequest -Force -ErrorAction SilentlyContinue
    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'returns id=GUEST-001' { (Get-CheckMetadata).id | Should -Be 'GUEST-001' }
    It 'returns severity=High'  { (Get-CheckMetadata).severity | Should -Be 'High' }
    It 'returns dataSource=Graph' { (Get-CheckMetadata).dataSource | Should -Be 'Graph' }
}

Describe 'Invoke-Check — guest invite too permissive' {
    It 'returns Fail when allowInvitesFrom=everyone' {
        Mock Invoke-GraphRequest {
            if ($Uri -match 'authorizationPolicy') {
                return [PSCustomObject]@{ Result=[PSCustomObject]@{ allowInvitesFrom='everyone'; id='authzPolicy' } }
            }
            return [PSCustomObject]@{ Result=[PSCustomObject]@{ value=@() } }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Fail'
    }

    It 'returns Pass when allowInvitesFrom=none and no stale guests' {
        Mock Invoke-GraphRequest {
            if ($Uri -match 'authorizationPolicy') {
                return [PSCustomObject]@{ Result=[PSCustomObject]@{ allowInvitesFrom='none'; id='authzPolicy' } }
            }
            return [PSCustomObject]@{ Result=[PSCustomObject]@{ value=@() } }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'Pass'
    }
}

Describe 'Invoke-Check — NotAssessed on error' {
    It 'returns NotAssessed when Graph throws' {
        Mock Invoke-GraphRequest { throw 'Graph error 500' }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
    }
}
