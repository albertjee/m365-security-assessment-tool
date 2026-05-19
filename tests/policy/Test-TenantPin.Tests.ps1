BeforeAll { . "$PSScriptRoot/../../src/Private/policy/Test-TenantPin.ps1" }

Describe 'Test-TenantPin' {
    BeforeAll {
        $script:expectedTenantId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    }

    It 'returns Match=true when both signals match' {
        Mock Get-TenantIdFromToken { $script:expectedTenantId }
        Mock Get-TenantIdFromOrganization { $script:expectedTenantId }
        $result = Test-TenantPin -RequestedTenantId $script:expectedTenantId -GraphGateway @{}
        $result.Match | Should -BeTrue
        $result.MismatchReason | Should -BeNullOrEmpty
    }

    It 'Match=false and MismatchReason=TokenTenantMismatch when token tid differs' {
        Mock Get-TenantIdFromToken { 'wrong-id' }
        Mock Get-TenantIdFromOrganization { $script:expectedTenantId }
        $result = Test-TenantPin -RequestedTenantId $script:expectedTenantId -GraphGateway @{}
        $result.Match | Should -BeFalse
        $result.MismatchReason | Should -Be 'TokenTenantMismatch'
    }

    It 'Match=false and MismatchReason=OrganizationTenantMismatch when org endpoint differs' {
        Mock Get-TenantIdFromToken { $script:expectedTenantId }
        Mock Get-TenantIdFromOrganization { 'wrong-id' }
        $result = Test-TenantPin -RequestedTenantId $script:expectedTenantId -GraphGateway @{}
        $result.Match | Should -BeFalse
        $result.MismatchReason | Should -Be 'OrganizationTenantMismatch'
    }

    It 'Match=false and MismatchReason=RequestedTenantMissing when RequestedTenantId is empty' {
        $result = Test-TenantPin -RequestedTenantId '' -GraphGateway @{}
        $result.Match | Should -BeFalse
        $result.MismatchReason | Should -Be 'RequestedTenantMissing'
    }

    It 'Match=false and MismatchReason=UnableToResolveTenant when both signals fail' {
        Mock Get-TenantIdFromToken { throw 'token error' }
        Mock Get-TenantIdFromOrganization { throw 'org error' }
        $result = Test-TenantPin -RequestedTenantId $script:expectedTenantId -GraphGateway @{}
        $result.Match | Should -BeFalse
        $result.MismatchReason | Should -Be 'UnableToResolveTenant'
    }
}
