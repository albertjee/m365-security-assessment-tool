BeforeAll { . "$PSScriptRoot/../../src/Private/policy/Test-TenantPin.ps1" }

Describe 'Get-TenantIdFromToken' {
    It 'returns correct tid from a base64url-encoded JWT payload' {
        $expectedTid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $json    = "{`"tid`":`"$expectedTid`"}"
        $bytes   = [System.Text.Encoding]::UTF8.GetBytes($json)
        $b64     = [Convert]::ToBase64String($bytes)
        $b64url  = $b64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
        $fakeJwt = "hdr.$b64url.sig"
        $gw = [PSCustomObject]@{ AccessToken = $fakeJwt }
        Get-TenantIdFromToken -GraphGateway $gw | Should -Be $expectedTid
    }

    It 'normalises - and _ in base64url payload before decoding' {
        # {"tid":">>>"} encodes to standard base64 eyJ0aWQiOiI+Pj4ifQ==
        # The + at index 12 becomes - in base64url; the function must restore it
        $fakeJwt = 'hdr.eyJ0aWQiOiI-Pj4ifQ.sig'
        $gw = [PSCustomObject]@{ AccessToken = $fakeJwt }
        Get-TenantIdFromToken -GraphGateway $gw | Should -Be '>>>'
    }

    It 'throws when GraphGateway has no access token' {
        $gw = [PSCustomObject]@{ AccessToken = $null }
        { Get-TenantIdFromToken -GraphGateway $gw } | Should -Throw '*No access token*'
    }
}

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
