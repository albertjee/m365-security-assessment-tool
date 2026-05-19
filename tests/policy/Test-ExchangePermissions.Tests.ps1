BeforeAll { . "$PSScriptRoot/../../src/Private/policy/Test-ExchangePermissions.ps1" }

Describe 'Test-ExchangePermissions' {
    It 'returns IsValid=true when all required Exchange roles present' {
        $result = Test-ExchangePermissions -RequiredRoles @('View-Only Configuration') -GrantedRoles @('View-Only Configuration','Compliance Management')
        $result.IsValid | Should -BeTrue
        $result.Missing | Should -BeNullOrEmpty
    }
    It 'returns IsValid=false with Missing list when role absent' {
        $result = Test-ExchangePermissions -RequiredRoles @('Compliance Management') -GrantedRoles @('View-Only Configuration')
        $result.IsValid | Should -BeFalse
        $result.Missing | Should -Contain 'Compliance Management'
    }
    It 'returns IsValid=true when RequiredRoles is empty' {
        $result = Test-ExchangePermissions -RequiredRoles @() -GrantedRoles @()
        $result.IsValid | Should -BeTrue
    }
}
