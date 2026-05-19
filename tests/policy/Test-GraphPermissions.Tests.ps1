BeforeAll { . "$PSScriptRoot/../../src/Private/policy/Test-GraphPermissions.ps1" }

Describe 'Test-GraphPermissions' {
    It 'returns IsValid=true when all required permissions present in granted scopes' {
        $result = Test-GraphPermissions -RequiredPermissions @('Policy.Read.All') -GrantedScopes @('Policy.Read.All','Directory.Read.All')
        $result.IsValid | Should -BeTrue
        $result.Missing | Should -BeNullOrEmpty
    }
    It 'returns IsValid=false with Missing list when permission absent' {
        $result = Test-GraphPermissions -RequiredPermissions @('Policy.Read.All','RoleManagement.Read.Directory') -GrantedScopes @('Policy.Read.All')
        $result.IsValid | Should -BeFalse
        $result.Missing | Should -Contain 'RoleManagement.Read.Directory'
    }
    It 'returns IsValid=true when RequiredPermissions is empty' {
        $result = Test-GraphPermissions -RequiredPermissions @() -GrantedScopes @()
        $result.IsValid | Should -BeTrue
    }
    It 'comparison is case-insensitive' {
        $result = Test-GraphPermissions -RequiredPermissions @('policy.read.all') -GrantedScopes @('Policy.Read.All')
        $result.IsValid | Should -BeTrue
    }
}
