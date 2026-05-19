BeforeAll { . "$PSScriptRoot/../../src/Private/policy/Test-Environment.ps1" }

Describe 'Test-Environment' {
    It 'returns object with IsValid property' {
        $result = Test-Environment -AuthMethod 'Certificate' -RequireExchange $false
        $result.PSObject.Properties.Name | Should -Contain 'IsValid'
    }
    It 'IsValid=false when PS version below 7.2' {
        Mock Get-PSVersion { [Version]'7.1.0' }
        $result = Test-Environment -AuthMethod 'Certificate' -RequireExchange $false
        $result.IsValid | Should -BeFalse
        $result.Failures | Should -Contain 'PowerShell 7.2+ required'
    }
    It 'IsValid=false when ExchangeOnlineManagement missing and RequireExchange=true' {
        Mock Get-Module { $null } -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
        $result = Test-Environment -AuthMethod 'Certificate' -RequireExchange $true
        $result.IsValid | Should -BeFalse
        $result.Failures | Should -Contain 'ExchangeOnlineManagement module not found'
    }
}
