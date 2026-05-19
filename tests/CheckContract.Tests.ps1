BeforeAll { . "$PSScriptRoot/../src/Private/policy/Test-CheckContract.ps1" }

Describe 'Test-CheckContract — valid module' {
    BeforeAll {
        $validModule = @'
function Get-CheckMetadata {
    @{
        id='CA-001'; title='Test'; category='Identity'; severity='Critical'
        riskScoreBaseline=90; secureScoreVisibility='Passes'; description='desc'
        requiredPermissions=@('Policy.Read.All'); requiredExchangeRoles=@()
        dataSource='Graph'; supportsRemediation=$false
        edition=@('Lite','Premium'); assessAuthMethods=@('Certificate','Secret','Delegated')
    }
}
function Invoke-Check { param($GraphGateway,$Config) @() }
'@
        $script:tmpValid = [System.IO.Path]::GetTempFileName() + '.ps1'
        Set-Content -Path $script:tmpValid -Value $validModule
    }
    AfterAll { Remove-Item $script:tmpValid -ErrorAction SilentlyContinue }

    It 'returns IsValid=true for a compliant module' {
        $result = Test-CheckContract -ModulePath $script:tmpValid
        $result.IsValid | Should -BeTrue -Because ($result.Violations -join '; ')
        $result.Violations | Should -BeNullOrEmpty
    }
}

Describe 'Test-CheckContract — missing Get-CheckMetadata' {
    BeforeAll {
        $bad = "function Invoke-Check { param(`$GraphGateway,`$Config) @() }"
        $script:tmpBad1 = [System.IO.Path]::GetTempFileName() + '.ps1'
        Set-Content -Path $script:tmpBad1 -Value $bad
    }
    AfterAll { Remove-Item $script:tmpBad1 -ErrorAction SilentlyContinue }

    It 'IsValid=false with violation for missing Get-CheckMetadata' {
        $result = Test-CheckContract -ModulePath $script:tmpBad1
        $result.IsValid | Should -BeFalse
        $result.Violations | Should -Contain 'Get-CheckMetadata function not found'
    }
}

Describe 'Test-CheckContract — write call detected' {
    BeforeAll {
        $bad = @'
function Get-CheckMetadata { @{ id='X-001';title='t';category='c';severity='High';riskScoreBaseline=70;secureScoreVisibility='Passes';description='d';requiredPermissions=@();requiredExchangeRoles=@();dataSource='Graph';supportsRemediation=$false;edition=@('Lite');assessAuthMethods=@('Certificate') } }
function Invoke-Check { param($GraphGateway,$Config) Invoke-GraphRequest -Method POST -OperationType Write; @() }
'@
        $script:tmpBad2 = [System.IO.Path]::GetTempFileName() + '.ps1'
        Set-Content -Path $script:tmpBad2 -Value $bad
    }
    AfterAll { Remove-Item $script:tmpBad2 -ErrorAction SilentlyContinue }

    It 'IsValid=false when Invoke-Check contains write call' {
        $result = Test-CheckContract -ModulePath $script:tmpBad2
        $result.IsValid | Should -BeFalse
        $result.Violations | Should -Match 'write.*Invoke-Check'
    }
}

Describe 'Test-CheckContract — generic cmdlet write call detected' {
    BeforeAll {
        $badSet = @'
function Get-CheckMetadata { @{ id='X-001';title='t';category='c';severity='High';riskScoreBaseline=70;secureScoreVisibility='Passes';description='d';requiredPermissions=@();requiredExchangeRoles=@();dataSource='Graph';supportsRemediation=$false;edition=@('Lite');assessAuthMethods=@('Certificate') } }
function Invoke-Check { param($GraphGateway,$Config) Set-CustomCompliancePolicy -Id 'foo'; @() }
'@
        $badNew = @'
function Get-CheckMetadata { @{ id='X-002';title='t';category='c';severity='High';riskScoreBaseline=70;secureScoreVisibility='Passes';description='d';requiredPermissions=@();requiredExchangeRoles=@();dataSource='Graph';supportsRemediation=$false;edition=@('Lite');assessAuthMethods=@('Certificate') } }
function Invoke-Check { param($GraphGateway,$Config) New-MgUser -DisplayName 'bad'; @() }
'@
        $script:tmpBad4 = [System.IO.Path]::GetTempFileName() + '.ps1'
        $script:tmpBad5 = [System.IO.Path]::GetTempFileName() + '.ps1'
        Set-Content -Path $script:tmpBad4 -Value $badSet
        Set-Content -Path $script:tmpBad5 -Value $badNew
    }
    AfterAll {
        Remove-Item $script:tmpBad4 -ErrorAction SilentlyContinue
        Remove-Item $script:tmpBad5 -ErrorAction SilentlyContinue
    }

    It 'IsValid=false when Invoke-Check calls a generic Set-* cmdlet' {
        $result = Test-CheckContract -ModulePath $script:tmpBad4
        $result.IsValid | Should -BeFalse
        $result.Violations | Should -Match 'write.*Invoke-Check'
    }

    It 'IsValid=false when Invoke-Check calls a generic New-* (non-Finding) cmdlet' {
        $result = Test-CheckContract -ModulePath $script:tmpBad5
        $result.IsValid | Should -BeFalse
        $result.Violations | Should -Match 'write.*Invoke-Check'
    }

    It 'IsValid=true when Invoke-Check calls only New-Finding (not a write operation)' {
        $onlyNewFinding = @'
function Get-CheckMetadata { @{ id='NF-001';title='t';category='c';severity='High';riskScoreBaseline=70;secureScoreVisibility='Passes';description='d';requiredPermissions=@();requiredExchangeRoles=@();dataSource='Graph';supportsRemediation=$false;edition=@('Lite');assessAuthMethods=@('Certificate') } }
function Invoke-Check { param($GraphGateway,$Config) @(New-Finding -CheckId 'NF-001' -RunId 'r1' -Title 't' -Category 'c' -Severity 'High' -RiskScore 70 -SecureScoreVisibility 'Passes' -Status 'Pass' -GraphEndpoint '/test' -SupportsRemediation $false) }
'@
        $tmpNF = [System.IO.Path]::GetTempFileName() + '.ps1'
        Set-Content -Path $tmpNF -Value $onlyNewFinding
        try {
            $result = Test-CheckContract -ModulePath $tmpNF
            $result.IsValid | Should -BeTrue -Because 'New-Finding is an internal result builder, not a write call'
        } finally {
            Remove-Item $tmpNF -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Test-CheckContract — missing required metadata fields' {
    BeforeAll {
        $bad = "function Get-CheckMetadata { @{ id='CA-001' } }`nfunction Invoke-Check { param(`$GraphGateway,`$Config) @() }"
        $script:tmpBad3 = [System.IO.Path]::GetTempFileName() + '.ps1'
        Set-Content -Path $script:tmpBad3 -Value $bad
    }
    AfterAll { Remove-Item $script:tmpBad3 -ErrorAction SilentlyContinue }

    It 'IsValid=false with violations for each missing metadata field' {
        $result = Test-CheckContract -ModulePath $script:tmpBad3
        $result.IsValid | Should -BeFalse
        @($result.Violations | Where-Object { $_ -match 'metadata' }).Count | Should -BeGreaterThan 0
    }
}
