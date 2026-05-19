BeforeAll {
    # --- Gateway stubs ---
    function New-GraphGateway {
        param($TenantId, $AppId, $AuthMethod, $RunId, $RunFolder,
              $CertificateThumbprint, $Certificate, $CertificateFilePath,
              $CertificatePassword, $ClientSecret, $UserPrincipalName)
        [PSCustomObject]@{
            PSTypeName  = 'Metis.GraphGateway'
            TenantId    = $TenantId
            AppId       = $AppId
            AuthMethod  = $AuthMethod
            Connected   = $false
            AccessToken = $null
            RunId       = $RunId
            RunFolder   = $RunFolder
        }
    }
    function Connect-GraphGateway {
        param($GraphGateway)
        $GraphGateway.Connected = $true
        return $GraphGateway
    }
    function Disconnect-GraphGateway { param($GraphGateway) }

    function New-ExchangeGateway {
        param($TenantId, $AppId, $AuthMethod, $Organization, $RunId, $RunFolder,
              $CertificateThumbprint, $Certificate, $CertificateFilePath,
              $CertificatePassword, $UserPrincipalName, $ShowBanner)
        [PSCustomObject]@{ PSTypeName='Metis.ExchangeGateway'; Connected=$false }
    }
    function Connect-ExchangeGateway    { param($ExchangeGateway) return $ExchangeGateway }
    function Disconnect-ExchangeGateway { param($ExchangeGateway) }

    # --- Policy stubs ---
    function Test-Environment {
        param($AuthMethod, $RequireExchange)
        [PSCustomObject]@{ IsValid=$true; Failures=@() }
    }
    function Test-TenantPin {
        param($RequestedTenantId, $GraphGateway)
        [PSCustomObject]@{ Match=$true; MismatchReason='' }
    }
    function Get-MgContext { [PSCustomObject]@{ Scopes = @() } }
    function Test-GraphPermissions {
        param($RequiredPermissions, $GrantedScopes)
        [PSCustomObject]@{ IsValid=$true; Missing=@() }
    }

    # --- Audit / sequencing stubs ---
    function Invoke-Audit {
        param($GraphGateway, $ExchangeGateway, $Config, $ChecksPath, $RunId)
        return @()
    }
    function Write-FindingsJson {
        param($Findings, $OutputFolder)
        return (Join-Path $OutputFolder 'findings.json')
    }
    function Write-RunManifest {
        param($Manifest, $OutputFolder, [switch]$ComputeArtifactHashes)
        return (Join-Path $OutputFolder 'run.manifest.json')
    }
    function Write-HtmlReport {
        param($Findings, $Metadata, $OutputFolder)
        return (Join-Path $OutputFolder 'report.html')
    }
    function Write-SequencePlanJson {
        param($SequencePlan, $OutputFolder)
        return (Join-Path $OutputFolder 'sequence-plan.json')
    }
    function Get-AllRules            { param($RulesPath) return @() }
    function Invoke-DependencyRules  { param($Actions, $Rules, $Findings) return $Actions }
    function New-SequencePlan {
        param($Actions, $RulesVersion)
        return [PSCustomObject]@{ planHash='abc'; rulesVersion=$RulesVersion; phases=@(); summary=@{} }
    }
    function Invoke-Executor {
        param($Plan, $Actions, $Context, $GraphGateway, $Findings, $TenantId)
        return @()
    }

    . "$PSScriptRoot/../Start-Assessment.ps1"
}

Describe 'Start-AssessmentPipeline — Assess mode' {
    It 'returns result object with RunId and Status=Complete' {
        $params = @{
            Mode          = 'Assess'
            AuthMethod    = 'Certificate'
            TenantId      = 'tenant-test-001'
            AppId         = 'app-test-001'
            Edition       = 'Lite'
            IncludeChecks = @()
            OutputPath    = [System.IO.Path]::GetTempPath()
            WhatIf        = $false
            Force         = $false
        }
        $result = Start-AssessmentPipeline -Params $params
        $result.RunId  | Should -Not -BeNullOrEmpty
        $result.Status | Should -Be 'Complete'
    }

    It 'creates output folder at OutputFolder' {
        $tmpBase = [System.IO.Path]::GetTempPath()
        $params  = @{
            Mode          = 'Assess'
            AuthMethod    = 'Certificate'
            TenantId      = 'tenant-test-002'
            AppId         = 'app-test-002'
            Edition       = 'Lite'
            IncludeChecks = @()
            OutputPath    = $tmpBase
            WhatIf        = $false
            Force         = $false
        }
        $result = Start-AssessmentPipeline -Params $params
        Test-Path $result.OutputFolder | Should -BeTrue
    }

    It 'calls Invoke-Audit once' {
        Mock Invoke-Audit { return @() }

        $params = @{
            Mode          = 'Assess'
            AuthMethod    = 'Certificate'
            TenantId      = 'tenant-audit'
            AppId         = 'app-audit'
            Edition       = 'Lite'
            IncludeChecks = @()
            OutputPath    = [System.IO.Path]::GetTempPath()
            WhatIf        = $false
            Force         = $false
        }
        Start-AssessmentPipeline -Params $params

        Should -Invoke Invoke-Audit -Times 1
    }
}

Describe 'Start-AssessmentPipeline — WhatIf does not invoke Executor' {
    It 'does not call Invoke-Executor when WhatIf=true and Edition=Lite' {
        Mock Invoke-Executor { throw 'should not be called' }
        Mock Invoke-Audit    { return @() }

        $params = @{
            Mode          = 'Remediate'
            AuthMethod    = 'Delegated'
            TenantId      = 'tenant-whatif'
            AppId         = 'app-whatif'
            Edition       = 'Lite'
            IncludeChecks = @()
            OutputPath    = [System.IO.Path]::GetTempPath()
            WhatIf        = $true
            Force         = $false
        }
        { Start-AssessmentPipeline -Params $params } | Should -Not -Throw
        Should -Invoke Invoke-Executor -Times 0
    }
}
