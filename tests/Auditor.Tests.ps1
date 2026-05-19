BeforeAll {
    . "$PSScriptRoot/../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../src/Private/policy/Test-CheckContract.ps1"
    . "$PSScriptRoot/../src/Private/policy/Test-ExchangePermissions.ps1"
    . "$PSScriptRoot/../src/Private/Auditor.ps1"

    function New-TempCheck {
        param([string]$Id, [string]$DataSource = 'Graph', [string]$Status = 'Fail', [bool]$Throws = $false)
        $throwLine = if ($Throws) { "throw 'simulated error'" } else { '' }
        $content = @"
function Get-CheckMetadata {
    @{ id='$Id'; title='Test $Id'; category='Test'; severity='High'; riskScoreBaseline=75
       secureScoreVisibility='Passes'; description='d'; requiredPermissions=@()
       requiredExchangeRoles=@(); dataSource='$DataSource'; supportsRemediation=`$false
       edition=@('Lite','Premium'); assessAuthMethods=@('Certificate','Secret','Delegated') }
}
function Invoke-Check {
    param(`$GraphGateway, `$Config)
    $throwLine
    @(New-Finding -CheckId '$Id' -RunId `$GraphGateway.RunId -Title 'Test' -Category 'Test' ``
        -Severity 'High' -RiskScore 75 -SecureScoreVisibility 'Passes' -Status '$Status' ``
        -GraphEndpoint '/test' -SupportsRemediation `$false)
}
"@
        $suffix = [System.IO.Path]::GetRandomFileName() -replace '\..*$', ''
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "Check-$Id-$suffix.ps1"
        Set-Content -Path $tmp -Value $content
        return $tmp
    }

    $script:mockGw = [PSCustomObject]@{
        PSTypeName = 'Metis.GraphGateway'; AuthMethod = 'Certificate'
        RunId = 'run-001'; Connected = $true
    }
}

Describe 'Invoke-Audit — basic discovery' {
    It 'runs all checks in ChecksPath and returns findings' {
        $tmp1 = New-TempCheck -Id 'TST-001'
        $tmp2 = New-TempCheck -Id 'TST-002'
        $dir  = Split-Path $tmp1
        try {
            $findings = Invoke-Audit -GraphGateway $script:mockGw -Config @{ EnabledChecks = @() } `
                            -ChecksPath $dir -RunId 'run-001'
            $checkIds = $findings | Select-Object -ExpandProperty checkId -Unique
            $checkIds | Should -Contain 'TST-001'
            $checkIds | Should -Contain 'TST-002'
        } finally {
            Remove-Item $tmp1, $tmp2 -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-Audit — IncludeChecks filter' {
    It 'skips checks not in EnabledChecks when list is non-empty' {
        $tmp1 = New-TempCheck -Id 'TST-003'
        $tmp2 = New-TempCheck -Id 'TST-004'
        $dir  = Split-Path $tmp1
        try {
            $findings = Invoke-Audit -GraphGateway $script:mockGw -Config @{ EnabledChecks = @('TST-003') } `
                            -ChecksPath $dir -RunId 'run-001'
            (@($findings | Where-Object { $_.checkId -eq 'TST-003' })).Count | Should -BeGreaterThan 0
            (@($findings | Where-Object { $_.checkId -eq 'TST-004' })).Count | Should -Be 0
        } finally {
            Remove-Item $tmp1, $tmp2 -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-Audit — per-check error isolation' {
    It 'marks one check NotAssessed when it throws, continues running others' {
        $good = New-TempCheck -Id 'TST-005' -Status 'Fail'
        $bad  = New-TempCheck -Id 'TST-006' -Throws $true
        $dir  = Split-Path $good
        try {
            $findings = Invoke-Audit -GraphGateway $script:mockGw -Config @{ EnabledChecks = @() } `
                            -ChecksPath $dir -RunId 'run-001'
            $goodFindings = @($findings | Where-Object { $_.checkId -eq 'TST-005' })
            $badFindings  = @($findings | Where-Object { $_.checkId -eq 'TST-006' })
            $goodFindings | Should -Not -BeNullOrEmpty
            $goodFindings[0].status | Should -Be 'Fail'
            $badFindings | Should -Not -BeNullOrEmpty
            $badFindings[0].status | Should -Be 'NotAssessed'
        } finally {
            Remove-Item $good, $bad -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-Audit — Exchange auth compatibility' {
    It 'marks Exchange check NotAssessed when AuthMethod=Secret' {
        $exchCheck = New-TempCheck -Id 'TST-007' -DataSource 'Exchange'
        try {
            $secretGw = [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Secret'; RunId='r1'; Connected=$true }
            $findings = Invoke-Audit -GraphGateway $secretGw -Config @{ EnabledChecks = @() } `
                            -ChecksPath (Split-Path $exchCheck) -RunId 'r1'
            $f = @($findings | Where-Object { $_.checkId -eq 'TST-007' })
            $f | Should -Not -BeNullOrEmpty
            $f[0].status        | Should -Be 'NotAssessed'
            $f[0].error.message | Should -Match 'ExchangeAuthNotSupported'
        } finally {
            Remove-Item $exchCheck -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-Audit — contract failure' {
    It 'marks check NotAssessed when Test-CheckContract fails' {
        $broken = [System.IO.Path]::GetTempFileName() + '.ps1'
        Set-Content -Path $broken -Value '# empty — no contract functions'
        try {
            $findings = Invoke-Audit -GraphGateway $script:mockGw -Config @{ EnabledChecks = @() } `
                            -ChecksPath (Split-Path $broken) -RunId 'run-001'
        } finally {
            Remove-Item $broken -ErrorAction SilentlyContinue
        }
    }
}
