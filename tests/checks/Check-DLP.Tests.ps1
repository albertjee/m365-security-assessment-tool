BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-DLP.ps1"
    function Invoke-ExchangeRequest { param($ExchangeGateway, $CmdletName, $Parameters, $OperationType, $Caller) throw 'Invoke-ExchangeRequest stub — must be mocked per test' }
    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' } }
    function New-SecretGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Secret'; Connected=$true; RunId='run-001' } }
    function New-MockConfig {
        $exGw = [PSCustomObject]@{ PSTypeName='Metis.ExchangeGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' }
        @{ ExchangeGateway = $exGw }
    }
}

Describe 'Get-CheckMetadata' {
    It 'returns id=DLP-001'         { (Get-CheckMetadata).id         | Should -Be 'DLP-001' }
    It 'returns dataSource=Exchange' { (Get-CheckMetadata).dataSource | Should -Be 'Exchange' }
    It 'returns severity=High'       { (Get-CheckMetadata).severity   | Should -Be 'High' }
}

Describe 'Invoke-Check — Secret auth returns NotAssessed' {
    It 'returns NotAssessed when AuthMethod=Secret' {
        $findings = Invoke-Check -GraphGateway (New-SecretGateway) -Config (New-MockConfig)
        $findings[0].status | Should -Be 'NotAssessed'
    }
}

Describe 'Invoke-Check — no policies found' {
    It 'returns Fail for absent-policies finding when no policies' {
        Mock Invoke-ExchangeRequest {
            [PSCustomObject]@{ Result = @() }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config (New-MockConfig)
        $f = $findings | Where-Object { $_.title -match 'No DLP' }
        $f.status | Should -Be 'Fail'
        $f.evidence.dlpPoliciesPresent | Should -BeFalse
    }

    It 'checkId is DLP-001' {
        Mock Invoke-ExchangeRequest {
            [PSCustomObject]@{ Result = @() }
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config (New-MockConfig)
        $findings[0].checkId | Should -Be 'DLP-001'
    }
}

Describe 'Invoke-Check — simulation mode detection' {
    It 'returns Fail for simulation-mode finding when all policies in AuditAndNotify' {
        Mock Invoke-ExchangeRequest {
            [PSCustomObject]@{ Result = @(
                [PSCustomObject]@{ Name='DLP-Audit'; Mode='AuditAndNotify'; Workload='Exchange,SharePoint,Teams' }
            )}
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config (New-MockConfig)
        $simFinding = $findings | Where-Object { $_.title -match 'Simulation' }
        $simFinding.status | Should -Be 'Fail'
    }

    It 'returns Pass for simulation-mode finding when at least one policy is Enable' {
        Mock Invoke-ExchangeRequest {
            [PSCustomObject]@{ Result = @(
                [PSCustomObject]@{ Name='DLP-Enforced'; Mode='Enable'; Workload='Exchange,SharePoint,Teams' }
            )}
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config (New-MockConfig)
        $simFinding = $findings | Where-Object { $_.title -match 'Simulation' }
        $simFinding.status | Should -Be 'Pass'
    }
}

Describe 'Invoke-Check — workload coverage' {
    It 'returns Fail for coverage finding when Teams workload missing' {
        Mock Invoke-ExchangeRequest {
            [PSCustomObject]@{ Result = @(
                [PSCustomObject]@{ Name='DLP-Only-Exchange'; Mode='Enable'; Workload='Exchange,SharePoint' }
            )}
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config (New-MockConfig)
        $covFinding = $findings | Where-Object { $_.title -match 'Coverage' }
        $covFinding.status | Should -Be 'Fail'
        $covFinding.evidence.missingWorkloads | Should -Contain 'Teams'
    }

    It 'returns Pass for coverage finding when all three workloads covered' {
        Mock Invoke-ExchangeRequest {
            [PSCustomObject]@{ Result = @(
                [PSCustomObject]@{ Name='DLP-Full'; Mode='Enable'; Workload='Exchange,SharePoint,Teams' }
            )}
        }
        $findings = Invoke-Check -GraphGateway (New-MockGateway) -Config (New-MockConfig)
        $covFinding = $findings | Where-Object { $_.title -match 'Coverage' }
        $covFinding.status | Should -Be 'Pass'
    }
}
