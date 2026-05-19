BeforeAll {
    . "$PSScriptRoot/../src/Private/models/RemediationAction.schema.ps1"
    . "$PSScriptRoot/../src/Private/Remediator.ps1"

    function Invoke-GraphRequest { param($Uri, $Method, $Body, $OperationType) throw 'Invoke-GraphRequest stub — must be mocked per test' }
    Remove-Alias -Name Invoke-GraphRequest -Force -ErrorAction SilentlyContinue
    function Invoke-ExchangeRequest { param($CmdletName, $Parameters, $OperationType) throw 'Invoke-ExchangeRequest stub — must be mocked per test' }

    function New-MockGraphGateway {
        [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Delegated'; Connected=$true; RunId='run-001' }
    }

    function New-MockExchangeGateway {
        [PSCustomObject]@{ PSTypeName='Metis.ExchangeGateway'; AuthMethod='Delegated'; Connected=$true; RunId='run-001' }
    }

    function New-GraphAction {
        param([string]$Id = 'ACT-A', [string]$Endpoint = '/policies/test', [string]$Method = 'PATCH')
        [PSCustomObject]@{
            action   = [PSCustomObject]@{
                actionId     = $Id
                provider     = 'Graph'
                operation    = 'PATCH'
                resourceType = 'policy'
                resourceId   = 'r1'
                target       = 'tenant'
            }
            sequence = [PSCustomObject]@{
                phase        = 2
                order        = 1
                dependencies = @()
                conflictsWith= @()
                priority     = 1
                safetyLevel  = 'High'
                category     = 'Identity'
            }
            result      = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied= @()
            request     = [PSCustomObject]@{ endpoint=$Endpoint; method=$Method; body=@{}; bodyHash=$null; headers=@{} }
            check       = [PSCustomObject]@{ checkId='CA-001'; checkName='CA'; findingId='FIND-001' }
            runContext  = [PSCustomObject]@{ runId='run-001'; timestampUtc='2026-01-01T00:00:00Z' }
            tenant      = [PSCustomObject]@{ tenantIdMasked='****-001' }
        }
    }

    function New-ExchangeAction {
        param([string]$Id = 'ACT-EX')
        $a = New-GraphAction -Id $Id
        $a.action.provider  = 'Exchange'
        $a.request = [PSCustomObject]@{ cmdletName='Get-Mailbox'; parameters=@{}; writeCmdletName='Set-Mailbox'; writeParameters=@{} }
        return $a
    }
}

Describe 'Invoke-Remediator — Graph provider' {
    It 'calls Invoke-GraphRequest with correct endpoint and method' {
        Mock Invoke-GraphRequest { [PSCustomObject]@{ id='result-001' } }

        $action = New-GraphAction
        Invoke-Remediator -Action $action -GraphGateway (New-MockGraphGateway)

        Should -Invoke Invoke-GraphRequest -Times 1 -ParameterFilter {
            $Uri -eq '/policies/test' -and $Method -eq 'PATCH'
        }
    }

    It 'returns object with status=Success when Graph call succeeds' {
        Mock Invoke-GraphRequest { [PSCustomObject]@{ id='result-001' } }

        $action = New-GraphAction
        $result = Invoke-Remediator -Action $action -GraphGateway (New-MockGraphGateway)
        $result.status | Should -Be 'Success'
    }

    It 'returns status=Failed when Graph call throws' {
        Mock Invoke-GraphRequest { throw 'Graph API error 500' }

        $action = New-GraphAction
        $result = Invoke-Remediator -Action $action -GraphGateway (New-MockGraphGateway)
        $result.status | Should -Be 'Failed'
        $result.error  | Should -Match 'Graph API error'
    }
}

Describe 'Invoke-Remediator — Exchange provider' {
    It 'calls Invoke-ExchangeRequest with write cmdlet' {
        Mock Invoke-ExchangeRequest { [PSCustomObject]@{ Success=$true } }

        $action = New-ExchangeAction
        Invoke-Remediator -Action $action -GraphGateway (New-MockGraphGateway) -ExchangeGateway (New-MockExchangeGateway)

        Should -Invoke Invoke-ExchangeRequest -Times 1
    }

    It 'returns status=Failed when ExchangeGateway is null for Exchange action' {
        $action = New-ExchangeAction
        $result = Invoke-Remediator -Action $action -GraphGateway (New-MockGraphGateway) -ExchangeGateway $null
        $result.status | Should -Be 'Failed'
        $result.error  | Should -Match 'ExchangeGateway'
    }
}

Describe 'Invoke-Remediator — result structure' {
    It 'result includes durationMs' {
        Mock Invoke-GraphRequest { [PSCustomObject]@{ id='r1' } }

        $action = New-GraphAction
        $result = Invoke-Remediator -Action $action -GraphGateway (New-MockGraphGateway)
        $result.durationMs | Should -BeGreaterOrEqual 0
    }

    It 'result includes actionId' {
        Mock Invoke-GraphRequest { [PSCustomObject]@{ id='r1' } }

        $action = New-GraphAction -Id 'ACT-TEST-123'
        $result = Invoke-Remediator -Action $action -GraphGateway (New-MockGraphGateway)
        $result.actionId | Should -Be 'ACT-TEST-123'
    }
}
