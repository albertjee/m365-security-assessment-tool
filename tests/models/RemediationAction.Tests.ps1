BeforeAll { . "$PSScriptRoot/../../src/Private/models/RemediationAction.schema.ps1" }

Describe 'New-RemediationAction' {
    BeforeAll {
        $script:base = @{
            RunId          = 'run-001'
            CheckId        = 'CA-001'
            CheckName      = 'Check-ConditionalAccess'
            FindingId      = 'FIND-CA-001-ABCD1234'
            ActionId       = 'ACT-CA-BLOCK-LEGACYAUTH'
            Operation      = 'POST'
            ResourceType   = 'ConditionalAccessPolicy'
            Target         = 'Block legacy authentication'
            Provider       = 'Graph'
            Endpoint       = '/identity/conditionalAccess/policies'
            HttpMethod     = 'POST'
            Phase          = 2
            Order          = 1
            Priority       = 1
            TenantIdMasked = 'aaaa-...-eeee'
        }
    }

    It 'returns object with schemaVersion 1.0' {
        $a = New-RemediationAction @script:base
        $a.schemaVersion | Should -Be '1.0'
    }

    It 'action.provider is set correctly' {
        $a = New-RemediationAction @script:base
        $a.action.provider | Should -Be 'Graph'
    }

    It 'throws if Provider is invalid' {
        { New-RemediationAction @script:base -Provider 'LDAP' } | Should -Throw
    }

    It 'result.status defaults to null (not yet executed)' {
        $a = New-RemediationAction @script:base
        $a.result.status | Should -BeNullOrEmpty
    }

    It 'execution.gates object present with all 4 keys' {
        $a = New-RemediationAction @script:base
        $a.execution.gates.PSObject.Properties.Name | Should -Contain 'modeRemediate'
        $a.execution.gates.PSObject.Properties.Name | Should -Contain 'delegatedAuth'
        $a.execution.gates.PSObject.Properties.Name | Should -Contain 'notWhatIf'
        $a.execution.gates.PSObject.Properties.Name | Should -Contain 'policyCheckPassed'
    }

    It 'request fields for Graph action have endpoint + method, cmdlet fields null' {
        $a = New-RemediationAction @script:base -Endpoint '/identity/conditionalAccess/policies' -HttpMethod 'POST'
        $a.request.endpoint   | Should -Be '/identity/conditionalAccess/policies'
        $a.request.method     | Should -Be 'POST'
        $a.request.cmdletName | Should -BeNullOrEmpty
    }

    It 'request fields for Exchange action have cmdletName, endpoint null' {
        $exchParams = @{
            RunId          = 'run-001'; CheckId = 'CA-001'; CheckName = 'Check-ConditionalAccess'
            FindingId      = 'FIND-CA-001-ABCD1234'; ActionId = 'ACT-CA-BLOCK-LEGACYAUTH'
            Operation      = 'POST'; ResourceType = 'ConditionalAccessPolicy'; Target = 'Block legacy auth'
            Provider       = 'Exchange'; CmdletName = 'Get-EXOMailbox'; WriteCmdletName = 'Set-CASMailbox'
            Phase = 2; Order = 1; Priority = 1; TenantIdMasked = 'aaaa-...-eeee'
        }
        $a = New-RemediationAction @exchParams
        $a.request.cmdletName      | Should -Be 'Get-EXOMailbox'
        $a.request.writeCmdletName | Should -Be 'Set-CASMailbox'
        $a.request.endpoint        | Should -BeNullOrEmpty
    }
}
