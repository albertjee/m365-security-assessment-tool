BeforeAll {
    . "$PSScriptRoot/../src/Private/ExchangeGateway.ps1"
}

Describe 'New-ExchangeGateway' {
    It 'returns PSTypeName Metis.ExchangeGateway' {
        $gw = New-ExchangeGateway -TenantId 't' -AppId 'a' -AuthMethod 'Certificate' -Organization 'c.onmicrosoft.com' -RunId 'r1' -RunFolder 'C:\tmp'
        $gw.PSObject.TypeNames[0] | Should -Be 'Metis.ExchangeGateway'
    }
    It 'Connected starts false' {
        $gw = New-ExchangeGateway -TenantId 't' -AppId 'a' -AuthMethod 'Certificate' -Organization 'c.onmicrosoft.com' -RunId 'r1' -RunFolder 'C:\tmp'
        $gw.Connected | Should -BeFalse
    }
}

Describe 'Connect-ExchangeGateway — Secret auth' {
    It 'throws immediately for Secret AuthMethod' {
        $gw = New-ExchangeGateway -TenantId 't' -AppId 'a' -AuthMethod 'Secret' -Organization 'c.onmicrosoft.com' -RunId 'r1' -RunFolder 'C:\tmp'
        { Connect-ExchangeGateway -ExchangeGateway $gw } | Should -Throw '*Secret*'
    }
}

Describe 'Invoke-ExchangeRequest — OperationType gate' {
    BeforeAll {
        $script:exGw = New-ExchangeGateway -TenantId 't' -AppId 'a' -AuthMethod 'Certificate' -Organization 'c.onmicrosoft.com' -RunId 'r1' -RunFolder 'C:\tmp'
        $script:exGw.Connected = $true
        Mock Connect-ExchangeGateway { }
    }
    It 'throws if OperationType=Read and cmdlet is not Get-*' {
        { Invoke-ExchangeRequest -ExchangeGateway $script:exGw -CmdletName 'Set-Mailbox' -OperationType 'Read' -Caller 'Auditor' } |
            Should -Throw '*Read requires Get-*'
    }
    It 'throws if Write from non-Remediator caller' {
        { Invoke-ExchangeRequest -ExchangeGateway $script:exGw -CmdletName 'Set-Mailbox' -OperationType 'Write' -Caller 'Auditor' } |
            Should -Throw '*Exchange write denied*'
    }
    It 'throws if cmdlet not found in session' {
        Mock Get-Command { $null }
        { Invoke-ExchangeRequest -ExchangeGateway $script:exGw -CmdletName 'Get-EXOMailbox' -OperationType 'Read' -Caller 'Auditor' } |
            Should -Throw '*not found in session*'
    }
}

Describe 'Disconnect-ExchangeGateway' {
    It 'sets Connected=false' {
        $gw = New-ExchangeGateway -TenantId 't' -AppId 'a' -AuthMethod 'Certificate' -Organization 'c.onmicrosoft.com' -RunId 'r1' -RunFolder 'C:\tmp'
        $gw.Connected = $true
        Mock Disconnect-ExchangeOnline { }
        Mock Get-Command { [PSCustomObject]@{ Name = 'Disconnect-ExchangeOnline' } } -ParameterFilter { $Name -eq 'Disconnect-ExchangeOnline' }
        Disconnect-ExchangeGateway -ExchangeGateway $gw
        $gw.Connected | Should -BeFalse
    }
}
