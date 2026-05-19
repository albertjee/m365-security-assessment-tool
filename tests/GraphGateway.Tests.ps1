BeforeAll {
    . "$PSScriptRoot/../src/Private/GraphGateway.ps1"
}

Describe 'New-GraphGateway' {
    It 'returns object with expected PSTypeName' {
        $gw = New-GraphGateway -TenantId 'tid' -AppId 'aid' -AuthMethod 'Certificate' -RunId 'r1' -RunFolder 'C:\tmp'
        $gw.PSObject.TypeNames[0] | Should -Be 'Metis.GraphGateway'
    }
    It 'stores AuthMethod' {
        $gw = New-GraphGateway -TenantId 'tid' -AppId 'aid' -AuthMethod 'Secret' -RunId 'r1' -RunFolder 'C:\tmp'
        $gw.AuthMethod | Should -Be 'Secret'
    }
}

Describe 'Invoke-GraphRequest — write gate' {
    BeforeAll {
        $gw = New-GraphGateway -TenantId 'tid' -AppId 'aid' -AuthMethod 'Certificate' -RunId 'r1' -RunFolder 'C:\tmp'
    }
    It 'throws if OperationType=Read and Method != GET' {
        { Invoke-GraphRequest -GraphGateway $gw -Uri '/test' -Method 'POST' -OperationType 'Read' -Caller 'Test' } |
            Should -Throw
    }
    It 'throws if OperationType=Write and Caller != Remediator' {
        { Invoke-GraphRequest -GraphGateway $gw -Uri '/test' -Method 'POST' -OperationType 'Write' -Caller 'Auditor' } |
            Should -Throw '*write denied*'
    }
    It 'throws if OperationType=Write and Caller=Remediator but no connection' {
        { Invoke-GraphRequest -GraphGateway $gw -Uri '/test' -Method 'POST' -OperationType 'Write' -Caller 'Remediator' } |
            Should -Throw
    }
}

Describe 'Connect-GraphGateway — Secret auth PSCredential binding' {
    BeforeAll {
        Mock Connect-MgGraph { }
        Mock Get-MgContext { [PSCustomObject]@{ AccessToken = 'fake-token' } }
    }

    It 'passes PSCredential (not bare SecureString) to Connect-MgGraph for Secret auth' {
        $gw = New-GraphGateway -TenantId 'tid' -AppId 'my-app-id' -AuthMethod 'Secret' `
                               -ClientSecret 'my-secret' -RunId 'r1' -RunFolder 'C:\tmp'
        Connect-GraphGateway -GraphGateway $gw
        Should -Invoke Connect-MgGraph -Times 1 -ParameterFilter {
            $ClientSecretCredential -is [System.Management.Automation.PSCredential]
        }
    }

    It 'uses AppId as PSCredential UserName for Secret auth' {
        $gw = New-GraphGateway -TenantId 'tid' -AppId 'my-app-id' -AuthMethod 'Secret' `
                               -ClientSecret 'my-secret' -RunId 'r1' -RunFolder 'C:\tmp'
        Connect-GraphGateway -GraphGateway $gw
        Should -Invoke Connect-MgGraph -Times 1 -ParameterFilter {
            $ClientSecretCredential.UserName -eq 'my-app-id'
        }
    }
}

Describe 'Invoke-GraphRequest — pagination' {
    BeforeAll {
        $script:paginationGw = New-GraphGateway -TenantId 'tid' -AppId 'aid' -AuthMethod 'Certificate' -RunId 'r1' -RunFolder 'C:\tmp'
        $script:paginationGw.Connected   = $true
        $script:paginationGw.AccessToken = 'fake-token'

        $global:_GwTestPage1     = @{ value = @(1,2); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/next' }
        $global:_GwTestPage2     = @{ value = @(3,4) }
        $global:_GwTestCallCount = 0

        Mock Invoke-MgGraphRequest {
            $global:_GwTestCallCount++
            if ($global:_GwTestCallCount -eq 1) { return $global:_GwTestPage1 }
            return $global:_GwTestPage2
        }

        # Microsoft.Graph.Authentication defines Invoke-GraphRequest as an alias (backward compat).
        # Loading that module via Mock overrides our dot-sourced function. Remove the alias so our
        # function wins.
        Remove-Alias -Name Invoke-GraphRequest -Force -ErrorAction SilentlyContinue
    }

    It 'follows @odata.nextLink until exhausted' {
        $global:_GwTestCallCount = 0
        $result = Invoke-GraphRequest -GraphGateway $script:paginationGw -Uri '/test' -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
        $result.Result.value.Count | Should -Be 4
    }
}
