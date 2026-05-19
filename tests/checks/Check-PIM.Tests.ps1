BeforeAll {
    . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../../src/Private/checks/Check-PIM.ps1"

    function Invoke-GraphRequest { throw 'Invoke-GraphRequest stub — must be mocked per test' }
    Remove-Alias -Name Invoke-GraphRequest -Force -ErrorAction SilentlyContinue

    function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-test-001' } }
}

Describe 'Get-CheckMetadata' {
    It 'id is PIM-001' { (Get-CheckMetadata).id | Should -Be 'PIM-001' }
    It 'severity is Critical' { (Get-CheckMetadata).severity | Should -Be 'Critical' }
    It 'has RoleManagement permission' { (Get-CheckMetadata).requiredPermissions | Should -Contain 'RoleManagement.Read.Directory' }
    It 'passes Test-CheckContract' {
        . "$PSScriptRoot/../../src/Private/policy/Test-CheckContract.ps1"
        $result = Test-CheckContract -ModulePath "$PSScriptRoot/../../src/Private/checks/Check-PIM.ps1"
        $result.IsValid | Should -BeTrue -Because ($result.Violations -join '; ')
    }
}

Describe 'Invoke-Check — standing active roles' {
    BeforeAll {
        $script:gaRoleId = '62e90394-69f5-4237-9190-012177145e10'
        $script:activeAssignment = [PSCustomObject]@{
            id               = 'assign-001'
            roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'
            principalId      = 'user-001'
            assignmentType   = 'Assigned'
            memberType       = 'Direct'
        }
    }

    It 'returns Fail when Global Admins have active (not eligible) assignments' {
        $gw = New-MockGateway
        $aa = $script:activeAssignment
        Mock Invoke-GraphRequest {
            param($Uri)
            if ($Uri -match 'roleAssignments') {
                return [PSCustomObject]@{ Result = @{ value = @($aa) } }
            }
            return [PSCustomObject]@{ Result = @{ value = @() } }
        }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $standingFinding = $findings | Where-Object { $_.title -match 'Standing' -or $_.title -match 'Active.*Assign' }
        $standingFinding | Should -Not -BeNullOrEmpty
        $standingFinding.status | Should -Be 'Fail'
        $standingFinding.evidence.standingGlobalAdminCount | Should -BeGreaterThan 0
    }

    It 'returns Pass when no standing active assignments for high-privilege roles' {
        $gw = New-MockGateway
        Mock Invoke-GraphRequest { [PSCustomObject]@{ Result = @{ value = @() } } }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $standingFinding = $findings | Where-Object { $_.title -match 'Standing' -or $_.title -match 'Active.*Assign' }
        $standingFinding.status | Should -Be 'Pass'
    }
}

Describe 'Invoke-Check — PIM not enabled' {
    It 'returns Fail when no eligible schedules and no role policies found' {
        $gw = New-MockGateway
        Mock Invoke-GraphRequest { [PSCustomObject]@{ Result = @{ value = @() } } }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $pimFinding = $findings | Where-Object { $_.title -match 'JIT' }
        $pimFinding | Should -Not -BeNullOrEmpty
    }

    It 'JIT finding title is exactly "Privileged Identity Management (JIT) Not in Use"' {
        $gw = New-MockGateway
        Mock Invoke-GraphRequest { [PSCustomObject]@{ Result = @{ value = @() } } }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $pimFinding = $findings | Where-Object { $_.title -match 'JIT' }
        $pimFinding.title | Should -Be 'Privileged Identity Management (JIT) Not in Use'
    }

    It 'JIT finding evidence includes pimConversionComplete key' {
        $gw = New-MockGateway
        Mock Invoke-GraphRequest { [PSCustomObject]@{ Result = @{ value = @() } } }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $pimFinding = $findings | Where-Object { $_.title -match 'JIT' }
        $pimFinding.evidence.Keys | Should -Contain 'pimConversionComplete'
    }

    It 'JIT finding evidence includes approvalWorkflowConfigured key' {
        $gw = New-MockGateway
        Mock Invoke-GraphRequest { [PSCustomObject]@{ Result = @{ value = @() } } }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $pimFinding = $findings | Where-Object { $_.title -match 'JIT' }
        $pimFinding.evidence.Keys | Should -Contain 'approvalWorkflowConfigured'
    }
}

Describe 'Invoke-Check — error handling' {
    It 'returns NotAssessed when gateway throws' {
        $gw = New-MockGateway
        Mock Invoke-GraphRequest { throw 'throttled' }
        $findings = Invoke-Check -GraphGateway $gw -Config @{}
        $findings[0].status | Should -Be 'NotAssessed'
    }
}
