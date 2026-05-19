BeforeAll {
    . "$PSScriptRoot/../../src/Private/sequencing/ActionGraphBuilder.ps1"
    . "$PSScriptRoot/../../src/Private/sequencing/DependencyRulesEngine.ps1"
    . "$PSScriptRoot/../../src/Private/sequencing/Planner.ps1"
    . "$PSScriptRoot/../../src/Private/sequencing/Executor.ps1"

    function New-ExecAction {
        param([string]$Id, [int]$Phase = 2, [string[]]$Deps = @(), [string]$Status = $null)
        [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId=$Id; provider='Graph'; operation='PATCH'; resourceType='policy'; resourceId='r1'; target='t1' }
            sequence = [PSCustomObject]@{ dependencies=$Deps; conflictsWith=@(); priority=1; safetyLevel='Medium'; category='Identity'; phase=$Phase }
            result   = [PSCustomObject]@{ status=$Status; reason=$null }
            rulesApplied = @()
        }
    }

    function New-MockGateway {
        [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Delegated'; Connected=$true; RunId='run-test-001' }
    }

    function Invoke-Remediator { throw 'Invoke-Remediator stub — must be mocked per test' }
}

Describe 'Invoke-Executor — plan integrity guard' {
    It 'throws PlanIntegrityViolation when planHash does not match' {
        $actions = @(New-ExecAction 'ACT-A')
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $plan.planHash = 'tampered000000000000000000000000000000000000000000000000000000'

        $context = [PSCustomObject]@{
            Mode       = 'Remediate'
            AuthMethod = 'Delegated'
            WhatIf     = $false
            Edition    = 'Premium'
        }

        { Invoke-Executor -Plan $plan -Actions $actions -Context $context -GraphGateway (New-MockGateway) } |
            Should -Throw -ExpectedMessage '*PlanIntegrityViolation*'
    }

    It 'does not throw when planHash matches' {
        $actions = @(New-ExecAction 'ACT-A')
        $plan    = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'

        $context = [PSCustomObject]@{
            Mode       = 'WhatIf'
            AuthMethod = 'Certificate'
            WhatIf     = $true
            Edition    = 'Lite'
        }

        { Invoke-Executor -Plan $plan -Actions $actions -Context $context -GraphGateway (New-MockGateway) } |
            Should -Not -Throw
    }
}

Describe 'Invoke-Executor — Blocked action skip' {
    It 'skips Blocked actions and records them as Blocked in execution log' {
        $actions = @(
            New-ExecAction 'ACT-BLOCKED' -Status 'Blocked'
        )
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'

        $context = [PSCustomObject]@{
            Mode       = 'WhatIf'
            AuthMethod = 'Certificate'
            WhatIf     = $true
            Edition    = 'Lite'
        }

        $log = Invoke-Executor -Plan $plan -Actions $actions -Context $context -GraphGateway (New-MockGateway)
        $blocked = @($log | Where-Object { $_.actionId -eq 'ACT-BLOCKED' -and $_.outcome -eq 'Blocked' })
        $blocked.Count | Should -Be 1
    }
}

Describe 'Invoke-Executor — WhatIf mode' {
    It 'returns WhatIf outcome for non-blocked actions when WhatIf=true' {
        $actions = @(New-ExecAction 'ACT-A')
        $plan    = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'

        $context = [PSCustomObject]@{
            Mode       = 'WhatIf'
            AuthMethod = 'Certificate'
            WhatIf     = $true
            Edition    = 'Lite'
        }

        $log = Invoke-Executor -Plan $plan -Actions $actions -Context $context -GraphGateway (New-MockGateway)
        $entry = $log | Where-Object { $_.actionId -eq 'ACT-A' }
        $entry.outcome | Should -Be 'WhatIf'
    }

    It 'does not invoke Remediator in WhatIf mode' {
        $actions = @(New-ExecAction 'ACT-A')
        $plan    = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'

        $context = [PSCustomObject]@{
            Mode       = 'WhatIf'
            AuthMethod = 'Certificate'
            WhatIf     = $true
            Edition    = 'Lite'
        }

        Mock Invoke-Remediator { throw 'should not be called' }

        $log = Invoke-Executor -Plan $plan -Actions $actions -Context $context -GraphGateway (New-MockGateway)
        Should -Invoke Invoke-Remediator -Times 0
    }
}

Describe 'Invoke-Executor — execution log structure' {
    It 'returns array of log entries with actionId, outcome, phase, order fields' {
        $actions = @(
            New-ExecAction 'ACT-A'
            New-ExecAction 'ACT-BLOCKED' -Status 'Blocked'
        )
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'

        $context = [PSCustomObject]@{
            Mode       = 'WhatIf'
            AuthMethod = 'Certificate'
            WhatIf     = $true
            Edition    = 'Lite'
        }

        $log = Invoke-Executor -Plan $plan -Actions $actions -Context $context -GraphGateway (New-MockGateway)
        $log.Count | Should -Be 2
        $log[0].actionId | Should -Not -BeNullOrEmpty
        $log[0].outcome  | Should -Not -BeNullOrEmpty
        $log[0].phase    | Should -Not -BeNullOrEmpty
        $log[0].order    | Should -BeGreaterThan 0
    }
}

Describe 'Invoke-Executor — topological walk order' {
    It 'processes actions in topological order (dependency before dependent)' {
        $actions = @(
            New-ExecAction 'ACT-B' -Phase 2 -Deps @('ACT-A')
            New-ExecAction 'ACT-A' -Phase 2
        )
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'

        $context = [PSCustomObject]@{
            Mode       = 'WhatIf'
            AuthMethod = 'Certificate'
            WhatIf     = $true
            Edition    = 'Lite'
        }

        $log = Invoke-Executor -Plan $plan -Actions $actions -Context $context -GraphGateway (New-MockGateway)
        $idxA = ($log | Select-Object -ExpandProperty actionId).IndexOf('ACT-A')
        $idxB = ($log | Select-Object -ExpandProperty actionId).IndexOf('ACT-B')
        $idxA | Should -BeLessThan $idxB
    }
}
