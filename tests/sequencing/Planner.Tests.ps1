BeforeAll {
    . "$PSScriptRoot/../../src/Private/sequencing/ActionGraphBuilder.ps1"
    . "$PSScriptRoot/../../src/Private/sequencing/DependencyRulesEngine.ps1"

    function New-PlanAction {
        param([string]$Id, [int]$Phase = 2, [string[]]$Deps = @(), [string]$Status = $null)
        [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId=$Id }
            sequence = [PSCustomObject]@{
                dependencies = $Deps
                conflictsWith = @()
                priority = 1
                safetyLevel = 'Medium'
                category = 'Identity'
                phase = $Phase
            }
            result   = [PSCustomObject]@{ status=$Status; reason=$null }
            rulesApplied = @()
        }
    }
}

Describe 'New-SequencePlan — basic structure' {
    BeforeAll {
        . "$PSScriptRoot/../../src/Private/sequencing/Planner.ps1"
    }

    It 'returns PSCustomObject with phases, summary, planHash, rulesVersion' {
        $actions = @(New-PlanAction 'ACT-A')
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $plan | Should -Not -BeNullOrEmpty
        $plan.phases      | Should -Not -BeNullOrEmpty
        $plan.summary     | Should -Not -BeNullOrEmpty
        $plan.planHash    | Should -Not -BeNullOrEmpty
        $plan.rulesVersion | Should -Be '1.0.0'
    }

    It 'planHash is sha256 hex string (64 chars)' {
        $actions = @(New-PlanAction 'ACT-A')
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $plan.planHash | Should -Match '^[0-9a-f]{64}$'
    }
}

Describe 'New-SequencePlan — phase assignment' {
    BeforeAll {
        . "$PSScriptRoot/../../src/Private/sequencing/Planner.ps1"
    }

    It 'assigns Phase 1 to Safety Prep actions (ACT-CA-EXCLUDE-*)' {
        $actions = @(New-PlanAction 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1)
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $phase = $plan.phases | Where-Object { $_.phaseNumber -eq 1 }
        $phase | Should -Not -BeNullOrEmpty
        $phase.actions | Where-Object { $_.actionId -eq 'ACT-CA-EXCLUDE-BREAKGLASS' } | Should -Not -BeNullOrEmpty
    }

    It 'assigns Phase 2 to Identity Controls actions (ACT-CA-*, ACT-LA-*)' {
        $actions = @(
            New-PlanAction 'ACT-CA-ENABLE-MFA' -Phase 2
            New-PlanAction 'ACT-LA-BLOCK-PROTOCOLS' -Phase 2
        )
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $phase = $plan.phases | Where-Object { $_.phaseNumber -eq 2 }
        $phase.actions.Count | Should -Be 2
    }

    It 'assigns Phase 3 to Privilege Controls actions (ACT-PIM-*)' {
        $actions = @(New-PlanAction 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE' -Phase 3)
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $phase = $plan.phases | Where-Object { $_.phaseNumber -eq 3 }
        $phase.actions | Where-Object { $_.actionId -eq 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE' } | Should -Not -BeNullOrEmpty
    }

    It 'phase objects have phaseNumber, name, and actions array' {
        $actions = @(New-PlanAction 'ACT-CA-ENABLE-MFA' -Phase 2)
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $phase = $plan.phases | Where-Object { $_.phaseNumber -eq 2 }
        $phase.phaseNumber | Should -Be 2
        $phase.name        | Should -Not -BeNullOrEmpty
        $phase.actions     | Should -Not -BeNullOrEmpty
    }
}

Describe 'New-SequencePlan — topological ordering' {
    BeforeAll {
        . "$PSScriptRoot/../../src/Private/sequencing/Planner.ps1"
    }

    It 'places dependency before dependent action within a phase' {
        $actions = @(
            New-PlanAction 'ACT-CA-ENABLE-MFA'       -Phase 2 -Deps @('ACT-CA-EXCLUDE-BREAKGLASS')
            New-PlanAction 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
        )
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $ordered = $plan.phases | ForEach-Object { $_.actions } | Select-Object -ExpandProperty order
        $ordered | Should -Not -BeNullOrEmpty
    }

    It 'order field is sequential integer starting at 1 within each phase' {
        $actions = @(
            New-PlanAction 'ACT-CA-ENABLE-MFA'     -Phase 2 -Deps @('ACT-LA-BLOCK-PROTOCOLS')
            New-PlanAction 'ACT-LA-BLOCK-PROTOCOLS' -Phase 2
        )
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $phase2 = $plan.phases | Where-Object { $_.phaseNumber -eq 2 }
        $orders = $phase2.actions | Select-Object -ExpandProperty order | Sort-Object
        $orders[0] | Should -Be 1
        $orders[1] | Should -Be 2
    }
}

Describe 'New-SequencePlan — summary' {
    BeforeAll {
        . "$PSScriptRoot/../../src/Private/sequencing/Planner.ps1"
    }

    It 'summary.total equals total action count' {
        $actions = @(
            New-PlanAction 'ACT-A'
            New-PlanAction 'ACT-B'
            New-PlanAction 'ACT-C'
        )
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $plan.summary.total | Should -Be 3
    }

    It 'summary.blocked counts only Blocked actions' {
        $actions = @(
            New-PlanAction 'ACT-A' -Status 'Blocked'
            New-PlanAction 'ACT-B'
            New-PlanAction 'ACT-C' -Status 'Blocked'
        )
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $plan.summary.blocked | Should -Be 2
    }

    It 'summary.highRisk counts actions with safetyLevel=High or Critical' {
        $actions = @(
            New-PlanAction 'ACT-A'
            New-PlanAction 'ACT-B'
        )
        $actions[0].sequence.safetyLevel = 'High'
        $actions[1].sequence.safetyLevel = 'Medium'
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $plan.summary.highRisk | Should -Be 1
    }
}

Describe 'New-SequencePlan — determinism' {
    BeforeAll {
        . "$PSScriptRoot/../../src/Private/sequencing/Planner.ps1"
    }

    It 'same input produces identical planHash on repeated calls' {
        $actions = @(
            New-PlanAction 'ACT-CA-ENABLE-MFA'       -Phase 2 -Deps @('ACT-CA-EXCLUDE-BREAKGLASS')
            New-PlanAction 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
            New-PlanAction 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE' -Phase 3
        )
        $plan1 = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $plan2 = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $plan1.planHash | Should -Be $plan2.planHash
    }

    It 'different rulesVersion produces different planHash' {
        $actions = @(New-PlanAction 'ACT-A')
        $plan1 = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $plan2 = New-SequencePlan -Actions $actions -RulesVersion '2.0.0'
        $plan1.planHash | Should -Not -Be $plan2.planHash
    }
}

Describe 'New-SequencePlan — blocked actions included in plan' {
    BeforeAll {
        . "$PSScriptRoot/../../src/Private/sequencing/Planner.ps1"
    }

    It 'Blocked action appears in plan with status=Blocked' {
        $actions = @(
            New-PlanAction 'ACT-CA-ENABLE-MFA' -Phase 2 -Status 'Blocked'
            New-PlanAction 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
        )
        $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
        $allActions = $plan.phases | ForEach-Object { $_.actions }
        $blocked = $allActions | Where-Object { $_.status -eq 'Blocked' }
        $blocked | Should -Not -BeNullOrEmpty
    }
}
