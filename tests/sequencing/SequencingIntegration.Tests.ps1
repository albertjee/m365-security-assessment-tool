BeforeAll {
    . "$PSScriptRoot/../../src/Private/sequencing/ActionGraphBuilder.ps1"
    . "$PSScriptRoot/../../src/Private/sequencing/DependencyRulesEngine.ps1"
    . "$PSScriptRoot/../../src/Private/sequencing/Planner.ps1"
    . "$PSScriptRoot/../../src/Private/sequencing/Executor.ps1"
    . "$PSScriptRoot/../../src/Private/sequencing/rules/CA.rules.ps1"
    $script:caRules = Get-Rules

    . "$PSScriptRoot/../../src/Private/sequencing/rules/PIM.rules.ps1"
    $script:pimRules = Get-Rules

    . "$PSScriptRoot/../../src/Private/sequencing/rules/LegacyAuth.rules.ps1"
    $script:laRules = Get-Rules

    function Invoke-Remediator { throw 'Invoke-Remediator stub' }

    function New-IntegAction {
        param([string]$Id, [int]$Phase = 2, [string[]]$Deps = @())
        [PSCustomObject]@{
            action   = [PSCustomObject]@{ actionId=$Id; provider='Graph'; operation='PATCH'; resourceType='policy'; resourceId='r1'; target='t' }
            sequence = [PSCustomObject]@{ dependencies=$Deps; conflictsWith=@(); priority=1; safetyLevel='High'; category='Identity'; phase=$Phase }
            result   = [PSCustomObject]@{ status=$null; reason=$null }
            rulesApplied = @()
        }
    }

    $script:caBlockFalseFindings = @(
        [PSCustomObject]@{
            checkId='CA-001'; status='Fail'
            evidence=@{ breakGlassFound=$false; totalPolicies=2; effectivelyBlocked=$false }
        }
    )
    $script:caBlockTrueFindings = @(
        [PSCustomObject]@{
            checkId='CA-001'; status='Fail'
            evidence=@{ breakGlassFound=$true; totalPolicies=3; effectivelyBlocked=$true }
        }
    )
    $script:pimDisabledFindings = @(
        [PSCustomObject]@{
            checkId='PIM-001'; status='Fail'
            evidence=@{ pimEnabled=$false }
        }
    )
}

Describe 'Sequencing integration — CA block when no break-glass' {
    It 'ACT-CA-ENABLE-MFA is Blocked when BreakGlassAccountsPresent=false' {
        $actions = @(
            New-IntegAction 'ACT-CA-ENABLE-MFA'         -Phase 2 -Deps @('ACT-CA-EXCLUDE-BREAKGLASS')
            New-IntegAction 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
        )
        $annotated = Invoke-DependencyRules -Actions $actions -Rules $script:caRules -Findings $script:caBlockFalseFindings
        $mfaAction = $annotated | Where-Object { $_.action.actionId -eq 'ACT-CA-ENABLE-MFA' }
        $mfaAction.result.status | Should -Be 'Blocked'
    }

    It 'ACT-CA-ENABLE-MFA is NOT Blocked when BreakGlassAccountsPresent=true' {
        $actions = @(
            New-IntegAction 'ACT-CA-ENABLE-MFA'         -Phase 2 -Deps @('ACT-CA-EXCLUDE-BREAKGLASS')
            New-IntegAction 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
        )
        $annotated = Invoke-DependencyRules -Actions $actions -Rules $script:caRules -Findings $script:caBlockTrueFindings
        $mfaAction = $annotated | Where-Object { $_.action.actionId -eq 'ACT-CA-ENABLE-MFA' }
        $mfaAction.result.status | Should -BeNullOrEmpty
    }
}

Describe 'Sequencing integration — full pipeline to plan' {
    It 'plan includes both actions when no block' {
        $actions = @(
            New-IntegAction 'ACT-CA-ENABLE-MFA'         -Phase 2 -Deps @('ACT-CA-EXCLUDE-BREAKGLASS')
            New-IntegAction 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
        )
        $annotated = Invoke-DependencyRules -Actions $actions -Rules $script:caRules -Findings $script:caBlockTrueFindings
        $plan      = New-SequencePlan -Actions $annotated -RulesVersion '1.0.0'

        $allActionIds = $plan.phases | ForEach-Object { $_.actions } | Select-Object -ExpandProperty actionId
        $allActionIds | Should -Contain 'ACT-CA-ENABLE-MFA'
        $allActionIds | Should -Contain 'ACT-CA-EXCLUDE-BREAKGLASS'
    }

    It 'planHash is stable across two identical runs' {
        $actions = @(
            New-IntegAction 'ACT-CA-ENABLE-MFA'         -Phase 2 -Deps @('ACT-CA-EXCLUDE-BREAKGLASS')
            New-IntegAction 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
        )
        $annotated1 = Invoke-DependencyRules -Actions $actions -Rules $script:caRules -Findings $script:caBlockTrueFindings
        $plan1      = New-SequencePlan -Actions $annotated1 -RulesVersion '1.0.0'

        $actions2 = @(
            New-IntegAction 'ACT-CA-ENABLE-MFA'         -Phase 2 -Deps @('ACT-CA-EXCLUDE-BREAKGLASS')
            New-IntegAction 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
        )
        $annotated2 = Invoke-DependencyRules -Actions $actions2 -Rules $script:caRules -Findings $script:caBlockTrueFindings
        $plan2      = New-SequencePlan -Actions $annotated2 -RulesVersion '1.0.0'

        $plan1.planHash | Should -Be $plan2.planHash
    }
}

Describe 'Sequencing integration — PIM block when PIM not enabled' {
    It 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE is Blocked when PIMEnabled=false' {
        $actions   = @(New-IntegAction 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE' -Phase 3)
        $annotated = Invoke-DependencyRules -Actions $actions -Rules $script:pimRules -Findings $script:pimDisabledFindings
        $pimAction = $annotated | Where-Object { $_.action.actionId -eq 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE' }
        $pimAction.result.status | Should -Be 'Blocked'
    }
}

Describe 'Sequencing integration — Executor WhatIf walk' {
    It 'Executor WhatIf walk produces one log entry per action' {
        $actions = @(
            New-IntegAction 'ACT-CA-ENABLE-MFA'         -Phase 2 -Deps @('ACT-CA-EXCLUDE-BREAKGLASS')
            New-IntegAction 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
        )
        $annotated = Invoke-DependencyRules -Actions $actions -Rules $script:caRules -Findings $script:caBlockTrueFindings
        $plan      = New-SequencePlan -Actions $annotated -RulesVersion '1.0.0'

        $context = [PSCustomObject]@{ Mode='WhatIf'; AuthMethod='Certificate'; WhatIf=$true; Edition='Lite' }
        $gateway = [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-integ-001' }

        $log = Invoke-Executor -Plan $plan -Actions $annotated -Context $context -GraphGateway $gateway
        $log.Count | Should -Be 2
        $log | ForEach-Object { $_.outcome | Should -Be 'WhatIf' }
    }

    It 'Executor drift guard catches tampered plan' {
        $actions   = @(New-IntegAction 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1)
        $annotated = Invoke-DependencyRules -Actions $actions -Rules $script:caRules -Findings $script:caBlockTrueFindings
        $plan    = New-SequencePlan -Actions $annotated -RulesVersion '1.0.0'
        $plan.planHash = 'tampered' + ('0' * 56)

        $context = [PSCustomObject]@{ Mode='WhatIf'; AuthMethod='Certificate'; WhatIf=$true; Edition='Lite' }
        $gateway = [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true; RunId='run-001' }

        { Invoke-Executor -Plan $plan -Actions $annotated -Context $context -GraphGateway $gateway } |
            Should -Throw -ExpectedMessage '*PlanIntegrityViolation*'
    }
}
