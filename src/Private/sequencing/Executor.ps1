Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-ExecutorRevalidation {
    [CmdletBinding()]
    param(
        $GraphGateway,
        [string] $TenantId,
        $Findings
    )

    $failures = [System.Collections.Generic.List[string]]::new()

    if ($GraphGateway -and -not [string]::IsNullOrWhiteSpace($TenantId)) {
        try {
            $pin = Test-TenantPin -RequestedTenantId $TenantId -GraphGateway $GraphGateway
            if (-not $pin.Match) {
                $failures.Add("TenantPinMismatch: $($pin.MismatchReason)")
            }
        } catch {
            $failures.Add("TenantPinRevalidationError: $($_.Exception.Message)")
        }
    }

    if ($Findings -and @($Findings).Count -gt 0) {
        try {
            if (-not (Get-FactValue -FactName 'BreakGlassAccountsPresent' -Findings $Findings)) {
                $failures.Add('BreakGlassAccountsNotPresent')
            }
        } catch {
            $failures.Add("BreakGlassRevalidationError: $($_.Exception.Message)")
        }

        try {
            if (-not (Get-FactValue -FactName 'CAFrameworkPresent' -Findings $Findings)) {
                $failures.Add('CABaselineMissing')
            }
        } catch {
            $failures.Add("CARevalidationError: $($_.Exception.Message)")
        }
    }

    return [PSCustomObject]@{
        Passed   = ($failures.Count -eq 0)
        Failures = $failures.ToArray()
    }
}

function Invoke-Executor {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)] $Plan,
        [Parameter(Mandatory)] $Actions,
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] $GraphGateway,
        $ExchangeGateway = $null,
        $Findings        = @(),
        [string] $TenantId = ''
    )

    $recomputedPlan = New-SequencePlan -Actions $Actions -RulesVersion $Plan.rulesVersion
    if ($recomputedPlan.planHash -ne $Plan.planHash) {
        throw [System.InvalidOperationException]::new(
            "PlanIntegrityViolation: planHash mismatch. Stored=$($Plan.planHash) Recomputed=$($recomputedPlan.planHash)"
        )
    }

    $actionMap = @{}
    foreach ($a in $Actions) { $actionMap[$a.action.actionId] = $a }

    $globalWhatIf = $Context.WhatIf -eq $true -or $Context.Mode -ne 'Remediate'
    $writeAllowed = (
        $Context.Mode       -eq 'Remediate' -and
        $Context.AuthMethod -eq 'Delegated' -and
        $Context.WhatIf     -ne $true       -and
        $Context.Edition    -eq 'Premium'
    )

    $executionLog       = [System.Collections.Generic.List[object]]::new()
    $revalidationDone   = $false
    $revalidationPassed = $true
    $revalidationReason = ''

    foreach ($phase in ($Plan.phases | Sort-Object phaseNumber)) {

        # Run revalidation once before first Phase 2+ action in live-execute mode
        if ($phase.phaseNumber -ge 2 -and -not $revalidationDone -and $writeAllowed) {
            $revalidationDone = $true
            $rv = Invoke-ExecutorRevalidation -GraphGateway $GraphGateway -TenantId $TenantId -Findings $Findings
            $revalidationPassed = $rv.Passed
            if (-not $rv.Passed) {
                $revalidationReason = $rv.Failures -join '; '
            }
        }

        foreach ($entry in ($phase.actions | Sort-Object order)) {
            $action  = $actionMap[$entry.actionId]
            $blocked = $entry.status -eq 'Blocked'

            if ($blocked) {
                $executionLog.Add([PSCustomObject]@{
                    actionId = $entry.actionId
                    phase    = $phase.phaseNumber
                    order    = $entry.order
                    outcome  = 'Blocked'
                    reason   = $entry.reason
                })
                continue
            }

            if ($phase.phaseNumber -ge 2 -and -not $revalidationPassed) {
                $executionLog.Add([PSCustomObject]@{
                    actionId = $entry.actionId
                    phase    = $phase.phaseNumber
                    order    = $entry.order
                    outcome  = 'RevalidationFailed'
                    reason   = $revalidationReason
                })
                continue
            }

            if ($globalWhatIf) {
                $executionLog.Add([PSCustomObject]@{
                    actionId = $entry.actionId
                    phase    = $phase.phaseNumber
                    order    = $entry.order
                    outcome  = 'WhatIf'
                    reason   = $null
                })
                continue
            }

            if (-not $writeAllowed) {
                $executionLog.Add([PSCustomObject]@{
                    actionId = $entry.actionId
                    phase    = $phase.phaseNumber
                    order    = $entry.order
                    outcome  = 'WriteGateDenied'
                    reason   = 'Write gate conditions not met'
                })
                continue
            }

            if (-not $PSCmdlet.ShouldProcess($entry.actionId, 'Execute remediation action')) {
                $executionLog.Add([PSCustomObject]@{
                    actionId = $entry.actionId
                    phase    = $phase.phaseNumber
                    order    = $entry.order
                    outcome  = 'WhatIf'
                    reason   = 'ShouldProcessDenied'
                })
                continue
            }

            try {
                $remResult = Invoke-Remediator -Action $action -GraphGateway $GraphGateway -ExchangeGateway $ExchangeGateway
                $executionLog.Add([PSCustomObject]@{
                    actionId   = $entry.actionId
                    phase      = $phase.phaseNumber
                    order      = $entry.order
                    outcome    = 'Executed'
                    reason     = $null
                    remediator = $remResult
                })
            } catch {
                $executionLog.Add([PSCustomObject]@{
                    actionId = $entry.actionId
                    phase    = $phase.phaseNumber
                    order    = $entry.order
                    outcome  = 'Failed'
                    reason   = $_.Exception.Message
                })
            }
        }
    }

    return $executionLog.ToArray()
}
