Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Executor {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)] $Plan,
        [Parameter(Mandatory)] $Actions,
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] $GraphGateway,
        $ExchangeGateway = $null
    )

    $recomputedPlan = New-SequencePlan -Actions $Actions -RulesVersion $Plan.rulesVersion
    if ($recomputedPlan.planHash -ne $Plan.planHash) {
        throw [System.InvalidOperationException]::new(
            "PlanIntegrityViolation: planHash mismatch. Stored=$($Plan.planHash) Recomputed=$($recomputedPlan.planHash)"
        )
    }

    $actionMap = @{}
    foreach ($a in $Actions) { $actionMap[$a.action.actionId] = $a }

    $executionLog = [System.Collections.Generic.List[object]]::new()

    foreach ($phase in ($Plan.phases | Sort-Object phaseNumber)) {
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

            $whatIf = $Context.WhatIf -eq $true -or $Context.Mode -ne 'Remediate'

            if ($whatIf) {
                $executionLog.Add([PSCustomObject]@{
                    actionId = $entry.actionId
                    phase    = $phase.phaseNumber
                    order    = $entry.order
                    outcome  = 'WhatIf'
                    reason   = $null
                })
                continue
            }

            $writeAllowed = (
                $Context.Mode       -eq 'Remediate' -and
                $Context.AuthMethod -eq 'Delegated' -and
                $Context.WhatIf     -ne $true -and
                $Context.Edition    -eq 'Premium'
            )

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
