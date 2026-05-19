Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PhaseMap = @{
    1 = 'Safety Prep'
    2 = 'Identity Controls'
    3 = 'Privilege Controls'
    4 = 'Device/Data'
    5 = 'Enforcement'
}

function Get-ActionPhase {
    param([string]$ActionId, $Action)
    $phaseProp = $Action.sequence.PSObject.Properties['phase']
    $phaseFromSeq = if ($phaseProp) { $phaseProp.Value } else { $null }
    if ($phaseFromSeq -and [int]$phaseFromSeq -ge 1) { return [int]$phaseFromSeq }

    if ($ActionId -match '^ACT-CA-EXCLUDE-') { return 1 }
    if ($ActionId -match '^ACT-CA-|^ACT-LA-') { return 2 }
    if ($ActionId -match '^ACT-PIM-') { return 3 }
    if ($ActionId -match '^ACT-DEV-|^ACT-DLP-|^ACT-LABEL-') { return 4 }
    return 5
}

function Get-PlanHashInput {
    param($OrderedActions, [string]$RulesVersion)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("rulesVersion=$RulesVersion;")
    foreach ($a in $OrderedActions) {
        $deps = ($a.sequence.dependencies | Sort-Object) -join ','
        $status = if ($a.result.status) { $a.result.status } else { 'Pending' }
        [void]$sb.Append("id=$($a.action.actionId)|phase=$(Get-ActionPhase $a.action.actionId $a)|status=$status|deps=$deps;")
    }
    return $sb.ToString()
}

function New-SequencePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Actions,
        [Parameter(Mandatory)][string] $RulesVersion
    )

    $graph   = Build-ActionGraph -Actions $Actions
    $ordered = Get-TopologicalOrder -Graph $graph

    $phaseGroups = [System.Collections.Generic.Dictionary[int, System.Collections.Generic.List[object]]]::new()
    foreach ($phaseNum in $script:PhaseMap.Keys) {
        $phaseGroups[$phaseNum] = [System.Collections.Generic.List[object]]::new()
    }

    $actionMap = @{}
    foreach ($a in $Actions) { $actionMap[$a.action.actionId] = $a }

    foreach ($id in $ordered) {
        $a     = $actionMap[$id]
        $phase = Get-ActionPhase $id $a
        if (-not $phaseGroups.ContainsKey($phase)) {
            $phaseGroups[$phase] = [System.Collections.Generic.List[object]]::new()
        }
        $phaseGroups[$phase].Add($a)
    }

    $phases = [System.Collections.Generic.List[object]]::new()
    foreach ($phaseNum in ($phaseGroups.Keys | Sort-Object)) {
        $group = $phaseGroups[$phaseNum]
        if ($group.Count -eq 0) { continue }
        $order = 1
        $phaseActions = $group | ForEach-Object {
            $status = if ($_.result.status) { $_.result.status } else { $null }
            $slProp  = $_.sequence.PSObject.Properties['safetyLevel']
            $catProp = $_.sequence.PSObject.Properties['category']
            $entry = [PSCustomObject]@{
                actionId     = $_.action.actionId
                order        = $order
                status       = $status
                reason       = $_.result.reason
                dependencies = $_.sequence.dependencies
                safetyLevel  = if ($slProp)  { $slProp.Value }  else { $null }
                category     = if ($catProp) { $catProp.Value } else { $null }
            }
            $order++
            $entry
        }
        $phases.Add([PSCustomObject]@{
            phaseNumber = $phaseNum
            name        = $script:PhaseMap[$phaseNum]
            actions     = @($phaseActions)
        })
    }

    $orderedAll = $ordered | ForEach-Object { $actionMap[$_] }
    $hashInput  = Get-PlanHashInput -OrderedActions $orderedAll -RulesVersion $RulesVersion
    $bytes      = [System.Text.Encoding]::UTF8.GetBytes($hashInput)
    $sha256     = [System.Security.Cryptography.SHA256]::Create()
    $hash       = ($sha256.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    $sha256.Dispose()

    $total     = $Actions.Count
    $blocked   = @($Actions | Where-Object { $_.result.status -eq 'Blocked' }).Count
    $highRisk  = @($Actions | Where-Object {
        $slP = $_.sequence.PSObject.Properties['safetyLevel']
        $sl  = if ($slP) { $slP.Value } else { $null }
        $sl -eq 'High' -or $sl -eq 'Critical'
    }).Count

    return [PSCustomObject]@{
        rulesVersion = $RulesVersion
        planHash     = $hash
        phases       = $phases.ToArray()
        summary      = [PSCustomObject]@{
            total    = $total
            blocked  = $blocked
            highRisk = $highRisk
        }
    }
}
