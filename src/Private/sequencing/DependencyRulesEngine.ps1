Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:FactMap = @{
    BreakGlassAccountsPresent     = @{ checkId='CA-001';    evidenceKey='breakGlassFound' }
    LegacyAuthBlocked             = @{ checkId='LA-001';    evidenceKey='effectivelyBlocked' }
    CAFrameworkPresent            = @{ checkId='CA-001';    evidenceKey='totalPolicies'; transform={ param($v) [int]$v -gt 0 } }
    PIMEnabled                    = @{ checkId='PIM-001';   evidenceKey='pimEnabled' }
    AuditLoggingEnabled           = @{ checkId='AUDIT-001'; evidenceKey='auditLoggingEnabled' }
    SensitivityLabelsDefined      = @{ checkId='LABEL-001'; evidenceKey='labelsDefined' }
    DeviceCompliancePoliciesExist = @{ checkId='DEV-001';   evidenceKey='compliancePoliciesExist' }
    Always                        = $null
}

function Get-FactValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $FactName,
        [Parameter(Mandatory)] $Findings
    )

    if ($FactName -eq 'Always') { return $true }

    $mapping = $script:FactMap[$FactName]
    if (-not $mapping) { return $false }

    $finding = $Findings | Where-Object { $_.checkId -eq $mapping.checkId } | Select-Object -First 1
    if (-not $finding) { return $false }

    $rawValue = $finding.evidence[$mapping.evidenceKey]
    if ($null -eq $rawValue) { return $false }

    $transform = $mapping['transform']
    if ($transform) {
        return & $transform $rawValue
    }
    return [bool]$rawValue
}

function Test-RuleCondition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Condition,
        [Parameter(Mandatory)] $Findings
    )
    $factValue = Get-FactValue -FactName $Condition.fact -Findings $Findings
    switch ($Condition.operator) {
        'Equals'      { return $factValue -eq $Condition.value }
        'NotEquals'   { return $factValue -ne $Condition.value }
        'GreaterThan' { return $factValue -gt $Condition.value }
        default       { return $false }
    }
}

function Get-AllRules {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $RulesPath)

    $allRules  = [System.Collections.Generic.List[object]]::new()
    $ruleFiles = Get-ChildItem -Path $RulesPath -Filter '*.rules.ps1' -File

    foreach ($file in $ruleFiles) {
        $content = Get-Content $file.FullName -Raw
        $rules   = & ([scriptblock]::Create("$content; Get-Rules"))
        foreach ($r in $rules) { $allRules.Add($r) }
    }
    return $allRules.ToArray()
}

function Invoke-DependencyRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Actions,
        [Parameter(Mandatory)] $Rules,
        [Parameter(Mandatory)] $Findings
    )

    $typePriority = @{ Block=10; Dependency=5; Conflict=3; Advisory=1 }

    foreach ($action in $Actions) {
        $actionId      = $action.action.actionId
        $matchingRules = @($Rules | Where-Object { $_.appliesToAction -eq $actionId }) |
                         Sort-Object { $typePriority[$_.type] * -1 }, { $_.priority * -1 }

        $appliedRules = [System.Collections.Generic.List[object]]::new()
        $isBlocked    = $false
        $blockReason  = $null

        foreach ($rule in $matchingRules) {
            $conditionMet = Test-RuleCondition -Condition $rule.condition -Findings $Findings

            switch ($rule.type) {
                'Block' {
                    if ($conditionMet) {
                        $isBlocked   = $true
                        $blockReason = $rule.effect.reason
                        $appliedRules.Add([PSCustomObject]@{ ruleId=$rule.ruleId; outcome='Blocked'; reason=$rule.effect.reason })
                    }
                }
                'Dependency' {
                    if ($conditionMet -and $rule.effect.dependency) {
                        if ($rule.effect.dependency -notin $action.sequence.dependencies) {
                            $action.sequence.dependencies = @($action.sequence.dependencies) + @($rule.effect.dependency)
                        }
                        $appliedRules.Add([PSCustomObject]@{ ruleId=$rule.ruleId; outcome='DependencyAdded'; reason=$rule.effect.reason })
                    } elseif (-not $conditionMet -and $rule.effect.blockIfUnsatisfied) {
                        $isBlocked   = $true
                        $blockReason = $rule.effect.reason
                        $appliedRules.Add([PSCustomObject]@{ ruleId=$rule.ruleId; outcome='Blocked'; reason=$rule.effect.reason })
                    }
                }
                'Conflict' {
                    if ($conditionMet -and $rule.effect.conflictsWith) {
                        if ($rule.effect.conflictsWith -notin $action.sequence.conflictsWith) {
                            $action.sequence.conflictsWith = @($action.sequence.conflictsWith) + @($rule.effect.conflictsWith)
                        }
                        $appliedRules.Add([PSCustomObject]@{ ruleId=$rule.ruleId; outcome='ConflictFlagged'; reason=$rule.effect.reason })
                    }
                }
                'Advisory' {
                    $appliedRules.Add([PSCustomObject]@{ ruleId=$rule.ruleId; outcome='Advisory'; reason=$rule.effect.reason })
                }
            }
        }

        if ($isBlocked) {
            $action.result.status = 'Blocked'
            $action.result.reason = $blockReason
        }
        $action.rulesApplied = $appliedRules.ToArray()
    }

    return $Actions
}
