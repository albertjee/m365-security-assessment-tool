# M365 Security Assessment Tool — Tasks 19–24

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Prerequisite:** Tasks 1–18 complete (Gateways, Policy, Models, Checks 10–12, Auditor, Reporter, ActionGraphBuilder, Rules Library, DependencyRulesEngine).

**Goal:** Planner produces deterministic ordered plan with planHash; Executor enforces drift guard and walk order; Remediator routes writes per `action.provider`; first 3 checks get `Invoke-Remediation` implementations.

---

### Task 19: Planner

**Files:**
- Modify: `src/Private/sequencing/Planner.ps1` (replace stub)
- Create: `tests/sequencing/Planner.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/sequencing/Planner.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/models/RemediationAction.schema.ps1"
      . "$PSScriptRoot/../../src/Private/sequencing/ActionGraphBuilder.ps1"
      . "$PSScriptRoot/../../src/Private/sequencing/DependencyRulesEngine.ps1"
      . "$PSScriptRoot/../../src/Private/sequencing/Planner.ps1"

      function New-TestAction {
          param([string]$Id, [int]$Phase = 2, [string[]]$Deps = @())
          [PSCustomObject]@{
              action   = [PSCustomObject]@{ actionId=$Id; provider='Graph' }
              sequence = [PSCustomObject]@{ phase=$Phase; order=0; dependencies=$Deps; conflictsWith=@(); priority=1 }
              result   = [PSCustomObject]@{ status=$null; reason=$null }
              rulesApplied = @()
          }
      }
  }

  Describe 'New-SequencePlan' {
      It 'returns plan with planHash (sha256: prefix)' {
          $a1 = New-TestAction 'ACT-001'
          $plan = New-SequencePlan -Actions @($a1) -RulesVersion '1.0.0'
          $plan.planHash | Should -Match '^sha256:[a-f0-9]{64}$'
      }

      It 'embeds rulesVersion' {
          $plan = New-SequencePlan -Actions @(New-TestAction 'ACT-001') -RulesVersion '1.0.0'
          $plan.rulesVersion | Should -Be '1.0.0'
      }

      It 'assigns sequential order within each phase' {
          $a1 = New-TestAction 'ACT-001' -Phase 1
          $a2 = New-TestAction 'ACT-002' -Phase 2
          $a3 = New-TestAction 'ACT-003' -Phase 2
          $plan = New-SequencePlan -Actions @($a1, $a2, $a3) -RulesVersion '1.0.0'
          $phase2 = $plan.actions | Where-Object { $_.sequence.phase -eq 2 }
          $orders = @($phase2 | Sort-Object { $_.sequence.order } | Select-Object -ExpandProperty sequence).order
          $orders[0] | Should -Be 1
          $orders[1] | Should -Be 2
      }

      It 'topological order: dependency action precedes dependent action' {
          $a1 = New-TestAction 'ACT-001' -Phase 1
          $a2 = New-TestAction 'ACT-002' -Phase 2 -Deps @('ACT-001')
          $plan = New-SequencePlan -Actions @($a2, $a1) -RulesVersion '1.0.0'   # intentional wrong order
          $ids = $plan.actions | Select-Object -ExpandProperty action | Select-Object -ExpandProperty actionId
          $ids.IndexOf('ACT-001') | Should -BeLessThan $ids.IndexOf('ACT-002')
      }

      It 'is deterministic — same input produces identical planHash' {
          $a1 = New-TestAction 'ACT-001' -Phase 1
          $a2 = New-TestAction 'ACT-002' -Phase 2 -Deps @('ACT-001')
          $p1 = New-SequencePlan -Actions @($a1, $a2) -RulesVersion '1.0.0'
          $p2 = New-SequencePlan -Actions @($a1, $a2) -RulesVersion '1.0.0'
          $p1.planHash | Should -Be $p2.planHash
      }

      It 'summary contains total, blocked, highRisk counts' {
          $a1 = New-TestAction 'ACT-001'
          $a2 = New-TestAction 'ACT-002'
          $a2.result.status = 'Blocked'
          $plan = New-SequencePlan -Actions @($a1, $a2) -RulesVersion '1.0.0'
          $plan.summary.total   | Should -Be 2
          $plan.summary.blocked | Should -Be 1
      }

      It 'throws on circular dependency' {
          $a1 = New-TestAction 'ACT-001' -Deps @('ACT-002')
          $a2 = New-TestAction 'ACT-002' -Deps @('ACT-001')
          { New-SequencePlan -Actions @($a1, $a2) -RulesVersion '1.0.0' } |
              Should -Throw '*CircularDependency*'
      }
  }

  Describe 'Get-PlanHash' {
      It 'returns different hash when action list changes' {
          $a1 = New-TestAction 'ACT-001'
          $a2 = New-TestAction 'ACT-002'
          $h1 = Get-PlanHash -Actions @($a1)
          $h2 = Get-PlanHash -Actions @($a1, $a2)
          $h1 | Should -Not -Be $h2
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\sequencing\Planner.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Planner.ps1**

  Replace stub at `src/Private/sequencing/Planner.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-PlanHash {
      [CmdletBinding()]
      param([Parameter(Mandatory)] $Actions)

      # Normalize: sort by actionId for determinism, then hash.
      # Include all fields that affect plan behavior — two plans with different
      # providers/endpoints/bodies/priorities MUST produce different hashes.
      $normalized = $Actions |
          Sort-Object { $_.action.actionId } |
          ForEach-Object {
              $bodyNorm = if ($_.request.bodyHash) { $_.request.bodyHash } else { 'null' }
              "$($_.action.actionId)|$($_.action.provider)|$($_.sequence.phase)|$($_.sequence.order)|" +
              "$($_.sequence.dependencies -join ',')|$($_.sequence.conflictsWith -join ',')|" +
              "$($_.sequence.priority)|$($_.request.endpoint)|$($_.request.method)|$bodyNorm|$($_.result.status)"
          }
      $canonical = $normalized -join "`n"
      $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
      $sha   = [System.Security.Cryptography.SHA256]::Create()
      'sha256:' + ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').ToLower()
  }

  function New-SequencePlan {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $Actions,
          [Parameter(Mandatory)][string] $RulesVersion
      )

      # Build and validate DAG (throws CircularDependency if cycle found)
      $graph    = Build-ActionGraph -Actions $Actions
      Test-AcyclicGraph -Graph $graph

      # Topological sort (guaranteed cycle-free at this point)
      $topoOrder = Get-TopologicalOrder -Graph $graph

      # Assign sequence numbers within each phase
      # Phase grouping comes from action.sequence.phase; topo order determines order within phase
      $phaseCounters = @{}
      $orderedActions = [System.Collections.Generic.List[object]]::new()

      foreach ($actionId in $topoOrder) {
          $action = $Actions | Where-Object { $_.action.actionId -eq $actionId } | Select-Object -First 1
          if (-not $action) { continue }

          $phase = $action.sequence.phase
          if (-not $phaseCounters.ContainsKey($phase)) { $phaseCounters[$phase] = 0 }
          $phaseCounters[$phase]++
          $action.sequence.order = $phaseCounters[$phase]

          $orderedActions.Add($action) | Out-Null
      }

      $actionsArray = $orderedActions.ToArray()
      $planHash     = Get-PlanHash -Actions $actionsArray

      $blockedCount  = @($actionsArray | Where-Object { $_.result.status -eq 'Blocked' }).Count
      $highRiskCount = @($actionsArray | Where-Object {
          $_.sequence.safetyLevel -eq 'High' -and $_.result.status -ne 'Blocked'
      }).Count

      return [PSCustomObject]@{
          planHash     = $planHash
          rulesVersion = $RulesVersion
          createdAtUtc = [System.DateTime]::UtcNow.ToString('o')
          phases       = ($actionsArray | Select-Object -ExpandProperty sequence | Select-Object -ExpandProperty phase | Sort-Object -Unique).Count
          actions      = $actionsArray
          summary      = [PSCustomObject]@{
              total    = $actionsArray.Count
              blocked  = $blockedCount
              highRisk = $highRiskCount
          }
      }
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\sequencing\Planner.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\sequencing\Planner.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/sequencing/Planner.ps1 tests/sequencing/Planner.Tests.ps1
  git commit -m "feat: add Planner (topo sort, phase order assignment, SHA-256 planHash, determinism guaranteed)"
  ```

---

### Task 20: Executor

**Files:**
- Create: `src/Private/sequencing/Executor.ps1`
- Create: `tests/sequencing/Executor.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/sequencing/Executor.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/policy/Test-WriteAllowed.ps1"
      . "$PSScriptRoot/../../src/Private/sequencing/ActionGraphBuilder.ps1"
      . "$PSScriptRoot/../../src/Private/sequencing/Planner.ps1"
      . "$PSScriptRoot/../../src/Private/sequencing/Executor.ps1"

      function New-PlanAction {
          param([string]$Id, [string]$Status = $null, [int]$Phase = 2, [string]$Provider = 'Graph')
          [PSCustomObject]@{
              action    = [PSCustomObject]@{ actionId=$Id; provider=$Provider; target='test'; operation='POST' }
              sequence  = [PSCustomObject]@{ phase=$Phase; order=1; dependencies=@(); conflictsWith=@(); priority=1; safetyLevel='High' }
              execution = [PSCustomObject]@{
                  whatIf=$false; confirmed=$false; writeAllowed=$false; executionMode=$null
                  gates=[PSCustomObject]@{ modeRemediate=$false; delegatedAuth=$false; notWhatIf=$false; policyCheckPassed=$false }
              }
              result    = [PSCustomObject]@{ status=$Status; reason=$null; httpStatusCode=$null; retries=0; retryDelaysMs=@(); durationMs=0 }
              rulesApplied = @()
              request   = [PSCustomObject]@{ endpoint='/test'; method='POST'; cmdletName=$null }
              state     = [PSCustomObject]@{ beforeRef=$null; afterRef=$null }
              error     = $null
          }
      }

      $writeAllowedParams = @{ Mode='Remediate'; AuthMethod='Delegated'; WhatIf=$false; Edition='Premium' }
      $mockGw = [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Delegated'; RunId='r1'; Connected=$true }
  }

  Describe 'Invoke-ExecutePlan — drift guard' {
      It 'throws PlanIntegrityViolation when planHash does not match recomputed hash' {
          $action = New-PlanAction 'ACT-001'
          $plan   = [PSCustomObject]@{
              planHash = 'sha256:wrong'
              actions  = @($action)
          }
          $mockRemediator = { param($action, $gw, $exgw) $action }
          {
              Invoke-ExecutePlan -Plan $plan -GraphGateway $mockGw -WriteAllowedParams $writeAllowedParams `
                  -RemediatorScript $mockRemediator -WhatIf $false
          } | Should -Throw '*PlanIntegrityViolation*'
      }
  }

  Describe 'Invoke-ExecutePlan — Blocked actions skipped' {
      It 'skips Blocked action without calling remediator, logs status=Blocked' {
          $a1 = New-PlanAction 'ACT-001' -Status 'Blocked'
          $plan = New-SequencePlan -Actions @($a1) -RulesVersion '1.0.0'

          $remediatorCalls = 0
          $mockRemediator = { param($action, $gw, $exgw) $remediatorCalls++; $action }

          $results = Invoke-ExecutePlan -Plan $plan -GraphGateway $mockGw -WriteAllowedParams $writeAllowedParams `
              -RemediatorScript $mockRemediator -WhatIf $false

          $remediatorCalls | Should -Be 0
          $results[0].result.status | Should -Be 'Blocked'
      }
  }

  Describe 'Invoke-ExecutePlan — WhatIf mode' {
      It 'stamps executionMode=WhatIf and does not call remediator when WhatIf=true' {
          $a1 = New-PlanAction 'ACT-001'
          $plan = New-SequencePlan -Actions @($a1) -RulesVersion '1.0.0'

          $remediatorCalls = 0
          $mockRemediator = { param($action, $gw, $exgw) $remediatorCalls++ }

          $results = Invoke-ExecutePlan -Plan $plan -GraphGateway $mockGw -WriteAllowedParams $writeAllowedParams `
              -RemediatorScript $mockRemediator -WhatIf $true

          $remediatorCalls | Should -Be 0
          $results[0].execution.executionMode | Should -Be 'WhatIf'
      }
  }

  Describe 'Invoke-ExecutePlan — write gate blocks when not all conditions met' {
      It 'stamps action Blocked with WriteGateFailed when Test-WriteAllowed returns false' {
          $a1  = New-PlanAction 'ACT-001'
          $plan = New-SequencePlan -Actions @($a1) -RulesVersion '1.0.0'

          $litePlan = @{ Mode='Assess'; AuthMethod='Certificate'; WhatIf=$false; Edition='Lite' }
          $mockRemediator = { param($action, $gw, $exgw) $action }

          $results = Invoke-ExecutePlan -Plan $plan -GraphGateway $mockGw -WriteAllowedParams $litePlan `
              -RemediatorScript $mockRemediator -WhatIf $false

          $results[0].result.status | Should -Be 'Blocked'
          $results[0].result.reason | Should -Be 'WriteGateFailed'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\sequencing\Executor.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Executor.ps1**

  Create `src/Private/sequencing/Executor.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Invoke-ExecutePlan {
      [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
      param(
          [Parameter(Mandatory)] $Plan,
          [Parameter(Mandatory)] $GraphGateway,
          [Parameter()] $ExchangeGateway = $null,
          [Parameter(Mandatory)] [hashtable] $WriteAllowedParams,
          [Parameter(Mandatory)] [scriptblock] $RemediatorScript,
          [Parameter(Mandatory)] [bool] $WhatIf
      )

      # Drift guard: recompute planHash from current action state
      $recomputed = Get-PlanHash -Actions $Plan.actions
      if ($recomputed -ne $Plan.planHash) {
          throw [System.InvalidOperationException]::new(
              "PlanIntegrityViolation: planHash mismatch. Stored=$($Plan.planHash) Recomputed=$recomputed. Plan may have been modified after creation."
          )
      }

      $writeAllowed = Test-WriteAllowed @WriteAllowedParams
      $results      = [System.Collections.Generic.List[object]]::new()

      # Build a lookup of completed actions by actionId for dependency enforcement
      $executedResults = @{}

      foreach ($action in $Plan.actions) {
          # Already-Blocked actions (from rules engine): skip, preserve status
          if ($action.result.status -eq 'Blocked') {
              $action.execution.executionMode = 'Execute'
              $executedResults[$action.action.actionId] = $action
              $results.Add($action) | Out-Null
              continue
          }

          # Dependency status enforcement: if any dependency did not succeed, block this action
          $failedDep = $action.sequence.dependencies | Where-Object {
              $dep = $executedResults[$_]
              -not $dep -or $dep.result.status -ne 'Success'
          } | Select-Object -First 1
          if ($failedDep) {
              $action.result.status  = 'Blocked'
              $action.result.reason  = "DependencyFailed: $failedDep"
              $action.execution.executionMode = 'Execute'
              $executedResults[$action.action.actionId] = $action
              $results.Add($action) | Out-Null
              continue
          }

          # WhatIf mode: stamp and continue, no execution
          if ($WhatIf) {
              $action.execution.executionMode = 'WhatIf'
              $action.result.status  = 'Blocked'
              $action.result.reason  = 'WhatIf'
              $executedResults[$action.action.actionId] = $action
              $results.Add($action) | Out-Null
              continue
          }

          # Write gate
          if (-not $writeAllowed) {
              $action.execution.writeAllowed  = $false
              $action.execution.executionMode = 'Execute'
              $action.result.status  = 'Blocked'
              $action.result.reason  = 'WriteGateFailed'
              $executedResults[$action.action.actionId] = $action
              $results.Add($action) | Out-Null
              continue
          }

          # Stamp gate values
          $action.execution.writeAllowed  = $true
          $action.execution.executionMode = 'Execute'
          $action.execution.gates.modeRemediate     = ($WriteAllowedParams.Mode -eq 'Remediate')
          $action.execution.gates.delegatedAuth      = ($WriteAllowedParams.AuthMethod -eq 'Delegated')
          $action.execution.gates.notWhatIf          = (-not $WhatIf)
          $action.execution.gates.policyCheckPassed  = $writeAllowed

          # Dispatch to remediator via scriptblock (allows injection in tests)
          try {
              $action = & $RemediatorScript $action $GraphGateway $ExchangeGateway
          } catch {
              # Remediator sets error.isCritical before re-throwing for critical errors.
              # Check structured field first; fall back to regex only for bare exceptions
              # that bypass Remediator's own catch (e.g., scriptblock setup failures).
              $isCritical = if ($null -ne $action.error) { [bool]$action.error.isCritical } `
                            else { $_.Exception.Message -match 'TenantPin|PlanIntegrity|WriteGate|CircularDependency' }
              if ($isCritical) { throw }

              # Non-critical: Remediator already stamped action.error for its own caught errors.
              # Only set here if Remediator didn't reach its catch (bare exception path).
              if (-not $action.result.status) {
                  $action.result.status = 'Failed'
                  $action.result.reason = 'Exception'
                  $action.error = [PSCustomObject]@{
                      type       = $action.action.provider
                      code       = 'UnhandledException'
                      message    = $_.Exception.Message
                      isCritical = $false
                  }
              }
          }

          $executedResults[$action.action.actionId] = $action
          $results.Add($action) | Out-Null
      }

      return $results.ToArray()
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\sequencing\Executor.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\sequencing\Executor.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/sequencing/Executor.ps1 tests/sequencing/Executor.Tests.ps1
  git commit -m "feat: add Executor (drift guard planHash, WhatIf stamp, write-gate block, critical vs non-critical failure)"
  ```

---

### Task 21: Remediator

**Files:**
- Modify: `src/Private/Remediator.ps1` (replace stub)
- Create: `tests/Remediator.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/Remediator.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../src/Private/policy/Test-WriteAllowed.ps1"
      . "$PSScriptRoot/../src/Private/Remediator.ps1"

      function New-GraphAction {
          param([string]$Id = 'ACT-001')
          [PSCustomObject]@{
              action    = [PSCustomObject]@{ actionId=$Id; provider='Graph'; target='test resource'; operation='POST' }
              execution = [PSCustomObject]@{ writeAllowed=$true; confirmed=$false; executionMode='Execute'; whatIf=$false
                            gates=[PSCustomObject]@{ modeRemediate=$true; delegatedAuth=$true; notWhatIf=$true; policyCheckPassed=$true } }
              request   = [PSCustomObject]@{ endpoint='/identity/conditionalAccess/policies'; method='POST'; body=$null
                            beforeEndpoint='/identity/conditionalAccess/policies'; afterEndpoint='/identity/conditionalAccess/policies'
                            cmdletName=$null; writeCmdletName=$null; parameters=$null; writeParameters=$null }
              result    = [PSCustomObject]@{ status=$null; reason=$null; httpStatusCode=$null; retries=0; retryDelaysMs=@(); durationMs=0 }
              state     = [PSCustomObject]@{ beforeRef=$null; afterRef=$null; diffSummary=$null }
              error     = $null
          }
      }

      function New-ExchangeAction {
          param([string]$Id = 'ACT-002')
          [PSCustomObject]@{
              action    = [PSCustomObject]@{ actionId=$Id; provider='Exchange'; target='SMTP Auth'; operation='SET' }
              execution = [PSCustomObject]@{ writeAllowed=$true; confirmed=$false; executionMode='Execute'; whatIf=$false
                            gates=[PSCustomObject]@{ modeRemediate=$true; delegatedAuth=$true; notWhatIf=$true; policyCheckPassed=$true } }
              request   = [PSCustomObject]@{ endpoint=$null; method=$null; body=$null; beforeEndpoint=$null; afterEndpoint=$null
                            cmdletName='Get-TransportConfig'; parameters=@{}
                            writeCmdletName='Set-TransportConfig'; writeParameters=@{ SmtpClientAuthenticationDisabled=$true } }
              result    = [PSCustomObject]@{ status=$null; reason=$null; httpStatusCode=$null; retries=0; retryDelaysMs=@(); durationMs=0 }
              state     = [PSCustomObject]@{ beforeRef=$null; afterRef=$null; diffSummary=$null }
              error     = $null
          }
      }

      $mockGraphGw = [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Delegated'; RunId='r1'; Connected=$true }
      $mockExchGw  = [PSCustomObject]@{ PSTypeName='Metis.ExchangeGateway'; AuthMethod='Delegated'; Connected=$true }
  }

  Describe 'Invoke-RemediationAction — Graph routing' {
      It 'calls Invoke-GraphRequest for provider=Graph action' {
          $action = New-GraphAction
          $graphCalled = $false

          Mock Invoke-GraphRequest {
              $script:graphCalled = $true
              [PSCustomObject]@{ Result=@{}; HttpStatusCode=200; Retries=0; RetryDelaysMs=@() }
          }

          $result = Invoke-RemediationAction -Action $action -GraphGateway $mockGraphGw -ExchangeGateway $null
          $script:graphCalled | Should -BeTrue
          $result.result.status | Should -Be 'Success'
      }

      It 'stamps durationMs on success' {
          $action = New-GraphAction
          Mock Invoke-GraphRequest { [PSCustomObject]@{ Result=@{}; HttpStatusCode=201; Retries=0; RetryDelaysMs=@() } }
          $result = Invoke-RemediationAction -Action $action -GraphGateway $mockGraphGw -ExchangeGateway $null
          $result.result.durationMs | Should -BeGreaterOrEqual 0
      }
  }

  Describe 'Invoke-RemediationAction — Exchange routing' {
      It 'calls Invoke-ExchangeRequest for provider=Exchange action' {
          $action = New-ExchangeAction
          $exchCalled = $false

          Mock Invoke-ExchangeRequest {
              $script:exchCalled = $true
              [PSCustomObject]@{ Result=@{}; Retries=0; RetryDelaysMs=@() }
          }

          $result = Invoke-RemediationAction -Action $action -GraphGateway $mockGraphGw -ExchangeGateway $mockExchGw
          $script:exchCalled | Should -BeTrue
          $result.result.status | Should -Be 'Success'
      }

      It 'throws if provider=Exchange but ExchangeGateway is null' {
          $action = New-ExchangeAction
          { Invoke-RemediationAction -Action $action -GraphGateway $mockGraphGw -ExchangeGateway $null } |
              Should -Throw '*ExchangeGateway required*'
      }
  }

  Describe 'Invoke-RemediationAction — state snapshots' {
      It 'sets state.beforeRef and state.afterRef after successful execution' {
          $action = New-GraphAction
          Mock Invoke-GraphRequest { [PSCustomObject]@{ Result=@{ id='pol-001' }; HttpStatusCode=201; Retries=0; RetryDelaysMs=@() } }
          $result = Invoke-RemediationAction -Action $action -GraphGateway $mockGraphGw -ExchangeGateway $null `
              -RunFolder 'C:\tmp' -CheckId 'CA-001' -FindingId 'FIND-001'
          $result.state.beforeRef | Should -Match 'state://before'
          $result.state.afterRef  | Should -Match 'state://after'
      }
  }

  Describe 'Invoke-RemediationAction — error handling' {
      It 'sets result.status=Failed and populates error when write throws' {
          $action = New-GraphAction
          Mock Invoke-GraphRequest { throw 'API error 403' }
          $result = Invoke-RemediationAction -Action $action -GraphGateway $mockGraphGw -ExchangeGateway $null
          $result.result.status        | Should -Be 'Failed'
          $result.error.message        | Should -Match 'API error'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\Remediator.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Remediator.ps1**

  Replace stub at `src/Private/Remediator.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Invoke-RemediationAction {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $Action,
          [Parameter(Mandatory)] $GraphGateway,
          [Parameter()] $ExchangeGateway = $null,
          [Parameter()][string] $RunFolder  = $null,
          [Parameter()][string] $CheckId    = $null,
          [Parameter()][string] $FindingId  = $null
      )

      $provider = $Action.action.provider
      $start    = Get-Date

      try {
          if ($provider -eq 'Exchange') {
              if (-not $ExchangeGateway) {
                  throw "ExchangeGateway required but not provided (provider=Exchange, action=$($Action.action.actionId))."
              }

              # Before snapshot
              # ?? not supported in Windows PowerShell 5.1; use explicit if/else for null coalescing.
              $readParams  = if ($null -ne $Action.request.parameters)      { $Action.request.parameters }      else { @{} }
              $writeParams = if ($null -ne $Action.request.writeParameters) { $Action.request.writeParameters } else { @{} }

              $before = Invoke-ExchangeRequest -ExchangeGateway $ExchangeGateway `
                  -CmdletName   $Action.request.cmdletName `
                  -Parameters   $readParams `
                  -OperationType 'Read' -Caller 'Remediator'

              # Write
              $resp = Invoke-ExchangeRequest -ExchangeGateway $ExchangeGateway `
                  -CmdletName   $Action.request.writeCmdletName `
                  -Parameters   $writeParams `
                  -OperationType 'Write' -Caller 'Remediator'

              # After snapshot
              $after = Invoke-ExchangeRequest -ExchangeGateway $ExchangeGateway `
                  -CmdletName   $Action.request.cmdletName `
                  -Parameters   $readParams `
                  -OperationType 'Read' -Caller 'Remediator'

              $Action.result = [PSCustomObject]@{
                  status         = 'Success'
                  reason         = $null
                  httpStatusCode = $null
                  retries        = $resp.Retries
                  retryDelaysMs  = $resp.RetryDelaysMs
                  durationMs     = [int]((Get-Date) - $start).TotalMilliseconds
              }

          } else {
              # Graph path
              $before = Invoke-GraphRequest -GraphGateway $GraphGateway `
                  -Uri $Action.request.beforeEndpoint -Method 'GET' `
                  -OperationType 'Read' -Caller 'Remediator'

              $resp = Invoke-GraphRequest -GraphGateway $GraphGateway `
                  -Uri $Action.request.endpoint -Method $Action.request.method `
                  -Body $Action.request.body `
                  -OperationType 'Write' -Caller 'Remediator'

              $after = Invoke-GraphRequest -GraphGateway $GraphGateway `
                  -Uri $Action.request.afterEndpoint -Method 'GET' `
                  -OperationType 'Read' -Caller 'Remediator'

              $Action.result = [PSCustomObject]@{
                  status         = 'Success'
                  reason         = $null
                  httpStatusCode = $resp.HttpStatusCode
                  retries        = $resp.Retries
                  retryDelaysMs  = $resp.RetryDelaysMs
                  durationMs     = [int]((Get-Date) - $start).TotalMilliseconds
              }
          }

          # State refs (path convention: state://before/<checkId>/<findingId>.json)
          if ($CheckId -and $FindingId) {
              $Action.state.beforeRef = "state://before/$CheckId/$FindingId.json"
              $Action.state.afterRef  = "state://after/$CheckId/$FindingId.json"

              # Persist snapshots to RunFolder if provided
              if ($RunFolder) {
                  $beforeDir = Join-Path $RunFolder "state\before\$CheckId"
                  $afterDir  = Join-Path $RunFolder "state\after\$CheckId"
                  New-Item -ItemType Directory -Path $beforeDir, $afterDir -Force | Out-Null
                  $before.Result | ConvertTo-Json -Depth 20 |
                      Set-Content (Join-Path $beforeDir "$FindingId.json") -Encoding UTF8
                  $after.Result  | ConvertTo-Json -Depth 20 |
                      Set-Content (Join-Path $afterDir  "$FindingId.json") -Encoding UTF8
              }
          }

      } catch {
          $errMsg = $_.Exception.Message
          # Classify before stamping: infrastructure/policy violations halt the run;
          # API errors (4xx, throttle, etc.) are non-critical — return Failed action.
          $isCritical = ($errMsg -match 'TenantPin|PlanIntegrity|CircularDependency|ExchangeGateway required')

          $Action.result = [PSCustomObject]@{
              status         = 'Failed'
              reason         = 'Exception'
              httpStatusCode = $null
              retries        = 0
              retryDelaysMs  = @()
              durationMs     = [int]((Get-Date) - $start).TotalMilliseconds
          }
          $Action.error = [PSCustomObject]@{
              type       = $provider
              code       = 'UnhandledException'
              message    = $errMsg
              isCritical = $isCritical
              requestId  = $null
              nodes      = @()
          }
          # Only re-throw for critical errors; non-critical returns action with Failed status.
          if ($isCritical) { throw }
      }

      return $Action
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\Remediator.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\Remediator.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/Remediator.ps1 tests/Remediator.Tests.ps1
  git commit -m "feat: add Remediator (Graph/Exchange routing via action.provider, before/after snapshots, state refs)"
  ```

---

### Task 22: Invoke-Remediation — Check-ConditionalAccess

**Files:**
- Modify: `src/Private/checks/Check-ConditionalAccess.ps1` (add `Invoke-Remediation`)
- Modify: `tests/checks/Check-ConditionalAccess.Tests.ps1` (add remediation tests)

- [ ] **Step 1: Write failing tests — append to Check-ConditionalAccess.Tests.ps1**

  ```powershell
  Describe 'Invoke-Remediation — CA-001' {
      BeforeAll {
          . "$PSScriptRoot/../../src/Private/models/RemediationAction.schema.ps1"
          . "$PSScriptRoot/../../src/Private/checks/Check-ConditionalAccess.ps1"

          $mockGw = [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Delegated'; RunId='r1'; Connected=$true; TenantId='tid' }
          $mockPSCmdlet = [PSCustomObject]@{}
          Add-Member -InputObject $mockPSCmdlet -MemberType ScriptMethod -Name ShouldProcess -Value { $true }

          $failFinding = [PSCustomObject]@{
              id='FIND-CA-001-ABCD'; checkId='CA-001'; status='Fail'; severity='Critical'
              title='Legacy Auth Not Blocked'; evidence=@{ legacyAuthPolicyFound=$false }
          }
      }

      It 'returns RemediationAction array for a Fail finding' {
          $actions = Invoke-Remediation -GraphGateway $mockGw -Finding $failFinding -PSCmdlet $mockPSCmdlet
          $actions | Should -Not -BeNullOrEmpty
          $actions[0].schemaVersion | Should -Be '1.0'
      }

      It 'action.provider is Graph' {
          $actions = Invoke-Remediation -GraphGateway $mockGw -Finding $failFinding -PSCmdlet $mockPSCmdlet
          $actions[0].action.provider | Should -Be 'Graph'
      }

      It 'returns empty array for a Pass finding' {
          $passFinding = [PSCustomObject]@{ status='Pass'; checkId='CA-001'; id='FIND-001'; evidence=@{} }
          $actions = Invoke-Remediation -GraphGateway $mockGw -Finding $passFinding -PSCmdlet $mockPSCmdlet
          $actions.Count | Should -Be 0
      }

      It 'action.request.endpoint targets CA policies endpoint' {
          $actions = Invoke-Remediation -GraphGateway $mockGw -Finding $failFinding -PSCmdlet $mockPSCmdlet
          $actions[0].request.endpoint | Should -Match 'conditionalAccess/policies'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-ConditionalAccess.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Add Invoke-Remediation to Check-ConditionalAccess.ps1**

  Append to `src/Private/checks/Check-ConditionalAccess.ps1`:

  ```powershell
  function Invoke-Remediation {
      [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          [Parameter(Mandatory)] $Finding,
          [Parameter(Mandatory)] $PSCmdlet
      )

      $actions = [System.Collections.Generic.List[object]]::new()
      if ($Finding.status -ne 'Fail') { return $actions.ToArray() }

      $tid = $GraphGateway.TenantId
      $tenantMasked = if ($tid -and $tid.Length -ge 8) { "$($tid.Substring(0,4))-...-$($tid.Substring($tid.Length - 4))" } else { '????-...-????' }

      switch -Wildcard ($Finding.title) {
          '*Legacy Auth*' {
              $body = @{
                  displayName   = '[Metis] Block Legacy Authentication'
                  state         = 'enabledForReportingButNotEnforced'   # report-only first
                  conditions    = @{
                      clientAppTypes = @('exchangeActiveSync','other')
                      users          = @{ includeUsers = @('All') }
                  }
                  grantControls = @{ operator='OR'; builtInControls=@('block') }
              }

              $actions.Add((New-RemediationAction `
                  -RunId $GraphGateway.RunId -CheckId 'CA-001' -CheckName 'Check-ConditionalAccess' `
                  -FindingId $Finding.id -ActionId 'ACT-CA-BLOCK-LEGACYAUTH' `
                  -Operation 'POST' -ResourceType 'ConditionalAccessPolicy' -Target 'Block legacy authentication (report-only)' `
                  -Provider 'Graph' -Phase 2 -Order 1 -Priority 2 -TenantIdMasked $tenantMasked `
                  -Endpoint '/identity/conditionalAccess/policies' -HttpMethod 'POST' -Body $body))
          }
          '*MFA*' {
              $body = @{
                  displayName   = '[Metis] Require MFA - All Users'
                  state         = 'enabledForReportingButNotEnforced'
                  conditions    = @{ users = @{ includeUsers = @('All') } }
                  grantControls = @{ operator='OR'; builtInControls=@('mfa') }
              }

              $actions.Add((New-RemediationAction `
                  -RunId $GraphGateway.RunId -CheckId 'CA-001' -CheckName 'Check-ConditionalAccess' `
                  -FindingId $Finding.id -ActionId 'ACT-CA-ENABLE-MFA' `
                  -Operation 'POST' -ResourceType 'ConditionalAccessPolicy' -Target 'Require MFA for all users (report-only)' `
                  -Provider 'Graph' -Phase 2 -Order 2 -Priority 1 `
                  -Dependencies @('ACT-CA-EXCLUDE-BREAKGLASS') -TenantIdMasked $tenantMasked `
                  -Endpoint '/identity/conditionalAccess/policies' -HttpMethod 'POST' -Body $body))
          }
      }

      return $actions.ToArray()
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-ConditionalAccess.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-ConditionalAccess.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/checks/Check-ConditionalAccess.ps1 tests/checks/Check-ConditionalAccess.Tests.ps1
  git commit -m "feat: add CA Invoke-Remediation (legacy auth + MFA actions, report-only first, dependency wiring)"
  ```

---

### Task 23: Invoke-Remediation — Check-PIM

**Files:**
- Modify: `src/Private/checks/Check-PIM.ps1` (add `Invoke-Remediation`)
- Modify: `tests/checks/Check-PIM.Tests.ps1` (add remediation tests)

- [ ] **Step 1: Write failing tests — append to Check-PIM.Tests.ps1**

  ```powershell
  Describe 'Invoke-Remediation — PIM-001' {
      BeforeAll {
          . "$PSScriptRoot/../../src/Private/models/RemediationAction.schema.ps1"
          . "$PSScriptRoot/../../src/Private/checks/Check-PIM.ps1"

          $mockGw = [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Delegated'; RunId='r1'; Connected=$true; TenantId='aaaa0000-0000-0000-0000-000011111111' }
          $mockPSCmdlet = [PSCustomObject]@{}
          Add-Member -InputObject $mockPSCmdlet -MemberType ScriptMethod -Name ShouldProcess -Value { $true }

          $standingFinding = [PSCustomObject]@{
              id='FIND-PIM-001'; checkId='PIM-001'; status='Fail'
              title='Standing Active Assignments Found for High-Privilege Roles'
              evidence=@{ standingHighRiskCount=2; standingGlobalAdminCount=1; eligibleScheduleCount=0 }
          }
      }

      It 'returns RemediationAction[] for standing active assignments finding' {
          $actions = Invoke-Remediation -GraphGateway $mockGw -Finding $standingFinding -PSCmdlet $mockPSCmdlet
          $actions.Count | Should -BeGreaterThan 0
      }

      It 'action.provider is Graph (PIM uses Graph API)' {
          $actions = Invoke-Remediation -GraphGateway $mockGw -Finding $standingFinding -PSCmdlet $mockPSCmdlet
          $actions[0].action.provider | Should -Be 'Graph'
      }

      It 'action is in Phase 3 (Privilege Controls)' {
          $actions = Invoke-Remediation -GraphGateway $mockGw -Finding $standingFinding -PSCmdlet $mockPSCmdlet
          $actions[0].sequence.phase | Should -Be 3
      }

      It 'returns empty for Pass finding' {
          $pass = [PSCustomObject]@{ status='Pass'; checkId='PIM-001'; id='FIND-002'; evidence=@{} }
          (Invoke-Remediation -GraphGateway $mockGw -Finding $pass -PSCmdlet $mockPSCmdlet).Count | Should -Be 0
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-PIM.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Add Invoke-Remediation to Check-PIM.ps1**

  Append to `src/Private/checks/Check-PIM.ps1`:

  ```powershell
  function Invoke-Remediation {
      [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          [Parameter(Mandatory)] $Finding,
          [Parameter(Mandatory)] $PSCmdlet
      )

      $actions = [System.Collections.Generic.List[object]]::new()
      if ($Finding.status -ne 'Fail') { return $actions.ToArray() }

      $tid = $GraphGateway.TenantId
      $tenantMasked = if ($tid -and $tid.Length -ge 8) { "$($tid.Substring(0,4))-...-$($tid.Substring($tid.Length - 4))" } else { '????-...-????' }

      switch -Wildcard ($Finding.title) {
          '*Standing Active*' {
              # Configure eligible role settings via PIM roleManagementPolicies
              # IMPORTANT: This action converts SETTINGS only (MFA on activation, approval, time limit)
              # It does NOT remove active role assignments — that requires explicit operator review per spec.
              $actions.Add((New-RemediationAction `
                  -RunId $GraphGateway.RunId -CheckId 'PIM-001' -CheckName 'Check-PIM' `
                  -FindingId $Finding.id -ActionId 'ACT-PIM-CONFIGURE-ROLE-SETTINGS' `
                  -Operation 'PATCH' -ResourceType 'RoleManagementPolicy' `
                  -Target 'Configure PIM role settings (MFA on activation, approval, 8h limit)' `
                  -Provider 'Graph' -Phase 3 -Order 1 -Priority 2 -TenantIdMasked $tenantMasked `
                  -Endpoint '/policies/roleManagementPolicies' -HttpMethod 'PATCH' `
                  -Body @{
                      rules = @(
                          @{ id='Enablement_EndUser_Assignment'; enabledRules=@('MultiFactorAuthentication','Justification') }
                          @{ id='Expiration_EndUser_Assignment'; maximumDuration='PT8H'; isExpirationRequired=$true }
                      )
                  }))
          }
          '*JIT*' {
              $actions.Add((New-RemediationAction `
                  -RunId $GraphGateway.RunId -CheckId 'PIM-001' -CheckName 'Check-PIM' `
                  -FindingId $Finding.id -ActionId 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE' `
                  -Operation 'POST' -ResourceType 'UnifiedRoleEligibilityScheduleRequest' `
                  -Target 'Convert standing active role to eligible (JIT model)' `
                  -Provider 'Graph' -Phase 3 -Order 1 -Priority 3 -TenantIdMasked $tenantMasked `
                  -Endpoint '/roleManagement/directory/roleEligibilityScheduleRequests' -HttpMethod 'POST' `
                  -Body @{ action='adminAssign'; justification='Metis: converting to JIT model' }))
          }
      }

      return $actions.ToArray()
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-PIM.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-PIM.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/checks/Check-PIM.ps1 tests/checks/Check-PIM.Tests.ps1
  git commit -m "feat: add PIM Invoke-Remediation (role settings: MFA on activation, 8h limit; NO role removal per spec)"
  ```

---

### Task 24: Invoke-Remediation — Check-LegacyAuthentication

**Files:**
- Modify: `src/Private/checks/Check-LegacyAuthentication.ps1` (add `Invoke-Remediation`)
- Modify: `tests/checks/Check-LegacyAuthentication.Tests.ps1` (add remediation tests)

- [ ] **Step 1: Write failing tests — append to Check-LegacyAuthentication.Tests.ps1**

  ```powershell
  Describe 'Invoke-Remediation — LA-001' {
      BeforeAll {
          . "$PSScriptRoot/../../src/Private/models/RemediationAction.schema.ps1"
          . "$PSScriptRoot/../../src/Private/checks/Check-LegacyAuthentication.ps1"

          $mockGw = [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Delegated'; RunId='r1'; Connected=$true; TenantId='aaaa0000-0000-0000-0000-000011111111' }
          $mockPSCmdlet = [PSCustomObject]@{}
          Add-Member -InputObject $mockPSCmdlet -MemberType ScriptMethod -Name ShouldProcess -Value { $true }

          $blockFinding = [PSCustomObject]@{
              id='FIND-LA-001'; checkId='LA-001'; status='Fail'
              title='Legacy Authentication Not Blocked at Tenant or CA Level'
              evidence=@{ tenantLevelBlocked=$false; caBlockPolicyPresent=$false; effectivelyBlocked=$false }
          }
      }

      It 'returns RemediationAction[] for Fail finding' {
          $actions = Invoke-Remediation -GraphGateway $mockGw -Finding $blockFinding -PSCmdlet $mockPSCmdlet
          $actions.Count | Should -BeGreaterThan 0
      }

      It 'produces Phase 5 action (Enforcement phase)' {
          $actions = Invoke-Remediation -GraphGateway $mockGw -Finding $blockFinding -PSCmdlet $mockPSCmdlet
          $actions | Where-Object { $_.sequence.phase -eq 5 } | Should -Not -BeNullOrEmpty
      }

      It 'action.provider is Graph' {
          $actions = Invoke-Remediation -GraphGateway $mockGw -Finding $blockFinding -PSCmdlet $mockPSCmdlet
          $actions[0].action.provider | Should -Be 'Graph'
      }

      It 'CA block policy action targets conditionalAccess/policies endpoint' {
          $actions = Invoke-Remediation -GraphGateway $mockGw -Finding $blockFinding -PSCmdlet $mockPSCmdlet
          $caAction = $actions | Where-Object { $_.request.endpoint -match 'conditionalAccess' }
          $caAction | Should -Not -BeNullOrEmpty
      }

      It 'returns empty for Pass finding' {
          $pass = [PSCustomObject]@{ status='Pass'; checkId='LA-001'; id='FIND-002'; evidence=@{} }
          (Invoke-Remediation -GraphGateway $mockGw -Finding $pass -PSCmdlet $mockPSCmdlet).Count | Should -Be 0
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-LegacyAuthentication.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Add Invoke-Remediation to Check-LegacyAuthentication.ps1**

  Append to `src/Private/checks/Check-LegacyAuthentication.ps1`:

  ```powershell
  function Invoke-Remediation {
      [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          [Parameter(Mandatory)] $Finding,
          [Parameter(Mandatory)] $PSCmdlet
      )

      $actions = [System.Collections.Generic.List[object]]::new()
      if ($Finding.status -ne 'Fail') { return $actions.ToArray() }

      $tid = $GraphGateway.TenantId
      $tenantMasked = if ($tid -and $tid.Length -ge 8) { "$($tid.Substring(0,4))-...-$($tid.Substring($tid.Length - 4))" } else { '????-...-????' }

      # Action 1: CA policy blocking legacy auth (report-only first, Phase 5 enforcement)
      $caBody = @{
          displayName   = '[Metis] Block Legacy Authentication'
          state         = 'enabledForReportingButNotEnforced'   # enforce in next run after validation
          conditions    = @{
              clientAppTypes = @('exchangeActiveSync','other')
              users          = @{ includeUsers=@('All') }
          }
          grantControls = @{ operator='OR'; builtInControls=@('block') }
      }

      $actions.Add((New-RemediationAction `
          -RunId $GraphGateway.RunId -CheckId 'LA-001' -CheckName 'Check-LegacyAuthentication' `
          -FindingId $Finding.id -ActionId 'ACT-LA-BLOCK-PROTOCOLS' `
          -Operation 'POST' -ResourceType 'ConditionalAccessPolicy' `
          -Target 'Block legacy authentication via CA policy (report-only → enforce)' `
          -Provider 'Graph' -Phase 5 -Order 1 -Priority 2 `
          -Dependencies @('ACT-CA-BASELINE') -TenantIdMasked $tenantMasked `
          -Endpoint '/identity/conditionalAccess/policies' -HttpMethod 'POST' -Body $caBody))

      # Action 2: Tenant-level block as belt-and-suspenders (authorizationPolicy)
      $policyBody = @{
          blockMsolPowerShell  = $true
      }

      $actions.Add((New-RemediationAction `
          -RunId $GraphGateway.RunId -CheckId 'LA-001' -CheckName 'Check-LegacyAuthentication' `
          -FindingId $Finding.id -ActionId 'ACT-LA-BLOCK-TENANT-LEVEL' `
          -Operation 'PATCH' -ResourceType 'AuthorizationPolicy' `
          -Target 'Block MSOL PowerShell legacy access at tenant level' `
          -Provider 'Graph' -Phase 5 -Order 2 -Priority 1 -TenantIdMasked $tenantMasked `
          -Endpoint '/policies/authorizationPolicy' -HttpMethod 'PATCH' -Body $policyBody))

      return $actions.ToArray()
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-LegacyAuthentication.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-LegacyAuthentication.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/checks/Check-LegacyAuthentication.ps1 tests/checks/Check-LegacyAuthentication.Tests.ps1
  git commit -m "feat: add LegacyAuth Invoke-Remediation (CA block report-only + tenant-level MSOL block, Phase 5)"
  ```

<!-- End tasks-19-24.md -->
