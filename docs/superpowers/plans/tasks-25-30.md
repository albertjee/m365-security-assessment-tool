# M365 Security Assessment Tool — Tasks 25–30

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Prerequisite:** Tasks 1–24 complete (all three planes wired: Detection, Intelligence, Execution).

**Goal:** Wire the full Assess and Remediate pipelines in `Invoke-M365Assessment`; add DLP + CrossCheck rules; write sequencing and end-to-end integration tests.

---

### Task 25: Invoke-M365Assessment — Assess Mode Pipeline

**Files:**
- Modify: `src/Public/Invoke-M365Assessment.ps1` (replace stub)
- Create: `tests/Invoke-M365Assessment.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/Invoke-M365Assessment.Tests.ps1`:

  ```powershell
  BeforeAll {
      # Dot-source the private layer (same order as .psm1)
      $private = "$PSScriptRoot/../src/Private"
      . "$private/models/Finding.schema.ps1"
      . "$private/models/RemediationAction.schema.ps1"
      . "$private/policy/Test-WriteAllowed.ps1"
      . "$private/policy/Test-Environment.ps1"
      . "$private/policy/Test-TenantPin.ps1"
      . "$private/policy/Test-GraphPermissions.ps1"
      . "$private/policy/Test-ExchangePermissions.ps1"
      . "$private/policy/Test-CheckContract.ps1"
      . "$private/GraphGateway.ps1"
      . "$private/ExchangeGateway.ps1"
      . "$private/Auditor.ps1"
      . "$private/Reporter.ps1"
      . "$PSScriptRoot/../templates/report.html.ps1"
      . "$private/sequencing/ActionGraphBuilder.ps1"
      . "$private/sequencing/DependencyRulesEngine.ps1"
      . "$private/sequencing/Planner.ps1"
      . "$private/sequencing/Executor.ps1"
      . "$private/Remediator.ps1"
      . "$PSScriptRoot/../src/Public/Invoke-M365Assessment.ps1"

      $tmpOutput = Join-Path ([System.IO.Path]::GetTempPath()) "metis-e2e-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
      New-Item -ItemType Directory -Path $tmpOutput -Force | Out-Null

      $testConfig = @{
          TenantId              = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
          AppId                 = 'app-001'
          Mode                  = 'Assess'
          AuthMethod            = 'Certificate'
          CertificateThumbprint = 'DEADBEEF'
          Edition               = 'Lite'
          OutputPath            = $tmpOutput
          EnabledChecks         = @()
          Organization          = 'contoso.onmicrosoft.com'
      }
  }

  AfterAll { Remove-Item $tmpOutput -Recurse -Force -ErrorAction SilentlyContinue }

  Describe 'Invoke-M365Assessment — Assess mode' {
      BeforeAll {
          Mock Connect-GraphGateway { param($GraphGateway) $GraphGateway.Connected = $true; $GraphGateway }
          Mock Disconnect-GraphGateway { }
          Mock Test-TenantPin { [PSCustomObject]@{ Match=$true; MismatchReason=$null; TokenTenantId='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'; OrganizationTenantId='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' } }
          Mock Test-Environment { [PSCustomObject]@{ IsValid=$true; Failures=@() } }
          Mock Test-GraphPermissions { [PSCustomObject]@{ IsValid=$true; Missing=@() } }
          Mock Invoke-Audit { @() }   # no checks to run in this unit test
          Mock Get-MgContext { [PSCustomObject]@{ Scopes=@('Policy.Read.All'); AccessToken='fake' } }
      }

      It 'returns a result object with RunId' {
          $result = Invoke-M365Assessment @testConfig
          $result.RunId | Should -Not -BeNullOrEmpty
      }

      It 'creates output folder for the run' {
          $result = Invoke-M365Assessment @testConfig
          Test-Path $result.OutputFolder | Should -BeTrue
      }

      It 'writes findings.json to output folder' {
          $result = Invoke-M365Assessment @testConfig
          Join-Path $result.OutputFolder 'findings.json' | Should -Exist
      }

      It 'writes report.html to output folder' {
          $result = Invoke-M365Assessment @testConfig
          Join-Path $result.OutputFolder 'report.html' | Should -Exist
      }

      It 'writes run.manifest.json to output folder' {
          $result = Invoke-M365Assessment @testConfig
          Join-Path $result.OutputFolder 'run.manifest.json' | Should -Exist
      }

      It 'run.manifest.json has status=Success when no errors' {
          $result = Invoke-M365Assessment @testConfig
          $manifest = Get-Content (Join-Path $result.OutputFolder 'run.manifest.json') | ConvertFrom-Json
          $manifest.execution.status | Should -Be 'Success'
      }

      It 'fails closed when tenant pin mismatches' {
          Mock Test-TenantPin { [PSCustomObject]@{ Match=$false; MismatchReason='TokenTenantMismatch' } }
          { Invoke-M365Assessment @testConfig } | Should -Throw '*TenantPin*'
      }

      It 'fails closed when Test-Environment fails' {
          Mock Test-Environment { [PSCustomObject]@{ IsValid=$false; Failures=@('PowerShell 7.2+ required') } }
          { Invoke-M365Assessment @testConfig } | Should -Throw '*environment*'
      }
  }

  Describe 'Invoke-M365Assessment — RunId format' {
      BeforeAll {
          Mock Connect-GraphGateway { param($gw) $gw.Connected=$true; $gw }
          Mock Disconnect-GraphGateway { }
          Mock Test-TenantPin { [PSCustomObject]@{ Match=$true; MismatchReason=$null } }
          Mock Test-Environment { [PSCustomObject]@{ IsValid=$true; Failures=@() } }
          Mock Test-GraphPermissions { [PSCustomObject]@{ IsValid=$true; Missing=@() } }
          Mock Invoke-Audit { @() }
          Mock Get-MgContext { [PSCustomObject]@{ Scopes=@(); AccessToken='fake' } }
      }

      It 'RunId contains timestamp and short GUID' {
          $result = Invoke-M365Assessment @testConfig
          $result.RunId | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z-[a-f0-9]{8}$'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\Invoke-M365Assessment.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Invoke-M365Assessment.ps1**

  Replace stub at `src/Public/Invoke-M365Assessment.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Invoke-M365Assessment {
      [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
      param(
          [Parameter(Mandatory)][string] $TenantId,
          [Parameter(Mandatory)][string] $AppId,
          [Parameter(Mandatory)][ValidateSet('Assess','Remediate')] [string] $Mode,
          [Parameter(Mandatory)][ValidateSet('Certificate','Secret','Delegated')] [string] $AuthMethod,
          [Parameter()][string] $CertificateThumbprint,
          [Parameter()][System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
          [Parameter()][string] $CertificateFilePath,
          [Parameter()][securestring] $CertificatePassword,
          [Parameter()][string] $ClientSecret,
          [Parameter()][string] $UserPrincipalName,
          [Parameter()][string] $Organization,
          [Parameter(Mandatory)][ValidateSet('Lite','Premium')] [string] $Edition,
          [Parameter()][string] $OutputPath = '.\Output',
          [Parameter()][string[]] $EnabledChecks = @(),
          [Parameter()][switch] $Force
      )

      # --- RunId + output folder ---
      $timestamp  = [System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH-mm-ssZ')
      $shortGuid  = [System.Guid]::NewGuid().ToString('N').Substring(0, 8)
      $runId      = "$timestamp-$shortGuid"
      $runFolder  = Join-Path $OutputPath $runId
      New-Item -ItemType Directory -Path $runFolder -Force | Out-Null

      $checksPath = Join-Path $PSScriptRoot '..\..\src\Private\checks'
      $rulesPath  = Join-Path $PSScriptRoot '..\..\src\Private\sequencing\rules'

      # --- Environment check ---
      $requireExchange = $false  # determined per-check; pre-flight uses $false
      $envResult = Test-Environment -AuthMethod $AuthMethod -RequireExchange $requireExchange
      if (-not $envResult.IsValid) {
          throw "Pre-flight environment check failed: $($envResult.Failures -join '; ')"
      }

      # --- Build GraphGateway ---
      $gwParams = @{
          TenantId  = $TenantId; AppId = $AppId; AuthMethod = $AuthMethod
          RunId     = $runId;    RunFolder = $runFolder
      }
      if ($CertificateThumbprint) { $gwParams['CertificateThumbprint'] = $CertificateThumbprint }
      if ($Certificate)           { $gwParams['Certificate']           = $Certificate }
      if ($CertificateFilePath)   { $gwParams['CertificateFilePath']   = $CertificateFilePath }
      if ($CertificatePassword)   { $gwParams['CertificatePassword']   = $CertificatePassword }
      if ($ClientSecret)          { $gwParams['ClientSecret']          = $ClientSecret }
      if ($UserPrincipalName)     { $gwParams['UserPrincipalName']     = $UserPrincipalName }

      $graphGateway = New-GraphGateway @gwParams
      Connect-GraphGateway -GraphGateway $graphGateway | Out-Null

      $exchangeGateway = $null

      try {
          # --- Tenant pinning (fail-closed) ---
          $pinResult = Test-TenantPin -RequestedTenantId $TenantId -GraphGateway $graphGateway
          if (-not $pinResult.Match) {
              throw "TenantPin mismatch ($($pinResult.MismatchReason)). Requested=$TenantId Token=$($pinResult.TokenTenantId) Org=$($pinResult.OrganizationTenantId)"
          }

          # --- Permission check ---
          $ctx = Get-MgContext
          $grantedScopes = @($ctx.Scopes)
          $permResult = Test-GraphPermissions -RequiredPermissions @('Policy.Read.All') -GrantedScopes $grantedScopes
          if (-not $permResult.IsValid) {
              throw "Missing required Graph permissions: $($permResult.Missing -join ', ')"
          }

          # --- Run checks ---
          $config   = @{ EnabledChecks = $EnabledChecks; Edition = $Edition }
          $findings = Invoke-Audit -GraphGateway $graphGateway -ExchangeGateway $exchangeGateway `
                          -Config $config -ChecksPath $checksPath -RunId $runId

          $runStatus = 'Success'
          $notAssessedCount = @($findings | Where-Object { $_.status -eq 'NotAssessed' }).Count
          if ($notAssessedCount -gt 0) { $runStatus = 'Partial' }

          # --- SequencingEngine (Assess + WhatIf only in Lite; full plan in Premium/Remediate) ---
          $sequencePlan  = $null
          $actionResults = @()

          if ($Mode -eq 'Remediate' -and $Edition -eq 'Premium') {
              # Full sequencing — handled in Task 26 (Remediate mode)
              throw "Remediate mode: see Task 26 implementation."
          }

          # --- Write artifacts ---
          # ?? not available in Windows PowerShell 5.1; use explicit if/else. Git may not be installed.
          $_gitShort  = try { git rev-parse --short HEAD 2>$null } catch { $null }
          $_gitFull   = try { git rev-parse HEAD 2>$null }         catch { $null }
          $_gitBranch = try { git branch --show-current 2>$null }  catch { $null }

          $findingsPath  = Write-FindingsJson  -Findings $findings -OutputFolder $runFolder
          $htmlPath      = Write-HtmlReport -Findings $findings -OutputFolder $runFolder -Metadata @{
              RunId          = $runId
              Mode           = $Mode
              AuthMethod     = $AuthMethod
              TenantIdMasked = if ($TenantId.Length -ge 8) { "$($TenantId.Substring(0,4))-...-$($TenantId.Substring($TenantId.Length-4))" } else { '????-...-????' }
              Timestamp      = [System.DateTime]::UtcNow.ToString('o')
              ModuleVersion  = '0.1.0'
              GitCommit      = if ($_gitShort) { $_gitShort } else { 'unknown' }
          }

          $manifest = @{
              schemaVersion = '1.0'
              tool          = @{
                  name          = 'm365-security-assessment-tool'
                  moduleVersion = '0.1.0'
                  git           = @{
                      commit  = if ($_gitFull)   { $_gitFull }   else { 'unknown' }
                      branch  = if ($_gitBranch) { $_gitBranch } else { 'unknown' }
                      isDirty = $false
                  }
              }
              run           = @{
                  runId        = $runId
                  startedAtUtc = $timestamp
                  endedAtUtc   = [System.DateTime]::UtcNow.ToString('o')
                  mode         = $Mode
                  whatIf       = [bool]$WhatIfPreference
                  enabledChecks = $EnabledChecks
              }
              tenantPinning = @{
                  requestedTenantIdMasked       = if ($TenantId.Length -ge 8) { "$($TenantId.Substring(0,4))-...-$($TenantId.Substring($TenantId.Length-4))" } else { '????-...-????' }
                  resolvedTenantIdFromToken       = $pinResult.TokenTenantId
                  resolvedTenantIdFromOrganization = $pinResult.OrganizationTenantId
                  match                          = $pinResult.Match
                  failClosedOnMismatch           = $true
              }
              auth          = @{
                  authMethod  = $AuthMethod
                  appIdMasked = "$($AppId.Substring(0,[Math]::Min(4,$AppId.Length)))-..."
                  runtimeGrants = @{ scopes = $grantedScopes }
              }
              environment   = @{
                  powerShell = @{ version=$PSVersionTable.PSVersion.ToString(); edition=$PSVersionTable.PSEdition }
                  os         = @{ platform=[System.Environment]::OSVersion.Platform.ToString() }
              }
              execution     = @{
                  status   = $runStatus
                  checks   = @{
                      discovered  = $findings.Count
                      attempted   = $findings.Count
                      succeeded   = @($findings | Where-Object { $_.status -ne 'NotAssessed' }).Count
                      failed      = 0
                      skipped     = $notAssessedCount
                  }
                  findings = @{
                      total         = $findings.Count
                      critical      = @($findings | Where-Object { $_.severity -eq 'Critical' }).Count
                      high          = @($findings | Where-Object { $_.severity -eq 'High' }).Count
                      medium        = @($findings | Where-Object { $_.severity -eq 'Medium' }).Count
                      informational = @($findings | Where-Object { $_.severity -eq 'Informational' }).Count
                  }
              }
              sequencing    = $null
              artifacts     = @(
                  @{ name='findings.json'; path=$findingsPath }
                  @{ name='report.html';   path=$htmlPath }
              )
          }

          $manifestPath = Write-RunManifest -Manifest $manifest -OutputFolder $runFolder -ComputeArtifactHashes

          return [PSCustomObject]@{
              RunId        = $runId
              OutputFolder = $runFolder
              Status       = $runStatus
              Findings     = $findings
              ManifestPath = $manifestPath
          }

      } finally {
          Disconnect-GraphGateway -GraphGateway $graphGateway
          if ($exchangeGateway) { Disconnect-ExchangeGateway -ExchangeGateway $exchangeGateway }
      }
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\Invoke-M365Assessment.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Public\Invoke-M365Assessment.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Public/Invoke-M365Assessment.ps1 tests/Invoke-M365Assessment.Tests.ps1
  git commit -m "feat: wire Invoke-M365Assessment Assess mode (env check, tenant pin, audit, reporter, fail-closed)"
  ```

---

### Task 26: Invoke-M365Assessment — Remediate Mode

**Files:**
- Modify: `src/Public/Invoke-M365Assessment.ps1` (replace stub Remediate block with full implementation)
- Modify: `tests/Invoke-M365Assessment.Tests.ps1` (add Remediate tests)

- [ ] **Step 1: Write failing tests — append Remediate describe block**

  Append to `tests/Invoke-M365Assessment.Tests.ps1`:

  ```powershell
  Describe 'Invoke-M365Assessment — Remediate mode (WhatIf)' {
      BeforeAll {
          $rulesPath = "$PSScriptRoot/../src/Private/sequencing/rules"
          . "$PSScriptRoot/../src/Private/sequencing/rules/CA.rules.ps1"
          . "$PSScriptRoot/../src/Private/sequencing/rules/PIM.rules.ps1"
          . "$PSScriptRoot/../src/Private/sequencing/rules/LegacyAuth.rules.ps1"

          Mock Connect-GraphGateway { param($gw) $gw.Connected=$true; $gw }
          Mock Disconnect-GraphGateway { }
          Mock Test-TenantPin { [PSCustomObject]@{ Match=$true; MismatchReason=$null; TokenTenantId=$testConfig.TenantId; OrganizationTenantId=$testConfig.TenantId } }
          Mock Test-Environment { [PSCustomObject]@{ IsValid=$true; Failures=@() } }
          Mock Test-GraphPermissions { [PSCustomObject]@{ IsValid=$true; Missing=@() } }
          Mock Get-MgContext { [PSCustomObject]@{ Scopes=@('Policy.Read.All'); AccessToken='fake' } }

          # Auditor returns two Fail findings — one CA, one LA
          Mock Invoke-Audit {
              @(
                  (New-Finding -CheckId 'CA-001' -RunId 'r1' -Title 'Legacy Auth Not Blocked' -Category 'Identity' `
                      -Severity 'Critical' -RiskScore 95 -SecureScoreVisibility 'Passes' -Status 'Fail' `
                      -GraphEndpoint '/identity/conditionalAccess/policies' -SupportsRemediation $true `
                      -Evidence @{ legacyAuthPolicyFound=$false; breakGlassFound=$false }),
                  (New-Finding -CheckId 'LA-001' -RunId 'r1' -Title 'Legacy Authentication Not Blocked at Tenant or CA Level' -Category 'Identity' `
                      -Severity 'Critical' -RiskScore 90 -SecureScoreVisibility 'Passes' -Status 'Fail' `
                      -GraphEndpoint '/policies/authorizationPolicy' -SupportsRemediation $true `
                      -Evidence @{ tenantLevelBlocked=$false; effectivelyBlocked=$false })
              )
          }

          $remConfig = $testConfig.Clone()
          $remConfig['Mode']       = 'Remediate'
          $remConfig['AuthMethod'] = 'Delegated'
          $remConfig['Edition']    = 'Premium'
      }

      It 'WhatIf=true stamps all actions as Blocked/WhatIf and writes sequence-plan.json' {
          $result = Invoke-M365Assessment @remConfig -WhatIf
          $planPath = Join-Path $result.OutputFolder 'sequence-plan.json'
          $planPath | Should -Exist
          $plan = Get-Content $planPath | ConvertFrom-Json
          $plan.planHash | Should -Match '^sha256:'
      }

      It 'WhatIf=true writes remediation.actions.jsonl with Blocked entries' {
          $result = Invoke-M365Assessment @remConfig -WhatIf
          $logPath = Join-Path $result.OutputFolder 'remediation.actions.jsonl'
          $logPath | Should -Exist
          $lines = Get-Content $logPath
          $lines.Count | Should -BeGreaterThan 0
          ($lines[0] | ConvertFrom-Json).result.status | Should -BeIn @('Blocked','WhatIf')
      }

      It 'manifest sequencing.planHash matches plan file planHash' {
          $result = Invoke-M365Assessment @remConfig -WhatIf
          $manifest = Get-Content (Join-Path $result.OutputFolder 'run.manifest.json') | ConvertFrom-Json
          $plan     = Get-Content (Join-Path $result.OutputFolder 'sequence-plan.json') | ConvertFrom-Json
          $manifest.sequencing.planHash | Should -Be $plan.planHash
      }

      It 'Lite edition does NOT produce sequence-plan.json' {
          $liteConfig = $remConfig.Clone()
          $liteConfig['Edition'] = 'Lite'
          $result = Invoke-M365Assessment @liteConfig -WhatIf
          Join-Path $result.OutputFolder 'sequence-plan.json' | Should -Not -Exist
      }
  }
  ```

- [ ] **Step 2: Run — verify new tests fail**

  ```powershell
  Invoke-Pester -Path tests\Invoke-M365Assessment.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Replace stub Remediate block in Invoke-M365Assessment.ps1**

  In `src/Public/Invoke-M365Assessment.ps1`, replace:

  ```powershell
          if ($Mode -eq 'Remediate' -and $Edition -eq 'Premium') {
              # Full sequencing — handled in Task 26 (Remediate mode)
              throw "Remediate mode: see Task 26 implementation."
          }
  ```

  With:

  ```powershell
          if ($Mode -eq 'Remediate' -and $Edition -eq 'Premium') {
              # Build ExchangeGateway if Organization provided
              if ($Organization -and $AuthMethod -ne 'Secret') {
                  $exchParams = @{
                      TenantId     = $TenantId;   AppId    = $AppId
                      AuthMethod   = $AuthMethod;  Organization = $Organization
                      RunId        = $runId;       RunFolder = $runFolder
                  }
                  if ($CertificateThumbprint) { $exchParams['CertificateThumbprint'] = $CertificateThumbprint }
                  if ($Certificate)           { $exchParams['Certificate']           = $Certificate }
                  $exchangeGateway = New-ExchangeGateway @exchParams
              }

              # Load rules from each file in its own scope — prevents silent Get-Rules collision
              # when every *.rules.ps1 defines 'function Get-Rules' (dot-sourcing multiple files
              # into the same scope means only the last-loaded version survives).
              $allRules = @()
              Get-ChildItem -Path $rulesPath -Filter '*.rules.ps1' | ForEach-Object {
                  $ruleFile = $_
                  $fileRules = & ([scriptblock]::Create(
                      (Get-Content $ruleFile.FullName -Raw) + '; Get-Rules'
                  ))
                  $allRules += @($fileRules)
              }

              # Static CheckId → filename registry.
              # Replaces fragile naming-convention inference ($prefix regex + Get-ChildItem scan)
              # which was non-deterministic when multiple files matched and silently wrong on mismatch.
              $checkRegistry = @{
                  'CA-001'    = 'Check-ConditionalAccess.ps1'
                  'PIM-001'   = 'Check-PIM.ps1'
                  'LA-001'    = 'Check-LegacyAuthentication.ps1'
                  'MAIL-001'  = 'Check-EmailAuthentication.ps1'
                  'DLP-001'   = 'Check-DLP.ps1'
                  'GUEST-001' = 'Check-GuestAccess.ps1'
                  'DEV-001'   = 'Check-DeviceCompliance.ps1'
                  'SMTP-001'  = 'Check-SmtpAuth.ps1'
                  'SP-001'    = 'Check-SharePointSharing.ps1'
                  'AUDIT-001' = 'Check-AuditLogging.ps1'
                  'LABEL-001' = 'Check-SensitivityLabels.ps1'
                  'DEF-001'   = 'Check-DefenderOffice365.ps1'
                  'CASB-001'  = 'Check-CloudAppSecurity.ps1'
              }

              # Build candidate actions by dot-sourcing each check file in an isolated child scope.
              # '& { . $file; Invoke-Remediation }' replaces raw ScriptBlock::Create on file content:
              # no string interpolation, no injection vector, normal debugger support.
              $candidateActions = [System.Collections.Generic.List[object]]::new()
              foreach ($finding in ($findings | Where-Object { $_.status -eq 'Fail' -and $_.supportsRemediation })) {
                  $filename = $checkRegistry[$finding.checkId]
                  if (-not $filename) {
                      Write-Warning "No check file registered for '$($finding.checkId)' — skipping remediation"
                      continue
                  }
                  $checkFilePath = Join-Path $checksPath $filename
                  if (-not (Test-Path $checkFilePath)) {
                      Write-Warning "Check file not found: $checkFilePath — skipping"
                      continue
                  }

                  try {
                      $actions = & {
                          . $checkFilePath
                          Invoke-Remediation -GraphGateway $graphGateway `
                              -ExchangeGateway $exchangeGateway `
                              -Finding $finding `
                              -PSCmdlet $PSCmdlet
                      }
                      foreach ($a in $actions) { $candidateActions.Add($a) | Out-Null }
                  } catch {
                      Write-Warning "Invoke-Remediation failed for $($finding.checkId): $($_.Exception.Message)"
                  }
              }

              # Validate candidate actions before handing to sequencer.
              # Malformed or duplicate actionIds crash the planner; catch them here with clear errors.
              $seenIds = [System.Collections.Generic.HashSet[string]]::new()
              foreach ($a in $candidateActions) {
                  if (-not $a.action.actionId) {
                      throw "RemediationAction missing actionId (checkId: $($a.check.checkId))"
                  }
                  if (-not $seenIds.Add($a.action.actionId)) {
                      throw "Duplicate action ID detected: '$($a.action.actionId)'"
                  }
                  if (-not $a.action.provider) {
                      throw "RemediationAction missing provider (actionId: $($a.action.actionId))"
                  }
              }

              if ($candidateActions.Count -gt 0) {
                  # Apply dependency rules
                  $annotatedActions = Invoke-DependencyRules -Actions $candidateActions.ToArray() -Rules $allRules -Findings $findings

                  # Build plan (topological sort + planHash)
                  $sequencePlan = New-SequencePlan -Actions $annotatedActions -RulesVersion '1.0.0'

                  # Write sequence-plan.json
                  $planPath = Write-SequencePlanJson -SequencePlan $sequencePlan -OutputFolder $runFolder

                  # Execute (or WhatIf stamp)
                  $writeAllowedParams = @{
                      Mode       = $Mode
                      AuthMethod = $AuthMethod
                      WhatIf     = [bool]$WhatIfPreference
                      Edition    = $Edition
                  }

                  $logPath        = Join-Path $runFolder 'remediation.actions.jsonl'
                  $remediatorScript = {
                      param($action, $gw, $exgw)
                      Invoke-RemediationAction -Action $action -GraphGateway $gw -ExchangeGateway $exgw `
                          -RunFolder $runFolder -CheckId $action.check.checkId -FindingId $action.check.findingId
                  }

                  $actionResults = Invoke-ExecutePlan `
                      -Plan $sequencePlan `
                      -GraphGateway $graphGateway `
                      -ExchangeGateway $exchangeGateway `
                      -WriteAllowedParams $writeAllowedParams `
                      -RemediatorScript $remediatorScript `
                      -WhatIf ([bool]$WhatIfPreference)

                  foreach ($a in $actionResults) {
                      Append-RemediationActionLog -Action $a -LogPath $logPath
                  }

                  $manifest['sequencing'] = @{
                      planHash       = $sequencePlan.planHash
                      rulesVersion   = $sequencePlan.rulesVersion
                      phases         = $sequencePlan.phases
                      blockedActions = @($actionResults | Where-Object { $_.result.status -eq 'Blocked' }).Count
                      executedActions = @($actionResults | Where-Object { $_.result.status -eq 'Success' }).Count
                  }
                  $manifest['artifacts'] += @{ name='sequence-plan.json'; path=$planPath }
                  if (Test-Path $logPath) {
                      $manifest['artifacts'] += @{ name='remediation.actions.jsonl'; path=$logPath }
                  }

                  $failedActions = @($actionResults | Where-Object { $_.result.status -eq 'Failed' })
                  if ($failedActions.Count -gt 0) { $runStatus = 'Partial' }
              }
          }
  ```

  Also update `$runStatus` assignment to account for action failures after the sequencing block, before writing artifacts.

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\Invoke-M365Assessment.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Public\Invoke-M365Assessment.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Public/Invoke-M365Assessment.ps1 tests/Invoke-M365Assessment.Tests.ps1
  git commit -m "feat: wire Invoke-M365Assessment Remediate mode (sequencing, WhatIf plan, JSONL log, state snapshots)"
  ```

---

### Task 27: Start-Assessment.ps1 Entry Point

**Files:**
- Modify: `Start-Assessment.ps1` (replace empty file)

- [ ] **Step 1: Write failing test**

  Create `tests/Start-Assessment.Tests.ps1`:

  ```powershell
  Describe 'Start-Assessment.ps1 — smoke test' {
      It 'script file exists and has no syntax errors' {
          $path = "$PSScriptRoot/../Start-Assessment.ps1"
          Test-Path $path | Should -BeTrue
          $errors = $null
          [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors) | Out-Null
          $errors.Count | Should -Be 0
      }
  }
  ```

- [ ] **Step 2: Run — verify fails (empty file has no Invoke-M365Assessment call)**

  ```powershell
  Invoke-Pester -Path tests\Start-Assessment.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Start-Assessment.ps1**

  Replace empty `Start-Assessment.ps1`:

  ```powershell
  #Requires -Version 7.2
  <#
  .SYNOPSIS
      Entry point for the M365 Security Assessment Tool.

  .DESCRIPTION
      Loads configuration from config/assessment.config.psd1 and config/assessment.secrets.psd1,
      then delegates to Invoke-M365Assessment. All business logic lives in the module.

  .EXAMPLE
      .\Start-Assessment.ps1
      .\Start-Assessment.ps1 -Mode Remediate -WhatIf
      .\Start-Assessment.ps1 -Mode Remediate -Edition Premium -Confirm:$false
  #>
  [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
  param(
      [ValidateSet('Assess','Remediate')] [string] $Mode,
      [ValidateSet('Certificate','Secret','Delegated')] [string] $AuthMethod,
      [ValidateSet('Lite','Premium')] [string] $Edition,
      [string[]] $IncludeChecks,
      [switch] $Force
  )

  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  $moduleRoot   = $PSScriptRoot
  $configPath   = Join-Path $moduleRoot 'config\assessment.config.psd1'
  $secretsPath  = Join-Path $moduleRoot 'config\assessment.secrets.psd1'
  $manifestPath = Join-Path $moduleRoot 'm365-security-assessment-tool.psd1'

  # Import module (dot-sources all Private + Public automatically)
  Import-Module $manifestPath -Force -ErrorAction Stop

  # Load config
  if (-not (Test-Path $configPath)) {
      throw "Config not found: $configPath. Copy and populate config\assessment.config.psd1."
  }
  $config = Import-PowerShellDataFile $configPath

  # Load secrets (gitignored)
  if (-not (Test-Path $secretsPath)) {
      throw "Secrets not found: $secretsPath. Copy and populate config\assessment.secrets.psd1 (never commit this file)."
  }
  $secrets = Import-PowerShellDataFile $secretsPath

  # CLI params override config file
  if ($Mode)          { $config['Mode']          = $Mode }
  if ($AuthMethod)    { $config['AuthMethod']     = $AuthMethod }
  if ($Edition)       { $config['Edition']        = $Edition }
  if ($IncludeChecks) { $config['EnabledChecks']  = $IncludeChecks }

  # ?? not available in Windows PowerShell 5.1; use explicit if/else for each default.
  $invokeParams = @{
      TenantId      = $secrets.TenantId
      AppId         = $secrets.AppId
      Mode          = if ($null -ne $config.Mode)          { $config.Mode }          else { 'Assess' }
      AuthMethod    = if ($null -ne $config.AuthMethod)    { $config.AuthMethod }    else { 'Certificate' }
      Edition       = if ($null -ne $config.Edition)       { $config.Edition }       else { 'Lite' }
      OutputPath    = if ($null -ne $config.OutputPath)    { $config.OutputPath }    else { '.\Output' }
      EnabledChecks = if ($null -ne $config.EnabledChecks) { $config.EnabledChecks } else { @() }
  }

  if ($secrets.CertificateThumbprint) { $invokeParams['CertificateThumbprint'] = $secrets.CertificateThumbprint }
  if ($secrets.ClientSecret)          { $invokeParams['ClientSecret']          = $secrets.ClientSecret }
  if ($secrets.Organization)          { $invokeParams['Organization']          = $secrets.Organization }
  if ($Force)                         { $invokeParams['Force']                 = $true }

  $result = Invoke-M365Assessment @invokeParams

  Write-Output ""
  Write-Output "Assessment complete."
  Write-Output "  RunId:   $($result.RunId)"
  Write-Output "  Status:  $($result.Status)"
  Write-Output "  Output:  $($result.OutputFolder)"
  Write-Output ""
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\Start-Assessment.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path Start-Assessment.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add Start-Assessment.ps1 tests/Start-Assessment.Tests.ps1
  git commit -m "feat: add Start-Assessment.ps1 entry point (config/secrets loader, CLI param overrides)"
  ```

---

### Task 28: DLP + CrossCheck Rules

**Files:**
- Create: `src/Private/sequencing/rules/DLP.rules.ps1`
- Create: `src/Private/sequencing/rules/CrossCheck.rules.ps1`
- Create: `tests/sequencing/rules/DLP.rules.Tests.ps1`
- Create: `tests/sequencing/rules/CrossCheck.rules.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/sequencing/rules/DLP.rules.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../../src/Private/sequencing/rules/DLP.rules.ps1" }

  Describe 'DLP.rules — structure' {
      BeforeAll { $rules = Get-Rules }
      It 'returns non-empty array'       { $rules.Count | Should -BeGreaterThan 0 }
      It 'contains DLP-DEP-001'          { $rules.ruleId | Should -Contain 'DLP-DEP-001' }
      It 'contains DLP-DEP-002'          { $rules.ruleId | Should -Contain 'DLP-DEP-002' }
      It 'all rules have version 1.0.0'  { $rules | ForEach-Object { $_.version | Should -Be '1.0.0' } }
      It 'DLP-DEP-001 appliesToAction ACT-DLP-ENABLE-POLICY' {
          ($rules | Where-Object { $_.ruleId -eq 'DLP-DEP-001' }).appliesToAction | Should -Be 'ACT-DLP-ENABLE-POLICY'
      }
      It 'DLP-DEP-001 fact is AuditLoggingEnabled' {
          ($rules | Where-Object { $_.ruleId -eq 'DLP-DEP-001' }).condition.fact | Should -Be 'AuditLoggingEnabled'
      }
      It 'DLP-DEP-002 fact is SensitivityLabelsDefined' {
          ($rules | Where-Object { $_.ruleId -eq 'DLP-DEP-002' }).condition.fact | Should -Be 'SensitivityLabelsDefined'
      }
  }
  ```

  Create `tests/sequencing/rules/CrossCheck.rules.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../../src/Private/sequencing/rules/CrossCheck.rules.ps1" }

  Describe 'CrossCheck.rules — structure' {
      BeforeAll { $rules = Get-Rules }
      It 'returns non-empty array'     { $rules.Count | Should -BeGreaterThan 0 }
      It 'contains CC-001'             { $rules.ruleId | Should -Contain 'CC-001' }
      It 'contains CC-002'             { $rules.ruleId | Should -Contain 'CC-002' }
      It 'contains CC-003'             { $rules.ruleId | Should -Contain 'CC-003' }
      It 'contains CC-004'             { $rules.ruleId | Should -Contain 'CC-004' }
      It 'CC-001 is type Dependency'   { ($rules | Where-Object { $_.ruleId -eq 'CC-001' }).type | Should -Be 'Dependency' }
      It 'CC-004 is type Block'        { ($rules | Where-Object { $_.ruleId -eq 'CC-004' }).type | Should -Be 'Block' }
      It 'CC-003 appliesToAction ACT-DLP-ENFORCE' {
          ($rules | Where-Object { $_.ruleId -eq 'CC-003' }).appliesToAction | Should -Be 'ACT-DLP-ENFORCE'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\sequencing\rules\DLP.rules.Tests.ps1, tests\sequencing\rules\CrossCheck.rules.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement DLP.rules.ps1**

  Create `src/Private/sequencing/rules/DLP.rules.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-Rules {
      @(
          [PSCustomObject]@{
              ruleId          = 'DLP-DEP-001'
              appliesToAction = 'ACT-DLP-ENABLE-POLICY'
              type            = 'Dependency'
              condition       = [PSCustomObject]@{ fact='AuditLoggingEnabled'; operator='Equals'; value=$true }
              effect          = [PSCustomObject]@{ dependency='ACT-AUDIT-ENABLE'; blockIfUnsatisfied=$true
                                    reason='DLP policy enforcement requires audit logging enabled to capture policy match events' }
              priority        = 2; category='DataGovernance'; version='1.0.0'
          }
          [PSCustomObject]@{
              ruleId          = 'DLP-DEP-002'
              appliesToAction = 'ACT-DLP-ENABLE-POLICY'
              type            = 'Dependency'
              condition       = [PSCustomObject]@{ fact='SensitivityLabelsDefined'; operator='Equals'; value=$true }
              effect          = [PSCustomObject]@{ dependency='ACT-LABEL-PUBLISH'; blockIfUnsatisfied=$false
                                    reason='DLP label-based conditions require sensitivity labels to be defined and published first' }
              priority        = 1; category='DataGovernance'; version='1.0.0'
          }
      )
  }
  ```

- [ ] **Step 4: Implement CrossCheck.rules.ps1**

  Create `src/Private/sequencing/rules/CrossCheck.rules.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-Rules {
      @(
          [PSCustomObject]@{
              ruleId          = 'CC-001'
              appliesToAction = 'ACT-CA-ENFORCE-MFA'
              type            = 'Dependency'
              condition       = [PSCustomObject]@{ fact='PIMEnabled'; operator='Equals'; value=$true }
              effect          = [PSCustomObject]@{ dependency='ACT-PIM-CONFIGURE-ROLE-SETTINGS'; blockIfUnsatisfied=$false
                                    reason='MFA enforcement for admins is stronger when PIM high-risk roles are already secured (CC-001)' }
              priority        = 3; category='CrossDomain'; version='1.0.0'
          }
          [PSCustomObject]@{
              ruleId          = 'CC-002'
              appliesToAction = 'ACT-CA-REQUIRE-COMPLIANT-DEVICE'
              type            = 'Dependency'
              condition       = [PSCustomObject]@{ fact='DeviceCompliancePoliciesExist'; operator='Equals'; value=$true }
              effect          = [PSCustomObject]@{ dependency='ACT-DEV-BASELINE-COMPLIANCE'; blockIfUnsatisfied=$true
                                    reason='Device compliance CA condition requires at least one compliance policy to exist (CC-002)' }
              priority        = 4; category='CrossDomain'; version='1.0.0'
          }
          [PSCustomObject]@{
              ruleId          = 'CC-003'
              appliesToAction = 'ACT-DLP-ENFORCE'
              type            = 'Dependency'
              condition       = [PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
              effect          = [PSCustomObject]@{ dependency='ACT-CA-IDENTITY-BASELINE'; blockIfUnsatisfied=$false
                                    reason='DLP enforcement (Phase 4) must follow identity baseline (Phase 2) to ensure data access is identity-gated before data controls apply (CC-003)' }
              priority        = 5; category='CrossDomain'; version='1.0.0'
          }
          [PSCustomObject]@{
              ruleId          = 'CC-004'
              appliesToAction = 'ACT-CA-BLOCK-ALL-EXTERNAL'
              type            = 'Block'
              condition       = [PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
              effect          = [PSCustomObject]@{ dependency=$null; blockIfUnsatisfied=$true
                                    reason='ACT-CA-BLOCK-ALL-EXTERNAL blocked: EmergencyAccessTested fact not verified. Risk of complete tenant lockout (CC-004)' }
              priority        = 10; category='CrossDomain'; version='1.0.0'
          }
      )
  }
  ```

  > **Note:** `CC-004` uses `fact='Always'` with a Block type as a permanent safety guard — the block reason explains this is intentional. To unblock, operator must confirm emergency access tested and remove this rule from the library (requires code change + version bump).
  >
  > **Name collision:** Every `*.rules.ps1` intentionally defines `function Get-Rules` for standalone testability. Dot-sourcing multiple files into the same scope means only the last-loaded version survives. The orchestrator (`Invoke-M365Assessment` Remediate block) and integration tests load each rules file via `& ([scriptblock]::Create(...))` to keep each `Get-Rules` in its own scope. Do NOT dot-source multiple rules files into a shared scope.

- [ ] **Step 5: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\sequencing\rules\ -Output Detailed
  ```

- [ ] **Step 6: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\sequencing\rules\ -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/sequencing/rules/DLP.rules.ps1 src/Private/sequencing/rules/CrossCheck.rules.ps1
  git add tests/sequencing/rules/DLP.rules.Tests.ps1 tests/sequencing/rules/CrossCheck.rules.Tests.ps1
  git commit -m "feat: add DLP and CrossCheck dependency rules (CC-001..CC-004, DLP-DEP-001..002, v1.0.0)"
  ```

---

### Task 29: Sequencing Integration Tests

**Files:**
- Create: `tests/sequencing/SequencingIntegration.Tests.ps1`

- [ ] **Step 1: Write integration tests**

  Create `tests/sequencing/SequencingIntegration.Tests.ps1`:

  ```powershell
  BeforeAll {
      $private = "$PSScriptRoot/../../src/Private"
      . "$private/models/Finding.schema.ps1"
      . "$private/models/RemediationAction.schema.ps1"
      . "$private/sequencing/ActionGraphBuilder.ps1"
      . "$private/sequencing/DependencyRulesEngine.ps1"
      . "$private/sequencing/Planner.ps1"
      . "$private/sequencing/rules/CA.rules.ps1"
      . "$private/sequencing/rules/PIM.rules.ps1"
      . "$private/sequencing/rules/LegacyAuth.rules.ps1"
      . "$private/sequencing/rules/DLP.rules.ps1"
      . "$private/sequencing/rules/CrossCheck.rules.ps1"

      function New-ActionStub {
          param([string]$Id, [int]$Phase = 2, [string[]]$Deps = @())
          [PSCustomObject]@{
              action   = [PSCustomObject]@{ actionId=$Id; provider='Graph' }
              sequence = [PSCustomObject]@{ phase=$Phase; order=0; dependencies=$Deps; conflictsWith=@(); priority=1; safetyLevel='High'; category='Identity' }
              result   = [PSCustomObject]@{ status=$null; reason=$null }
              rulesApplied = @()
          }
      }

      # Each *.rules.ps1 defines 'function Get-Rules'. Load each in its own scope via
      # & ([scriptblock]::Create(...)) so function names don't overwrite each other.
      $allCA        = & ([scriptblock]::Create((Get-Content "$private/sequencing/rules/CA.rules.ps1" -Raw) + '; Get-Rules'))
      $allPIM       = & ([scriptblock]::Create((Get-Content "$private/sequencing/rules/PIM.rules.ps1" -Raw) + '; Get-Rules'))
      $allLA        = & ([scriptblock]::Create((Get-Content "$private/sequencing/rules/LegacyAuth.rules.ps1" -Raw) + '; Get-Rules'))
      $allDLP       = & ([scriptblock]::Create((Get-Content "$private/sequencing/rules/DLP.rules.ps1" -Raw) + '; Get-Rules'))
      $allCC        = & ([scriptblock]::Create((Get-Content "$private/sequencing/rules/CrossCheck.rules.ps1" -Raw) + '; Get-Rules'))
      $allRules     = @($allCA) + @($allPIM) + @($allLA) + @($allDLP) + @($allCC)

      $findingsNoBreakGlass = @(
          [PSCustomObject]@{ checkId='CA-001'; status='Fail'; evidence=@{ breakGlassFound=$false; legacyAuthPolicyFound=$false; effectivelyBlocked=$false; totalPolicies=0 } }
          [PSCustomObject]@{ checkId='PIM-001'; status='Fail'; evidence=@{ pimEnabled=$false; standingHighRiskCount=2; eligibleScheduleCount=0 } }
      )

      $findingsWithBreakGlass = @(
          [PSCustomObject]@{ checkId='CA-001'; status='Fail'; evidence=@{ breakGlassFound=$true; legacyAuthPolicyFound=$false; effectivelyBlocked=$false; totalPolicies=1 } }
          [PSCustomObject]@{ checkId='PIM-001'; status='Fail'; evidence=@{ pimEnabled=$true; standingHighRiskCount=2; eligibleScheduleCount=3 } }
      )
  }

  Describe 'Full pipeline: Findings → DependencyRules → Planner' {
      It 'CA-BLOCK-001: ACT-CA-ENABLE-MFA blocked when BreakGlassAccountsPresent=false' {
          $actions = @(
              New-ActionStub 'ACT-CA-ENABLE-MFA' -Phase 2
              New-ActionStub 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
          )
          $annotated = Invoke-DependencyRules -Actions $actions -Rules $allRules -Findings $findingsNoBreakGlass
          $mfaAction = $annotated | Where-Object { $_.action.actionId -eq 'ACT-CA-ENABLE-MFA' }
          $mfaAction.result.status | Should -Be 'Blocked'
          $mfaAction.rulesApplied.ruleId | Should -Contain 'CA-BLOCK-001'
      }

      It 'CA-DEP-001: ACT-CA-ENABLE-MFA gets dependency on ACT-CA-EXCLUDE-BREAKGLASS when break-glass present' {
          $actions = @(
              New-ActionStub 'ACT-CA-ENABLE-MFA' -Phase 2
              New-ActionStub 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
          )
          $annotated = Invoke-DependencyRules -Actions $actions -Rules $allRules -Findings $findingsWithBreakGlass
          $mfaAction = $annotated | Where-Object { $_.action.actionId -eq 'ACT-CA-ENABLE-MFA' }
          $mfaAction.sequence.dependencies | Should -Contain 'ACT-CA-EXCLUDE-BREAKGLASS'
          $mfaAction.rulesApplied.ruleId | Should -Contain 'CA-DEP-001'
      }

      It 'PIM-BLOCK-001: all PIM actions blocked when PIMEnabled=false' {
          $actions = @(New-ActionStub 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE' -Phase 3)
          $annotated = Invoke-DependencyRules -Actions $actions -Rules $allRules -Findings $findingsNoBreakGlass
          $pimAction = $annotated | Where-Object { $_.action.actionId -eq 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE' }
          $pimAction.result.status | Should -Be 'Blocked'
          $pimAction.rulesApplied.ruleId | Should -Contain 'PIM-BLOCK-001'
      }

      It 'Planner topological order respects CA-DEP-001 dependency' {
          $actions = @(
              New-ActionStub 'ACT-CA-ENABLE-MFA' -Phase 2 -Deps @('ACT-CA-EXCLUDE-BREAKGLASS')
              New-ActionStub 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
          )
          $plan = New-SequencePlan -Actions $actions -RulesVersion '1.0.0'
          $ids  = $plan.actions | Select-Object -ExpandProperty action | Select-Object -ExpandProperty actionId
          $ids.IndexOf('ACT-CA-EXCLUDE-BREAKGLASS') | Should -BeLessThan $ids.IndexOf('ACT-CA-ENABLE-MFA')
      }

      It 'planHash is deterministic across two identical runs' {
          $actions1 = @(
              New-ActionStub 'ACT-001' -Phase 1
              New-ActionStub 'ACT-002' -Phase 2 -Deps @('ACT-001')
          )
          $actions2 = @(
              New-ActionStub 'ACT-001' -Phase 1
              New-ActionStub 'ACT-002' -Phase 2 -Deps @('ACT-001')
          )
          $p1 = New-SequencePlan -Actions $actions1 -RulesVersion '1.0.0'
          $p2 = New-SequencePlan -Actions $actions2 -RulesVersion '1.0.0'
          $p1.planHash | Should -Be $p2.planHash
      }

      It 'Planner throws CircularDependency for A→B→A cycle' {
          $a1 = New-ActionStub 'ACT-A' -Deps @('ACT-B')
          $a2 = New-ActionStub 'ACT-B' -Deps @('ACT-A')
          { New-SequencePlan -Actions @($a1, $a2) -RulesVersion '1.0.0' } | Should -Throw '*CircularDependency*'
      }

      It 'Blocked actions do not block Planner from producing a plan' {
          $a1 = New-ActionStub 'ACT-CA-EXCLUDE-BREAKGLASS' -Phase 1
          $a2 = New-ActionStub 'ACT-CA-ENABLE-MFA' -Phase 2
          $a2.result.status = 'Blocked'   # pre-blocked by rules engine
          $plan = New-SequencePlan -Actions @($a1, $a2) -RulesVersion '1.0.0'
          $plan.summary.blocked | Should -Be 1
          $plan.summary.total   | Should -Be 2
          $plan.planHash | Should -Not -BeNullOrEmpty
      }

      It 'unknown fact evaluates as false — does not block action when condition.value=false expected' {
          $actions = @(New-ActionStub 'ACT-CA-ENABLE-MFA' -Phase 2)
          # CA-BLOCK-001: blocks when BreakGlassAccountsPresent=false
          # With empty findings, breakGlassFound is unknown → false → condition BreakGlassAccountsPresent=false IS satisfied → blocked
          $annotated = Invoke-DependencyRules -Actions $actions -Rules $allRules -Findings @()
          $mfaAction = $annotated | Where-Object { $_.action.actionId -eq 'ACT-CA-ENABLE-MFA' }
          $mfaAction.result.status | Should -Be 'Blocked'   # unknown = false = BreakGlassAccountsPresent=false → block fires
      }

      It 'rulesVersion propagates to plan output' {
          $plan = New-SequencePlan -Actions @(New-ActionStub 'ACT-001') -RulesVersion '2.0.0'
          $plan.rulesVersion | Should -Be '2.0.0'
      }
  }
  ```

- [ ] **Step 2: Run — verify pass (all rules and sequencing logic already implemented)**

  ```powershell
  Invoke-Pester -Path tests\sequencing\SequencingIntegration.Tests.ps1 -Output Detailed
  ```

  Expected: all pass. If any fail, fix the underlying implementation (not the tests).

- [ ] **Step 3: Run full test suite — verify no regressions**

  ```powershell
  Invoke-Pester -Path tests\ -Output Detailed
  ```

  Expected: all tests pass across all test files.

- [ ] **Step 4: Commit**

  ```powershell
  git add tests/sequencing/SequencingIntegration.Tests.ps1
  git commit -m "test: add sequencing integration tests (findings→rules→planner pipeline, determinism, edge cases)"
  ```

---

### Task 30: CI/CD Pipeline

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write failing smoke test**

  Create `tests/Module.Tests.ps1`:

  ```powershell
  Describe 'Module manifest' {
      It 'Test-ModuleManifest passes' {
          $result = Test-ModuleManifest -Path "$PSScriptRoot/../m365-security-assessment-tool.psd1" -ErrorAction Stop
          $result.Name | Should -Be 'm365-security-assessment-tool'
      }

      It 'FunctionsToExport contains Invoke-M365Assessment' {
          $manifest = Import-PowerShellDataFile "$PSScriptRoot/../m365-security-assessment-tool.psd1"
          $manifest.FunctionsToExport | Should -Contain 'Invoke-M365Assessment'
      }

      It 'PowerShellVersion is 7.2' {
          $manifest = Import-PowerShellDataFile "$PSScriptRoot/../m365-security-assessment-tool.psd1"
          $manifest.PowerShellVersion | Should -Be '7.2'
      }
  }

  Describe 'ScriptAnalyzer — zero issues across all source files' {
      It 'src/ has no ScriptAnalyzer errors or warnings' {
          $results = Invoke-ScriptAnalyzer -Path "$PSScriptRoot/../src" -Recurse `
              -Settings "$PSScriptRoot/../PSScriptAnalyzerSettings.psd1"
          $issues = $results | Where-Object { $_.Severity -in @('Error','Warning') }
          $issues | ForEach-Object { Write-Warning "$($_.ScriptName):$($_.Line) [$($_.Severity)] $($_.Message)" }
          $issues.Count | Should -Be 0
      }
  }
  ```

- [ ] **Step 2: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\Module.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement ci.yml**

  Create `.github/workflows/ci.yml`:

  ```yaml
  name: CI

  on:
    push:
      branches: [ main, develop ]
    pull_request:
      branches: [ main ]

  jobs:
    test:
      name: Test (PowerShell ${{ matrix.ps-version }})
      runs-on: windows-latest
      strategy:
        matrix:
          ps-version: ['7.2', '7.4']

      steps:
        - uses: actions/checkout@v4

        - name: Set up PowerShell ${{ matrix.ps-version }}
          uses: actions/setup-dotnet@v4
          with:
            dotnet-version: '8.x'

        - name: Install Pester
          shell: pwsh
          run: |
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            Install-Module -Name Pester -RequiredVersion 5.6.0 -Force -SkipPublisherCheck

        - name: Install PSScriptAnalyzer
          shell: pwsh
          run: |
            Install-Module -Name PSScriptAnalyzer -Force -SkipPublisherCheck

        - name: Validate module manifest
          shell: pwsh
          run: Test-ModuleManifest -Path .\m365-security-assessment-tool.psd1

        - name: Run PSScriptAnalyzer
          shell: pwsh
          run: |
            $results = Invoke-ScriptAnalyzer -Path .\src -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
            $errors = $results | Where-Object { $_.Severity -in @('Error','Warning') }
            if ($errors.Count -gt 0) {
              $errors | Format-Table -AutoSize
              exit 1
            }

        - name: Run Pester tests
          shell: pwsh
          run: |
            $config = New-PesterConfiguration
            $config.Run.Path         = '.\tests'
            $config.Output.Verbosity = 'Detailed'
            $config.TestResult.Enabled    = $true
            $config.TestResult.OutputPath = 'test-results.xml'
            $config.TestResult.OutputFormat = 'NUnitXml'
            $result = Invoke-Pester -Configuration $config
            if ($result.FailedCount -gt 0) { exit 1 }

        - name: Upload test results
          uses: actions/upload-artifact@v4
          if: always()
          with:
            name: test-results-${{ matrix.ps-version }}
            path: test-results.xml
  ```

- [ ] **Step 4: Run full test suite locally**

  ```powershell
  $config = New-PesterConfiguration
  $config.Run.Path = '.\tests'
  $config.Output.Verbosity = 'Detailed'
  Invoke-Pester -Configuration $config
  ```

  Expected: all tests pass. Zero PSScriptAnalyzer errors.

- [ ] **Step 5: Commit**

  ```powershell
  git add .github/workflows/ci.yml tests/Module.Tests.ps1
  git commit -m "ci: add GitHub Actions workflow (manifest, ScriptAnalyzer, Pester on PS 7.2 + 7.4)"
  ```

<!-- End tasks-25-30.md -->
