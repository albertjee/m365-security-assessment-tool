# M365 Security Assessment Tool — Tasks 31–34

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Prerequisite:** Tasks 1–30 complete (full pipeline wired, first 3 checks validated end-to-end).

**Goal:** Implement Check-EmailAuthentication, Check-DLP, Check-GuestAccess, Check-DeviceCompliance.

---

### Task 31: Check-EmailAuthentication

**Files:**
- Create: `src/Private/checks/Check-EmailAuthentication.ps1`
- Create: `tests/checks/Check-EmailAuthentication.Tests.ps1`

> **API note:** `GET /domains` uses `Get-MgDomain` from `Microsoft.Graph.Identity.DirectoryManagement`. DKIM, anti-phishing, Safe Links, Safe Attachments use Exchange Online PS via ExchangeGateway. `dataSource='Both'` — check requires Graph (domains) + Exchange (policy state). Secret auth → NotAssessed because ExchangeGateway rejects Secret.

- [ ] **Step 1: Write failing tests**

  Create `tests/checks/Check-EmailAuthentication.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-EmailAuthentication.ps1"

      function New-MockGw {
          [PSCustomObject]@{
              PSTypeName = 'Metis.GraphGateway'
              AuthMethod = 'Certificate'
              RunId      = 'run-001'
              Connected  = $true
          }
      }
      function New-MockExGw {
          [PSCustomObject]@{
              PSTypeName = 'Metis.ExchangeGateway'
              AuthMethod = 'Certificate'
              Connected  = $true
          }
      }
  }

  Describe 'Get-CheckMetadata' {
      It 'id is MAIL-001'      { (Get-CheckMetadata).id        | Should -Be 'MAIL-001' }
      It 'severity is High'    { (Get-CheckMetadata).severity  | Should -Be 'High' }
      It 'dataSource is Both'  { (Get-CheckMetadata).dataSource | Should -Be 'Both' }
      It 'has Organization.Read.All' {
          (Get-CheckMetadata).requiredPermissions | Should -Contain 'Organization.Read.All'
      }
      It 'assessAuthMethods excludes Secret' {
          (Get-CheckMetadata).assessAuthMethods | Should -Not -Contain 'Secret'
      }
  }

  Describe 'Invoke-Check — Secret auth guard' {
      It 'returns NotAssessed for Secret auth' {
          $gw = New-MockGw; $gw.AuthMethod = 'Secret'
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $null }
          $findings[0].status | Should -Be 'NotAssessed'
          $findings[0].error.message | Should -Match 'ExchangeAuthNotSupported'
      }
  }

  Describe 'Invoke-Check — DKIM disabled' {
      It 'returns Fail for DKIM-DISABLED when DKIM not enabled' {
          $gw   = New-MockGw
          $exGw = New-MockExGw
          Mock Invoke-GraphRequest {
              [PSCustomObject]@{ Result = @{ value = @(
                  [PSCustomObject]@{ id = 'contoso.com'; isVerified = $true }
              )}}
          }
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-DkimSigningConfig') {
                  return [PSCustomObject]@{ Result = @(
                      [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $false; KeyCreatedTime = $null }
                  )}
              }
              return [PSCustomObject]@{ Result = @() }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $dkimF = $findings | Where-Object { $_.checkId -eq 'MAIL-001' -and $_.title -match 'DKIM' }
          $dkimF | Should -Not -BeNullOrEmpty
          $dkimF.status | Should -Be 'Fail'
      }
  }

  Describe 'Invoke-Check — anti-phishing default preset' {
      It 'returns Fail when no standard/strict anti-phish policy' {
          $gw   = New-MockGw
          $exGw = New-MockExGw
          Mock Invoke-GraphRequest {
              [PSCustomObject]@{ Result = @{ value = @() } }
          }
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-AntiPhishPolicy') {
                  return [PSCustomObject]@{ Result = @(
                      [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; PhishThresholdLevel = 1 }
                  )}
              }
              return [PSCustomObject]@{ Result = @() }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $apF = $findings | Where-Object { $_.title -match 'Anti-Phish' }
          $apF.status | Should -Be 'Fail'
      }
  }

  Describe 'Invoke-Check — error handling' {
      It 'returns NotAssessed when Graph throws' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-GraphRequest { throw 'Graph error' }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $findings[0].status | Should -Be 'NotAssessed'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-EmailAuthentication.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Check-EmailAuthentication.ps1**

  Create `src/Private/checks/Check-EmailAuthentication.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-CheckMetadata {
      @{
          id                    = 'MAIL-001'
          title                 = 'Email Authentication Assessment'
          category              = 'Email Security'
          severity              = 'High'
          riskScoreBaseline     = 82
          secureScoreVisibility = 'Partial'
          description           = 'Evaluates DKIM signing, anti-phishing policy preset (default vs standard/strict), Safe Links, and Safe Attachments configuration. DNS-level SPF/DMARC review is generated as a change package only — no DNS writes.'
          requiredPermissions   = @('Organization.Read.All')
          requiredExchangeRoles = @('View-Only Configuration')
          dataSource            = 'Both'
          supportsRemediation   = $true
          edition               = @('Lite', 'Premium')
          assessAuthMethods     = @('Certificate', 'Delegated')
      }
  }

  function Invoke-Check {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          [Parameter(Mandatory)] $Config
      )

      $runId    = $GraphGateway.RunId
      $findings = [System.Collections.Generic.List[object]]::new()
      $exGw     = $Config.ExchangeGateway

      if ($GraphGateway.AuthMethod -eq 'Secret') {
          $findings.Add((New-Finding -CheckId 'MAIL-001' -RunId $runId `
              -Title 'Email Authentication Assessment Unavailable' `
              -Category 'Email Security' -Severity 'High' -RiskScore 82 `
              -SecureScoreVisibility 'Partial' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint '/domains' -SupportsRemediation $false `
              -ErrorMessage 'ExchangeAuthNotSupported'))
          return $findings.ToArray()
      }

      # --- Get accepted domains via Graph ---
      $domains = @()
      try {
          $resp    = Invoke-GraphRequest -GraphGateway $GraphGateway `
                         -Uri '/domains' -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
          $domains = @($resp.Result.value | Where-Object { $_.isVerified -eq $true })
      } catch {
          $findings.Add((New-Finding -CheckId 'MAIL-001' -RunId $runId `
              -Title 'Email Authentication Assessment Failed' `
              -Category 'Email Security' -Severity 'High' -RiskScore 82 `
              -SecureScoreVisibility 'Partial' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint '/domains' -SupportsRemediation $false `
              -ErrorMessage $_.Exception.Message))
          return $findings.ToArray()
      }

      # --- DKIM ---
      $dkimConfigs = @()
      try {
          $dkimResult  = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                             -CmdletName 'Get-DkimSigningConfig' -Parameters @{} `
                             -OperationType 'Read' -Caller 'Auditor'
          $dkimConfigs = @($dkimResult.Result)
      } catch { $dkimConfigs = @() }

      $disabledDomains = @($dkimConfigs | Where-Object { $_.Enabled -eq $false })
      $dkimStatus      = if ($disabledDomains.Count -eq 0 -and $dkimConfigs.Count -gt 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'MAIL-001' -RunId $runId `
          -Title 'DKIM Signing Disabled for One or More Accepted Domains' `
          -Category 'Email Security' -Severity 'High' -RiskScore 80 `
          -SecureScoreVisibility 'Partial' -Status $dkimStatus `
          -Evidence @{
              acceptedDomainCount  = $domains.Count
              dkimConfigCount      = $dkimConfigs.Count
              disabledDomainCount  = $disabledDomains.Count
              disabledDomains      = @($disabledDomains | Select-Object -ExpandProperty Domain)
          } `
          -GraphEndpoint '/domains' -SupportsRemediation $true))

      # --- Anti-phishing preset ---
      $antiPhishPolicies = @()
      try {
          $apResult         = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                                  -CmdletName 'Get-AntiPhishPolicy' -Parameters @{} `
                                  -OperationType 'Read' -Caller 'Auditor'
          $antiPhishPolicies = @($apResult.Result)
      } catch { $antiPhishPolicies = @() }

      # PhishThresholdLevel: 1=Standard (default), 2=Aggressive, 3=More aggressive, 4=Most aggressive
      # Standard/Strict preset = PhishThresholdLevel >= 2 and not IsDefault
      $strictPolicies  = @($antiPhishPolicies | Where-Object { $_.IsDefault -ne $true -and $_.PhishThresholdLevel -ge 2 })
      $hasStrictPreset = $strictPolicies.Count -gt 0
      $apStatus        = if ($hasStrictPreset) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'MAIL-001' -RunId $runId `
          -Title 'Anti-Phishing Policy Using Default (Non-Strict) Preset' `
          -Category 'Email Security' -Severity 'High' -RiskScore 78 `
          -SecureScoreVisibility 'Partial' -Status $apStatus `
          -Evidence @{
              policyCount         = $antiPhishPolicies.Count
              hasStrictPreset     = $hasStrictPreset
              defaultOnlyPresent  = ($antiPhishPolicies.Count -eq 1 -and $antiPhishPolicies[0].IsDefault)
          } `
          -GraphEndpoint $null -SupportsRemediation $true))

      # --- Safe Links ---
      $safeLinks = @()
      try {
          $slResult  = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                           -CmdletName 'Get-SafeLinksPolicy' -Parameters @{} `
                           -OperationType 'Read' -Caller 'Auditor'
          $safeLinks = @($slResult.Result | Where-Object { $_.IsEnabled -eq $true -or $_.EnableSafeLinksForEmail -eq $true })
      } catch { $safeLinks = @() }

      $slStatus = if ($safeLinks.Count -gt 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'MAIL-001' -RunId $runId `
          -Title 'Safe Links Not Configured' `
          -Category 'Email Security' -Severity 'High' -RiskScore 76 `
          -SecureScoreVisibility 'Partial' -Status $slStatus `
          -Evidence @{ enabledPolicyCount = $safeLinks.Count } `
          -GraphEndpoint $null -SupportsRemediation $true))

      # --- Safe Attachments ---
      $safeAttach = @()
      try {
          $saResult   = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                            -CmdletName 'Get-SafeAttachmentPolicy' -Parameters @{} `
                            -OperationType 'Read' -Caller 'Auditor'
          $safeAttach = @($saResult.Result | Where-Object { $_.Enable -eq $true })
      } catch { $safeAttach = @() }

      $saStatus = if ($safeAttach.Count -gt 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'MAIL-001' -RunId $runId `
          -Title 'Safe Attachments Not Configured' `
          -Category 'Email Security' -Severity 'High' -RiskScore 76 `
          -SecureScoreVisibility 'Partial' -Status $saStatus `
          -Evidence @{ enabledPolicyCount = $safeAttach.Count } `
          -GraphEndpoint $null -SupportsRemediation $true))

      return $findings.ToArray()
  }

  function Invoke-Remediation {
      [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          $ExchangeGateway,
          [Parameter(Mandatory)] $Finding,
          [Parameter(Mandatory)] $PSCmdlet
      )

      $actions = [System.Collections.Generic.List[object]]::new()
      $tenantMasked = ($GraphGateway.TenantId -replace '(.{4}).+(.{4})', '$1-...-$2')

      if ($Finding.title -match 'DKIM') {
          foreach ($domain in $Finding.evidence.disabledDomains) {
              if ($PSCmdlet.ShouldProcess("DKIM for $domain", 'Enable-DkimSigningConfig')) {
                  $actions.Add((New-RemediationAction `
                      -RunId $GraphGateway.RunId -CheckId 'MAIL-001' `
                      -CheckName 'Check-EmailAuthentication' -FindingId $Finding.id `
                      -ActionId "ACT-MAIL-ENABLE-DKIM-$($domain.Replace('.','_').ToUpper())" `
                      -Operation 'Write' -ResourceType 'DkimSigningConfig' `
                      -ResourceId $domain -Target "Enable DKIM signing for $domain" `
                      -Provider 'Exchange' -Phase 4 -Order 1 `
                      -Dependencies @() -ConflictsWith @() -Priority 2 `
                      -SafetyLevel 'Medium' -Category 'EmailSecurity' `
                      -TenantIdMasked $tenantMasked `
                      -CmdletName 'Get-DkimSigningConfig' `
                      -Parameters @{ Identity = $domain } `
                      -WriteCmdletName 'Set-DkimSigningConfig' `
                      -WriteParameters @{ Identity = $domain; Enabled = $true }))
              }
          }
      }

      return $actions.ToArray()
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-EmailAuthentication.Tests.ps1 -Output Detailed
  ```

  Expected: all 7 tests pass.

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-EmailAuthentication.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/checks/Check-EmailAuthentication.ps1 tests/checks/Check-EmailAuthentication.Tests.ps1
  git commit -m "feat: implement Check-EmailAuthentication (DKIM, anti-phish preset, Safe Links, Safe Attachments)"
  ```

---

### Task 32: Check-DLP

**Files:**
- Create: `src/Private/checks/Check-DLP.ps1`
- Create: `tests/checks/Check-DLP.Tests.ps1`

> **API note:** `dataSource='Exchange'`. Uses Exchange Online PS: `Get-DlpCompliancePolicy`, `Get-DlpComplianceRule`. Secret auth → NotAssessed. Policy `Mode` values: `Enable` (enforced) | `AuditAndNotify` | `TestWithNotifications` | `Disable`.

- [ ] **Step 1: Write failing tests**

  Create `tests/checks/Check-DLP.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-DLP.ps1"

      function New-MockGw {
          [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; RunId='run-001'; Connected=$true }
      }
      function New-MockExGw {
          [PSCustomObject]@{ PSTypeName='Metis.ExchangeGateway'; AuthMethod='Certificate'; Connected=$true }
      }
  }

  Describe 'Get-CheckMetadata' {
      It 'id is DLP-001'         { (Get-CheckMetadata).id         | Should -Be 'DLP-001' }
      It 'dataSource is Exchange' { (Get-CheckMetadata).dataSource | Should -Be 'Exchange' }
      It 'severity is High'      { (Get-CheckMetadata).severity   | Should -Be 'High' }
      It 'excludes Secret from assessAuthMethods' {
          (Get-CheckMetadata).assessAuthMethods | Should -Not -Contain 'Secret'
      }
  }

  Describe 'Invoke-Check — Secret auth guard' {
      It 'returns NotAssessed for Secret auth' {
          $gw = New-MockGw; $gw.AuthMethod = 'Secret'
          $f  = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $null }
          $f[0].status | Should -Be 'NotAssessed'
          $f[0].error.message | Should -Match 'ExchangeAuthNotSupported'
      }
  }

  Describe 'Invoke-Check — no policies' {
      It 'returns Fail DLP-ABSENT when no DLP policies exist' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-ExchangeRequest { [PSCustomObject]@{ Result = @() } }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $absentF = $findings | Where-Object { $_.title -match 'No DLP' }
          $absentF.status | Should -Be 'Fail'
      }
  }

  Describe 'Invoke-Check — simulation mode' {
      It 'returns Fail DLP-SIMULATION when all policies in AuditAndNotify or Disable mode' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-DlpCompliancePolicy') {
                  return [PSCustomObject]@{ Result = @(
                      [PSCustomObject]@{ Name='DLP-Audit'; Mode='AuditAndNotify'; Workload='Exchange,SharePoint' }
                  )}
              }
              return [PSCustomObject]@{ Result = @() }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $simF = $findings | Where-Object { $_.title -match 'Simulation' }
          $simF.status | Should -Be 'Fail'
          $simF.evidence.simulationModeCount | Should -Be 1
      }
  }

  Describe 'Invoke-Check — enforced policy' {
      It 'returns Pass DLP-SIMULATION when at least one policy is Enable mode' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-DlpCompliancePolicy') {
                  return [PSCustomObject]@{ Result = @(
                      [PSCustomObject]@{ Name='DLP-Enforced'; Mode='Enable'; Workload='Exchange,SharePoint,Teams' }
                  )}
              }
              return [PSCustomObject]@{ Result = @() }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $simF = $findings | Where-Object { $_.title -match 'Simulation' }
          $simF.status | Should -Be 'Pass'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-DLP.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Check-DLP.ps1**

  Create `src/Private/checks/Check-DLP.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-CheckMetadata {
      @{
          id                    = 'DLP-001'
          title                 = 'Data Loss Prevention Assessment'
          category              = 'Data Protection'
          severity              = 'High'
          riskScoreBaseline     = 78
          secureScoreVisibility = 'Passes'
          description           = 'Evaluates DLP compliance policies across workloads. Identifies absent policies, simulation-mode-only coverage, and workload gaps. DLP policies in AuditAndNotify mode pass Secure Score but do not enforce.'
          requiredPermissions   = @('InformationProtectionPolicy.Read.All')
          requiredExchangeRoles = @('Compliance Management')
          dataSource            = 'Exchange'
          supportsRemediation   = $true
          edition               = @('Lite', 'Premium')
          assessAuthMethods     = @('Certificate', 'Delegated')
      }
  }

  function Invoke-Check {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          [Parameter(Mandatory)] $Config
      )

      $runId    = $GraphGateway.RunId
      $findings = [System.Collections.Generic.List[object]]::new()
      $exGw     = $Config.ExchangeGateway

      if ($GraphGateway.AuthMethod -eq 'Secret') {
          $findings.Add((New-Finding -CheckId 'DLP-001' -RunId $runId `
              -Title 'DLP Assessment Unavailable' `
              -Category 'Data Protection' -Severity 'High' -RiskScore 78 `
              -SecureScoreVisibility 'Passes' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint $null -SupportsRemediation $false `
              -ErrorMessage 'ExchangeAuthNotSupported'))
          return $findings.ToArray()
      }

      $policies = @()
      try {
          $result   = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                          -CmdletName 'Get-DlpCompliancePolicy' -Parameters @{} `
                          -OperationType 'Read' -Caller 'Auditor'
          $policies = @($result.Result)
      } catch {
          $findings.Add((New-Finding -CheckId 'DLP-001' -RunId $runId `
              -Title 'DLP Assessment Failed' `
              -Category 'Data Protection' -Severity 'High' -RiskScore 78 `
              -SecureScoreVisibility 'Passes' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint $null -SupportsRemediation $false `
              -ErrorMessage $_.Exception.Message))
          return $findings.ToArray()
      }

      # --- Finding 1: No policies at all ---
      $absentStatus = if ($policies.Count -gt 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'DLP-001' -RunId $runId `
          -Title 'No DLP Compliance Policies Configured' `
          -Category 'Data Protection' -Severity 'High' -RiskScore 78 `
          -SecureScoreVisibility 'Passes' -Status $absentStatus `
          -Evidence @{
              policyCount        = $policies.Count
              dlpPoliciesPresent = ($policies.Count -gt 0)
          } `
          -GraphEndpoint $null -SupportsRemediation $true))

      if ($policies.Count -eq 0) { return $findings.ToArray() }

      # --- Finding 2: All policies in simulation/audit mode ---
      $enforcedPolicies    = @($policies | Where-Object { $_.Mode -eq 'Enable' })
      $simulationPolicies  = @($policies | Where-Object { $_.Mode -in @('AuditAndNotify', 'TestWithNotifications', 'Disable') })
      $simStatus = if ($enforcedPolicies.Count -gt 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'DLP-001' -RunId $runId `
          -Title 'DLP Policies in Simulation Mode Only (Not Enforced)' `
          -Category 'Data Protection' -Severity 'High' -RiskScore 72 `
          -SecureScoreVisibility 'Passes' -Status $simStatus `
          -Evidence @{
              totalPolicies       = $policies.Count
              enforcedCount       = $enforcedPolicies.Count
              simulationModeCount = $simulationPolicies.Count
              simulationNames     = @($simulationPolicies | Select-Object -ExpandProperty Name)
          } `
          -GraphEndpoint $null -SupportsRemediation $true))

      # --- Finding 3: Coverage gaps (Exchange, SharePoint, Teams) ---
      $requiredWorkloads = @('Exchange', 'SharePoint', 'Teams')
      $coveredWorkloads  = @()
      foreach ($policy in $policies) {
          if ($policy.Workload) {
              $coveredWorkloads += $policy.Workload -split ','
          }
      }
      $coveredWorkloads = @($coveredWorkloads | Select-Object -Unique)
      $missingWorkloads = @($requiredWorkloads | Where-Object { $_ -notin $coveredWorkloads })
      $coverageStatus   = if ($missingWorkloads.Count -eq 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'DLP-001' -RunId $runId `
          -Title 'DLP Policy Coverage Gaps Across Key Workloads' `
          -Category 'Data Protection' -Severity 'High' -RiskScore 68 `
          -SecureScoreVisibility 'Passes' -Status $coverageStatus `
          -Evidence @{
              requiredWorkloads = $requiredWorkloads
              coveredWorkloads  = $coveredWorkloads
              missingWorkloads  = $missingWorkloads
          } `
          -GraphEndpoint $null -SupportsRemediation $true))

      return $findings.ToArray()
  }

  function Invoke-Remediation {
      [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          $ExchangeGateway,
          [Parameter(Mandatory)] $Finding,
          [Parameter(Mandatory)] $PSCmdlet
      )

      $actions      = [System.Collections.Generic.List[object]]::new()
      $tenantMasked = ($GraphGateway.TenantId -replace '(.{4}).+(.{4})', '$1-...-$2')

      if ($Finding.title -match 'Simulation Mode') {
          $simPolicies = $Finding.evidence.simulationNames
          foreach ($policyName in $simPolicies) {
              if ($PSCmdlet.ShouldProcess($policyName, 'Set DLP policy mode to Enable')) {
                  $actions.Add((New-RemediationAction `
                      -RunId $GraphGateway.RunId -CheckId 'DLP-001' `
                      -CheckName 'Check-DLP' -FindingId $Finding.id `
                      -ActionId "ACT-DLP-ENABLE-POLICY-$($policyName.Replace(' ','_').ToUpper())" `
                      -Operation 'Write' -ResourceType 'DlpCompliancePolicy' `
                      -ResourceId $policyName `
                      -Target "Set-DlpCompliancePolicy -Identity '$policyName' -Mode Enable" `
                      -Provider 'Exchange' -Phase 4 -Order 2 `
                      -Dependencies @() -ConflictsWith @() -Priority 2 `
                      -SafetyLevel 'High' -Category 'DataProtection' `
                      -TenantIdMasked $tenantMasked `
                      -CmdletName 'Get-DlpCompliancePolicy' `
                      -Parameters @{ Identity = $policyName } `
                      -WriteCmdletName 'Set-DlpCompliancePolicy' `
                      -WriteParameters @{ Identity = $policyName; Mode = 'Enable' }))
              }
          }
      }

      return $actions.ToArray()
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-DLP.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-DLP.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/checks/Check-DLP.ps1 tests/checks/Check-DLP.Tests.ps1
  git commit -m "feat: implement Check-DLP (absent policies, simulation mode, workload coverage gaps)"
  ```

---

### Task 33: Check-GuestAccess

**Files:**
- Create: `src/Private/checks/Check-GuestAccess.ps1`
- Create: `tests/checks/Check-GuestAccess.Tests.ps1`

> **API note:** `dataSource='Graph'`. `GET /policies/authorizationPolicy` → `Get-MgPolicyAuthorizationPolicy` from `Microsoft.Graph.Identity.SignIns`. `GET /users?$filter=userType eq 'Guest'&$select=id,signInActivity` → requires `AuditLog.Read.All` for `signInActivity`. Stale guest = last sign-in older than 365 days.

- [ ] **Step 1: Write failing tests**

  Create `tests/checks/Check-GuestAccess.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-GuestAccess.ps1"

      function New-MockGw {
          [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; RunId='run-001'; Connected=$true }
      }
  }

  Describe 'Get-CheckMetadata' {
      It 'id is GUEST-001'       { (Get-CheckMetadata).id         | Should -Be 'GUEST-001' }
      It 'dataSource is Graph'   { (Get-CheckMetadata).dataSource | Should -Be 'Graph' }
      It 'severity is High'      { (Get-CheckMetadata).severity   | Should -Be 'High' }
      It 'has Policy.Read.All'   { (Get-CheckMetadata).requiredPermissions | Should -Contain 'Policy.Read.All' }
      It 'has AuditLog.Read.All' { (Get-CheckMetadata).requiredPermissions | Should -Contain 'AuditLog.Read.All' }
  }

  Describe 'Invoke-Check — open invitations' {
      It 'returns Fail GUEST-OPEN when allowInvitesFrom is everyone' {
          $gw = New-MockGw
          Mock Invoke-GraphRequest {
              param($Uri)
              if ($Uri -match 'authorizationPolicy') {
                  return [PSCustomObject]@{ Result = @{
                      allowInvitesFrom         = 'everyone'
                      allowedToSignUpEmailBasedSubscriptions = $true
                      guestUserRoleId          = '10dae51f-b6af-4016-8d66-8c2a99b929b3'
                  }}
              }
              return [PSCustomObject]@{ Result = @{ value = @() } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $inviteF = $findings | Where-Object { $_.title -match 'Invitation' -or $_.title -match 'Invite' }
          $inviteF.status | Should -Be 'Fail'
          $inviteF.evidence.allowInvitesFrom | Should -Be 'everyone'
      }
  }

  Describe 'Invoke-Check — stale guests' {
      It 'returns Fail GUEST-STALE when guests have no sign-in in 365+ days' {
          $gw = New-MockGw
          $staleDate = [System.DateTime]::UtcNow.AddDays(-400).ToString('o')
          Mock Invoke-GraphRequest {
              param($Uri)
              if ($Uri -match 'authorizationPolicy') {
                  return [PSCustomObject]@{ Result = @{
                      allowInvitesFrom = 'adminsAndGuestInviters'
                      guestUserRoleId  = '10dae51f-b6af-4016-8d66-8c2a99b929b3'
                  }}
              }
              if ($Uri -match 'users') {
                  return [PSCustomObject]@{ Result = @{ value = @(
                      [PSCustomObject]@{
                          id           = 'guest-001'
                          displayName  = 'External User'
                          userType     = 'Guest'
                          signInActivity = [PSCustomObject]@{ lastSignInDateTime = $staleDate }
                      }
                  )}}
              }
              return [PSCustomObject]@{ Result = @{ value = @() } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $staleF = $findings | Where-Object { $_.title -match 'Stale' }
          $staleF.status | Should -Be 'Fail'
          $staleF.evidence.staleGuestCount | Should -Be 1
      }
  }

  Describe 'Invoke-Check — restricted invitations pass' {
      It 'returns Pass when allowInvitesFrom is adminsAndGuestInviters' {
          $gw = New-MockGw
          Mock Invoke-GraphRequest {
              param($Uri)
              if ($Uri -match 'authorizationPolicy') {
                  return [PSCustomObject]@{ Result = @{
                      allowInvitesFrom = 'adminsAndGuestInviters'
                      guestUserRoleId  = '10dae51f-b6af-4016-8d66-8c2a99b929b3'
                  }}
              }
              return [PSCustomObject]@{ Result = @{ value = @() } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $inviteF = $findings | Where-Object { $_.title -match 'Invitation' -or $_.title -match 'Invite' }
          $inviteF.status | Should -Be 'Pass'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-GuestAccess.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Check-GuestAccess.ps1**

  Create `src/Private/checks/Check-GuestAccess.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-CheckMetadata {
      @{
          id                    = 'GUEST-001'
          title                 = 'Guest Access Assessment'
          category              = 'Identity Security'
          severity              = 'High'
          riskScoreBaseline     = 75
          secureScoreVisibility = 'NotFlagged'
          description           = 'Evaluates external collaboration settings (allowInvitesFrom), stale guest accounts with no sign-in in 365+ days, and absence of guest access review policies.'
          requiredPermissions   = @('Policy.Read.All', 'User.Read.All', 'AuditLog.Read.All')
          requiredExchangeRoles = @()
          dataSource            = 'Graph'
          supportsRemediation   = $true
          edition               = @('Lite', 'Premium')
          assessAuthMethods     = @('Certificate', 'Secret', 'Delegated')
      }
  }

  function Invoke-Check {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          [Parameter(Mandatory)] $Config
      )

      $runId    = $GraphGateway.RunId
      $findings = [System.Collections.Generic.List[object]]::new()

      # --- Authorization policy ---
      $authPolicy = $null
      try {
          $resp       = Invoke-GraphRequest -GraphGateway $GraphGateway `
                            -Uri '/policies/authorizationPolicy' -Method 'GET' `
                            -OperationType 'Read' -Caller 'Auditor'
          $authPolicy = $resp.Result
      } catch {
          $findings.Add((New-Finding -CheckId 'GUEST-001' -RunId $runId `
              -Title 'Guest Access Assessment Failed' `
              -Category 'Identity Security' -Severity 'High' -RiskScore 75 `
              -SecureScoreVisibility 'NotFlagged' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint '/policies/authorizationPolicy' -SupportsRemediation $false `
              -ErrorMessage $_.Exception.Message))
          return $findings.ToArray()
      }

      # --- Finding 1: Open guest invitations ---
      $allowInvitesFrom = $authPolicy.allowInvitesFrom
      $openInviteValues = @('everyone', 'adminsGuestInvitersAndAllMembers')
      if (-not $allowInvitesFrom) {
          # Property absent from API response — fail closed (unknown state = assume permissive)
          $openInviteStatus = 'Fail'
          $allowInvitesFrom = 'unknown'
      } else {
          $openInviteStatus = if ($allowInvitesFrom -notin $openInviteValues) { 'Pass' } else { 'Fail' }
      }
      $findings.Add((New-Finding -CheckId 'GUEST-001' -RunId $runId `
          -Title 'Guest Invitation Policy Too Permissive' `
          -Category 'Identity Security' -Severity 'High' -RiskScore 75 `
          -SecureScoreVisibility 'NotFlagged' -Status $openInviteStatus `
          -Evidence @{
              allowInvitesFrom         = $allowInvitesFrom
              recommendedValue         = 'adminsAndGuestInviters'
              isOpenToEveryone         = ($allowInvitesFrom -in $openInviteValues)
          } `
          -GraphEndpoint '/policies/authorizationPolicy' -SupportsRemediation $true))

      # --- Guest users + stale check ---
      $guests = @()
      try {
          $guestResp = Invoke-GraphRequest -GraphGateway $GraphGateway `
                           -Uri "/users?`$filter=userType eq 'Guest'&`$select=id,displayName,mail,userType,signInActivity" `
                           -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
          $guests    = @($guestResp.Result.value)
      } catch { $guests = @() }

      $staleCutoff = [System.DateTime]::UtcNow.AddDays(-365)
      $staleGuests = @($guests | Where-Object {
          $lastSignIn = $_.signInActivity.lastSignInDateTime
          if (-not $lastSignIn) { return $true }   # never signed in = stale
          $parsed = [System.DateTime]::MinValue
          if ([System.DateTime]::TryParse($lastSignIn, [ref]$parsed)) {
              $parsed -lt $staleCutoff
          } else {
              $true   # unparseable date = fail closed (treat as stale)
          }
      })
      $staleStatus = if ($staleGuests.Count -eq 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'GUEST-001' -RunId $runId `
          -Title 'Stale Guest Accounts Detected (No Sign-in in 365+ Days)' `
          -Category 'Identity Security' -Severity 'High' -RiskScore 70 `
          -SecureScoreVisibility 'NotFlagged' -Status $staleStatus `
          -Evidence @{
              totalGuestCount    = $guests.Count
              staleGuestCount    = $staleGuests.Count
              staleGuestIds      = @($staleGuests | Select-Object -First 10 -ExpandProperty id)
              staleCutoffDays    = 365
          } `
          -GraphEndpoint '/users' -SupportsRemediation $true))

      return $findings.ToArray()
  }

  function Invoke-Remediation {
      [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          $ExchangeGateway,
          [Parameter(Mandatory)] $Finding,
          [Parameter(Mandatory)] $PSCmdlet
      )

      $actions      = [System.Collections.Generic.List[object]]::new()
      $tenantMasked = ($GraphGateway.TenantId -replace '(.{4}).+(.{4})', '$1-...-$2')

      if ($Finding.title -match 'Invitation Policy') {
          if ($PSCmdlet.ShouldProcess('authorizationPolicy', 'Restrict guest invitations to admins and designated inviters')) {
              $actions.Add((New-RemediationAction `
                  -RunId $GraphGateway.RunId -CheckId 'GUEST-001' `
                  -CheckName 'Check-GuestAccess' -FindingId $Finding.id `
                  -ActionId 'ACT-GUEST-RESTRICT-INVITATIONS' `
                  -Operation 'PATCH' -ResourceType 'AuthorizationPolicy' `
                  -ResourceId 'authorizationPolicy' `
                  -Target 'Set allowInvitesFrom to adminsAndGuestInviters' `
                  -Provider 'Graph' -Phase 2 -Order 3 `
                  -Dependencies @() -ConflictsWith @() -Priority 2 `
                  -SafetyLevel 'Medium' -Category 'Identity' `
                  -TenantIdMasked $tenantMasked `
                  -Endpoint '/policies/authorizationPolicy' `
                  -HttpMethod 'PATCH' `
                  -Body @{ allowInvitesFrom = 'adminsAndGuestInviters' }))
          }
      }

      return $actions.ToArray()
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-GuestAccess.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-GuestAccess.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/checks/Check-GuestAccess.ps1 tests/checks/Check-GuestAccess.Tests.ps1
  git commit -m "feat: implement Check-GuestAccess (invitation policy, stale guest detection)"
  ```

---

### Task 34: Check-DeviceCompliance

**Files:**
- Create: `src/Private/checks/Check-DeviceCompliance.ps1`
- Create: `tests/checks/Check-DeviceCompliance.Tests.ps1`

> **API note:** `dataSource='Graph'`. `GET /deviceManagement/deviceCompliancePolicies` → `Get-MgDeviceManagementDeviceCompliancePolicy` from `Microsoft.Graph.DeviceManagement`. Also queries CA policies (`GET /identity/conditionalAccess/policies`) to detect CA→device-compliance gap: CA requires compliant device but no compliance policy is defined.

- [ ] **Step 1: Write failing tests**

  Create `tests/checks/Check-DeviceCompliance.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-DeviceCompliance.ps1"

      function New-MockGw {
          [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; RunId='run-001'; Connected=$true }
      }
  }

  Describe 'Get-CheckMetadata' {
      It 'id is DEV-001'                  { (Get-CheckMetadata).id         | Should -Be 'DEV-001' }
      It 'dataSource is Graph'            { (Get-CheckMetadata).dataSource | Should -Be 'Graph' }
      It 'severity is High'               { (Get-CheckMetadata).severity   | Should -Be 'High' }
      It 'has DeviceManagement permission' {
          (Get-CheckMetadata).requiredPermissions | Should -Contain 'DeviceManagementConfiguration.Read.All'
      }
  }

  Describe 'Invoke-Check — no compliance policies' {
      It 'returns Fail DEV-NO-POLICIES when no policies exist' {
          $gw = New-MockGw
          Mock Invoke-GraphRequest {
              [PSCustomObject]@{ Result = @{ value = @() } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $noPolF = $findings | Where-Object { $_.title -match 'No.*Compliance' }
          $noPolF.status | Should -Be 'Fail'
          $noPolF.evidence.compliancePolicyCount | Should -Be 0
      }
  }

  Describe 'Invoke-Check — CA requires compliant device but no policy' {
      It 'returns Fail DEV-CA-MISMATCH when CA requires compliant device but no compliance policy' {
          $gw = New-MockGw
          $caPolicy = [PSCustomObject]@{
              id    = 'ca-001'
              state = 'enabled'
              grantControls = [PSCustomObject]@{ builtInControls = @('compliantDevice') }
          }
          Mock Invoke-GraphRequest {
              param($Uri)
              if ($Uri -match 'deviceCompliancePolicies') {
                  return [PSCustomObject]@{ Result = @{ value = @() } }
              }
              if ($Uri -match 'conditionalAccess') {
                  return [PSCustomObject]@{ Result = @{ value = @($caPolicy) } }
              }
              return [PSCustomObject]@{ Result = @{ value = @() } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $mismatchF = $findings | Where-Object { $_.title -match 'CA.*Mismatch|Mismatch.*CA|Compliant Device' }
          $mismatchF.status | Should -Be 'Fail'
      }
  }

  Describe 'Invoke-Check — compliance policy exists' {
      It 'returns Pass DEV-NO-POLICIES when at least one policy exists' {
          $gw = New-MockGw
          $policy = [PSCustomObject]@{ id='pol-001'; displayName='Win10 Compliance'; scheduledActionsForRule=@() }
          Mock Invoke-GraphRequest {
              param($Uri)
              if ($Uri -match 'deviceCompliancePolicies') {
                  return [PSCustomObject]@{ Result = @{ value = @($policy) } }
              }
              return [PSCustomObject]@{ Result = @{ value = @() } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $noPolF = $findings | Where-Object { $_.title -match 'No.*Compliance' }
          $noPolF.status | Should -Be 'Pass'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-DeviceCompliance.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Check-DeviceCompliance.ps1**

  Create `src/Private/checks/Check-DeviceCompliance.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-CheckMetadata {
      @{
          id                    = 'DEV-001'
          title                 = 'Device Compliance Assessment'
          category              = 'Device Security'
          severity              = 'High'
          riskScoreBaseline     = 72
          secureScoreVisibility = 'NotFlagged'
          description           = 'Evaluates device compliance policy existence, CA policy alignment (CA requires compliant device but no compliance policy defined), and coverage gaps for enrolled devices.'
          requiredPermissions   = @('DeviceManagementConfiguration.Read.All', 'Policy.Read.All')
          requiredExchangeRoles = @()
          dataSource            = 'Graph'
          supportsRemediation   = $true
          edition               = @('Lite', 'Premium')
          assessAuthMethods     = @('Certificate', 'Secret', 'Delegated')
      }
  }

  function Invoke-Check {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          [Parameter(Mandatory)] $Config
      )

      $runId    = $GraphGateway.RunId
      $findings = [System.Collections.Generic.List[object]]::new()

      # --- Device compliance policies ---
      $compliancePolicies = @()
      try {
          $resp               = Invoke-GraphRequest -GraphGateway $GraphGateway `
                                    -Uri '/deviceManagement/deviceCompliancePolicies' `
                                    -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
          $compliancePolicies = @($resp.Result.value)
      } catch {
          $findings.Add((New-Finding -CheckId 'DEV-001' -RunId $runId `
              -Title 'Device Compliance Assessment Failed' `
              -Category 'Device Security' -Severity 'High' -RiskScore 72 `
              -SecureScoreVisibility 'NotFlagged' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint '/deviceManagement/deviceCompliancePolicies' `
              -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
          return $findings.ToArray()
      }

      # --- Finding 1: No compliance policies ---
      $noPolicyStatus = if ($compliancePolicies.Count -gt 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'DEV-001' -RunId $runId `
          -Title 'No Device Compliance Policies Configured' `
          -Category 'Device Security' -Severity 'High' -RiskScore 72 `
          -SecureScoreVisibility 'NotFlagged' -Status $noPolicyStatus `
          -Evidence @{
              compliancePolicyCount = $compliancePolicies.Count
              policyNames           = @($compliancePolicies | Select-Object -ExpandProperty displayName)
          } `
          -GraphEndpoint '/deviceManagement/deviceCompliancePolicies' -SupportsRemediation $true))

      # --- CA policy alignment check ---
      $caPolicies = @()
      try {
          $caResp     = Invoke-GraphRequest -GraphGateway $GraphGateway `
                            -Uri '/identity/conditionalAccess/policies' `
                            -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
          $caPolicies = @($caResp.Result.value)
      } catch { $caPolicies = @() }

      $caRequiresCompliance = @($caPolicies | Where-Object {
          $_.state -eq 'enabled' -and
          $_.grantControls -and
          $_.grantControls.builtInControls -contains 'compliantDevice'
      })

      # Only emit this finding when at least one CA policy enforces device compliance.
      # Emitting it unconditionally produces a misleading Pass when no CA requires compliance.
      if ($caRequiresCompliance.Count -gt 0) {
          $mismatchStatus = if ($compliancePolicies.Count -eq 0) { 'Fail' } else { 'Pass' }
          $findings.Add((New-Finding -CheckId 'DEV-001' -RunId $runId `
              -Title 'CA Policy Requires Compliant Device But No Compliance Policy Exists' `
              -Category 'Device Security' -Severity 'High' -RiskScore 78 `
              -SecureScoreVisibility 'NotFlagged' -Status $mismatchStatus `
              -Evidence @{
                  caRequiresComplianceCount = $caRequiresCompliance.Count
                  compliancePolicyCount     = $compliancePolicies.Count
                  caGapPresent              = ($compliancePolicies.Count -eq 0)
              } `
              -GraphEndpoint '/identity/conditionalAccess/policies' -SupportsRemediation $true))
      }

      return $findings.ToArray()
  }

  function Invoke-Remediation {
      [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          $ExchangeGateway,
          [Parameter(Mandatory)] $Finding,
          [Parameter(Mandatory)] $PSCmdlet
      )

      $actions      = [System.Collections.Generic.List[object]]::new()
      $tenantMasked = ($GraphGateway.TenantId -replace '(.{4}).+(.{4})', '$1-...-$2')

      if ($Finding.title -match 'No Device Compliance') {
          if ($PSCmdlet.ShouldProcess('Intune', 'Create baseline Windows device compliance policy')) {
              $body = @{
                  '@odata.type'   = '#microsoft.graph.windows10CompliancePolicy'
                  displayName     = 'Metis-Baseline-Windows-Compliance'
                  description     = 'Baseline compliance policy deployed by M365 Security Assessment Tool'
                  passwordRequired = $true
                  passwordMinimumLength = 8
                  storageRequireEncryption = $true
              }
              $actions.Add((New-RemediationAction `
                  -RunId $GraphGateway.RunId -CheckId 'DEV-001' `
                  -CheckName 'Check-DeviceCompliance' -FindingId $Finding.id `
                  -ActionId 'ACT-DEV-CREATE-COMPLIANCE-POLICY' `
                  -Operation 'POST' -ResourceType 'DeviceCompliancePolicy' `
                  -ResourceId $null -Target 'Create baseline Windows 10 device compliance policy' `
                  -Provider 'Graph' -Phase 4 -Order 1 `
                  -Dependencies @('ACT-CA-ENABLE-MFA') -ConflictsWith @() -Priority 2 `
                  -SafetyLevel 'Medium' -Category 'Device' `
                  -TenantIdMasked $tenantMasked `
                  -Endpoint '/deviceManagement/deviceCompliancePolicies' `
                  -HttpMethod 'POST' -Body $body))
          }
      }

      return $actions.ToArray()
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-DeviceCompliance.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-DeviceCompliance.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/checks/Check-DeviceCompliance.ps1 tests/checks/Check-DeviceCompliance.Tests.ps1
  git commit -m "feat: implement Check-DeviceCompliance (no policies, CA mismatch detection)"
  ```
