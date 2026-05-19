# M365 Security Assessment Tool — Tasks 35–38

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Prerequisite:** Tasks 1–34 complete.

**Goal:** Implement Check-SmtpAuth, Check-SharePointSharing (with ExchangeGateway SPO extension), Check-AuditLogging, Check-SensitivityLabels, Check-DefenderOffice365, Check-CloudAppSecurity.

---

### Task 35: Check-SmtpAuth

**Files:**
- Create: `src/Private/checks/Check-SmtpAuth.ps1`
- Create: `tests/checks/Check-SmtpAuth.Tests.ps1`

> **API note:** `dataSource='Both'`. Graph: `GET /organization` → `SmtpClientAuthenticationDisabled` (org-level). Exchange: `Get-TransportConfig` → `SmtpClientAuthenticationDisabled` (org transport config) and `Get-CASMailbox -ResultSize Unlimited` → per-mailbox overrides. Secret auth → NotAssessed (Exchange component unavailable).

- [ ] **Step 1: Write failing tests**

  Create `tests/checks/Check-SmtpAuth.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-SmtpAuth.ps1"

      function New-MockGw {
          [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; RunId='run-001'; Connected=$true }
      }
      function New-MockExGw {
          [PSCustomObject]@{ PSTypeName='Metis.ExchangeGateway'; AuthMethod='Certificate'; Connected=$true }
      }
  }

  Describe 'Get-CheckMetadata' {
      It 'id is SMTP-001'        { (Get-CheckMetadata).id         | Should -Be 'SMTP-001' }
      It 'dataSource is Exchange' { (Get-CheckMetadata).dataSource | Should -Be 'Exchange' }
      It 'severity is High'      { (Get-CheckMetadata).severity   | Should -Be 'High' }
      It 'excludes Secret'       { (Get-CheckMetadata).assessAuthMethods | Should -Not -Contain 'Secret' }
  }

  Describe 'Invoke-Check — Secret auth guard' {
      It 'returns NotAssessed for Secret auth' {
          $gw = New-MockGw; $gw.AuthMethod = 'Secret'
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $null }
          $findings[0].status | Should -Be 'NotAssessed'
          $findings[0].error.message | Should -Match 'ExchangeAuthNotSupported'
      }
  }

  Describe 'Invoke-Check — SMTP AUTH enabled tenant-level' {
      It 'returns Fail SMTP-TENANT when SmtpClientAuthenticationDisabled=false (SMTP AUTH on)' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-TransportConfig') {
                  return [PSCustomObject]@{ Result = [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $false } }
              }
              return [PSCustomObject]@{ Result = @() }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $tenantF = $findings | Where-Object { $_.title -match 'Tenant' -or $_.title -match 'SMTP AUTH.*Enabled' }
          $tenantF.status | Should -Be 'Fail'
          $tenantF.evidence.smtpAuthDisabledTenantLevel | Should -BeFalse
      }
  }

  Describe 'Invoke-Check — SMTP AUTH disabled tenant-level' {
      It 'returns Pass SMTP-TENANT when SmtpClientAuthenticationDisabled=true' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-TransportConfig') {
                  return [PSCustomObject]@{ Result = [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $true } }
              }
              return [PSCustomObject]@{ Result = @() }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $tenantF = $findings | Where-Object { $_.title -match 'Tenant' -or $_.title -match 'SMTP AUTH.*Enabled' }
          $tenantF.status | Should -Be 'Pass'
      }
  }

  Describe 'Invoke-Check — per-mailbox SMTP AUTH overrides' {
      It 'returns Fail SMTP-MAILBOX when mailboxes override tenant disable' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-GraphRequest {
              [PSCustomObject]@{ Result = @{ value = @([PSCustomObject]@{ id='org-001' }) } }
          }
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-TransportConfig') {
                  return [PSCustomObject]@{ Result = [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $true } }
              }
              if ($CmdletName -eq 'Get-CASMailbox') {
                  return [PSCustomObject]@{ Result = @(
                      [PSCustomObject]@{ Identity='user1@contoso.com'; SmtpClientAuthenticationDisabled=$false }
                  )}
              }
              return [PSCustomObject]@{ Result = @() }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $mbF = $findings | Where-Object { $_.title -match 'Mailbox' -or $_.title -match 'Override' }
          $mbF.status | Should -Be 'Fail'
          $mbF.evidence.mailboxOverrideCount | Should -Be 1
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-SmtpAuth.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Check-SmtpAuth.ps1**

  Create `src/Private/checks/Check-SmtpAuth.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-CheckMetadata {
      @{
          id                    = 'SMTP-001'
          title                 = 'SMTP Authentication Assessment'
          category              = 'Email Security'
          severity              = 'High'
          riskScoreBaseline     = 75
          secureScoreVisibility = 'NotFlagged'
          description           = 'Evaluates SMTP AUTH protocol status at tenant and per-mailbox levels. SMTP AUTH allows legacy clients to authenticate and bypasses modern auth security controls including MFA.'
          requiredPermissions   = @('Organization.Read.All')
          requiredExchangeRoles = @('View-Only Configuration', 'View-Only Recipients')
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
          $findings.Add((New-Finding -CheckId 'SMTP-001' -RunId $runId `
              -Title 'SMTP Authentication Assessment Unavailable' `
              -Category 'Email Security' -Severity 'High' -RiskScore 75 `
              -SecureScoreVisibility 'NotFlagged' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint '/organization' -SupportsRemediation $false `
              -ErrorMessage 'ExchangeAuthNotSupported'))
          return $findings.ToArray()
      }

      # --- Tenant-level SMTP AUTH state (Exchange transport config is authoritative) ---
      $transportConfig = $null
      try {
          $tcResult        = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                                 -CmdletName 'Get-TransportConfig' -Parameters @{} `
                                 -OperationType 'Read' -Caller 'Auditor'
          $transportConfig = $tcResult.Result
      } catch {
          $findings.Add((New-Finding -CheckId 'SMTP-001' -RunId $runId `
              -Title 'SMTP Authentication Assessment Failed' `
              -Category 'Email Security' -Severity 'High' -RiskScore 75 `
              -SecureScoreVisibility 'NotFlagged' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint $null -SupportsRemediation $false `
              -ErrorMessage $_.Exception.Message))
          return $findings.ToArray()
      }

      # SmtpClientAuthenticationDisabled = $true means SMTP AUTH is OFF (secure)
      $tenantDisabled = $transportConfig.SmtpClientAuthenticationDisabled -eq $true
      $tenantStatus   = if ($tenantDisabled) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'SMTP-001' -RunId $runId `
          -Title 'SMTP AUTH Enabled at Tenant Level' `
          -Category 'Email Security' -Severity 'High' -RiskScore 75 `
          -SecureScoreVisibility 'NotFlagged' -Status $tenantStatus `
          -Evidence @{
              smtpAuthDisabledTenantLevel = $tenantDisabled
              transportConfigValue        = $transportConfig.SmtpClientAuthenticationDisabled
          } `
          -GraphEndpoint $null -SupportsRemediation $true))

      # --- Per-mailbox overrides (mailboxes where SMTP AUTH re-enabled despite tenant disable) ---
      $mailboxOverrides = @()
      try {
          $mbResult         = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                                  -CmdletName 'Get-CASMailbox' -Parameters @{ ResultSize = 'Unlimited' } `
                                  -OperationType 'Read' -Caller 'Auditor'
          # SmtpClientAuthenticationDisabled=$false on a mailbox = SMTP AUTH explicitly RE-ENABLED for that box
          $mailboxOverrides = @($mbResult.Result | Where-Object {
              $_.SmtpClientAuthenticationDisabled -eq $false
          })
      } catch { $mailboxOverrides = @() }

      $mbStatus = if ($mailboxOverrides.Count -eq 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'SMTP-001' -RunId $runId `
          -Title 'Mailboxes with SMTP AUTH Override (Re-enabled Per-Mailbox)' `
          -Category 'Email Security' -Severity 'High' -RiskScore 68 `
          -SecureScoreVisibility 'NotFlagged' -Status $mbStatus `
          -Evidence @{
              mailboxOverrideCount     = $mailboxOverrides.Count
              mailboxIdentitySample    = @($mailboxOverrides | Select-Object -First 10 -ExpandProperty Identity)
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

      if ($Finding.title -match 'Tenant Level') {
          if ($PSCmdlet.ShouldProcess('TransportConfig', 'Disable SMTP AUTH at tenant level')) {
              $actions.Add((New-RemediationAction `
                  -RunId $GraphGateway.RunId -CheckId 'SMTP-001' `
                  -CheckName 'Check-SmtpAuth' -FindingId $Finding.id `
                  -ActionId 'ACT-SMTP-DISABLE-TENANT' `
                  -Operation 'Write' -ResourceType 'TransportConfig' `
                  -ResourceId $null -Target 'Set-TransportConfig -SmtpClientAuthenticationDisabled $true' `
                  -Provider 'Exchange' -Phase 5 -Order 1 `
                  -Dependencies @('ACT-CA-ENABLE-MFA') -ConflictsWith @() -Priority 3 `
                  -SafetyLevel 'High' -Category 'EmailSecurity' `
                  -TenantIdMasked $tenantMasked `
                  -CmdletName 'Get-TransportConfig' -Parameters @{} `
                  -WriteCmdletName 'Set-TransportConfig' `
                  -WriteParameters @{ SmtpClientAuthenticationDisabled = $true }))
          }
      }

      return $actions.ToArray()
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-SmtpAuth.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-SmtpAuth.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/checks/Check-SmtpAuth.ps1 tests/checks/Check-SmtpAuth.Tests.ps1
  git commit -m "feat: implement Check-SmtpAuth (tenant-level disable, per-mailbox override detection)"
  ```

---

### Task 36: Check-SharePointSharing

**Files:**
- Modify: `src/Private/ExchangeGateway.ps1` (add SPO connection support)
- Create: `src/Private/checks/Check-SharePointSharing.ps1`
- Create: `tests/checks/Check-SharePointSharing.Tests.ps1`

> **API note:** `dataSource='Exchange'` (SPO PowerShell). SPO cmdlets (`Get-SPOTenant`, `Get-SPOSite`) are from `Microsoft.Online.SharePoint.PowerShell` module — separate from ExchangeOnlineManagement. ExchangeGateway is extended to optionally connect to SPO via `Connect-SPOService` when `SpoAdminUrl` is set. ExchangeGateway `Invoke-ExchangeRequest` already calls `& $CmdletName @Parameters` generically, so SPO cmdlets work once the session is established. Secret auth → NotAssessed.

- [ ] **Step 1: Extend ExchangeGateway for SPO**

  Add `SpoAdminUrl` property to `New-ExchangeGateway` and an optional SPO connect block in `Connect-ExchangeGateway`. Open `src/Private/ExchangeGateway.ps1` and locate `New-ExchangeGateway`. Add `SpoAdminUrl = $SpoAdminUrl` to the returned object and a `$SpoAdminUrl` parameter to the function. Then in `Connect-ExchangeGateway`, after the Exchange session is established, add:

  ```powershell
  # In Connect-ExchangeGateway, after Connect-ExchangeOnline block:
  if ($ExchangeGateway.SpoAdminUrl) {
      $spoParams = @{ Url = $ExchangeGateway.SpoAdminUrl }
      if ($ExchangeGateway.AuthMethod -eq 'Certificate') {
          $spoParams['ClientId']   = $ExchangeGateway.ClientId
          $spoParams['Thumbprint'] = $ExchangeGateway.CertificateThumbprint
          $spoParams['Tenant']     = $ExchangeGateway.TenantId
      }
      Connect-SPOService @spoParams
  }
  ```

  In `New-ExchangeGateway`, add parameter and property:

  ```powershell
  # New parameter:
  [Parameter()][string] $SpoAdminUrl = $null

  # In returned PSCustomObject:
  SpoAdminUrl = $SpoAdminUrl
  ```

  Run existing ExchangeGateway tests to confirm no regressions:

  ```powershell
  Invoke-Pester -Path tests\ExchangeGateway.Tests.ps1 -Output Detailed
  ```

  Expected: all existing tests still pass.

- [ ] **Step 2: Write failing tests**

  Create `tests/checks/Check-SharePointSharing.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-SharePointSharing.ps1"

      function New-MockGw {
          [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; RunId='run-001'; Connected=$true }
      }
      function New-MockExGw {
          [PSCustomObject]@{ PSTypeName='Metis.ExchangeGateway'; AuthMethod='Certificate'; Connected=$true; SpoAdminUrl='https://contoso-admin.sharepoint.com' }
      }
  }

  Describe 'Get-CheckMetadata' {
      It 'id is SP-001'            { (Get-CheckMetadata).id         | Should -Be 'SP-001' }
      It 'dataSource is Exchange'  { (Get-CheckMetadata).dataSource | Should -Be 'Exchange' }
      It 'severity is High'        { (Get-CheckMetadata).severity   | Should -Be 'High' }
      It 'excludes Secret'         { (Get-CheckMetadata).assessAuthMethods | Should -Not -Contain 'Secret' }
  }

  Describe 'Invoke-Check — Secret auth guard' {
      It 'returns NotAssessed for Secret auth' {
          $gw = New-MockGw; $gw.AuthMethod = 'Secret'
          $f  = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $null }
          $f[0].status | Should -Be 'NotAssessed'
          $f[0].error.message | Should -Match 'ExchangeAuthNotSupported'
      }
  }

  Describe 'Invoke-Check — anonymous sharing enabled' {
      It 'returns Fail SP-ANON when SharingCapability includes anonymous links' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-SPOTenant') {
                  return [PSCustomObject]@{ Result = [PSCustomObject]@{
                      SharingCapability               = 'ExternalUserAndGuestSharing'
                      RequireAnonymousLinksExpireInDays = 0
                      DefaultSharingLinkType          = 'Anonymous'
                  }}
              }
              return [PSCustomObject]@{ Result = @() }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $anonF = $findings | Where-Object { $_.title -match 'Anonymous' }
          $anonF.status | Should -Be 'Fail'
          $anonF.evidence.sharingCapability | Should -Be 'ExternalUserAndGuestSharing'
      }
  }

  Describe 'Invoke-Check — anonymous sharing disabled' {
      It 'returns Pass SP-ANON when SharingCapability is ExternalUserSharingOnly or Disabled' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-SPOTenant') {
                  return [PSCustomObject]@{ Result = [PSCustomObject]@{
                      SharingCapability               = 'ExternalUserSharingOnly'
                      RequireAnonymousLinksExpireInDays = 30
                      DefaultSharingLinkType          = 'Internal'
                  }}
              }
              return [PSCustomObject]@{ Result = @() }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $anonF = $findings | Where-Object { $_.title -match 'Anonymous' }
          $anonF.status | Should -Be 'Pass'
      }
  }
  ```

- [ ] **Step 3: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-SharePointSharing.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 4: Implement Check-SharePointSharing.ps1**

  Create `src/Private/checks/Check-SharePointSharing.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-CheckMetadata {
      @{
          id                    = 'SP-001'
          title                 = 'SharePoint Sharing Assessment'
          category              = 'Data Protection'
          severity              = 'High'
          riskScoreBaseline     = 73
          secureScoreVisibility = 'Partial'
          description           = 'Evaluates SharePoint Online tenant sharing settings: anonymous link enablement, link expiry policy, and site-level overrides more permissive than the tenant policy. Requires Microsoft.Online.SharePoint.PowerShell module.'
          requiredPermissions   = @('Sites.Read.All')
          requiredExchangeRoles = @('SharePoint Administrator')
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
          $findings.Add((New-Finding -CheckId 'SP-001' -RunId $runId `
              -Title 'SharePoint Sharing Assessment Unavailable' `
              -Category 'Data Protection' -Severity 'High' -RiskScore 73 `
              -SecureScoreVisibility 'Partial' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint $null -SupportsRemediation $false `
              -ErrorMessage 'ExchangeAuthNotSupported'))
          return $findings.ToArray()
      }

      # --- SPO tenant settings ---
      $spoTenant = $null
      try {
          $result    = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                           -CmdletName 'Get-SPOTenant' -Parameters @{} `
                           -OperationType 'Read' -Caller 'Auditor'
          $spoTenant = $result.Result
      } catch {
          $findings.Add((New-Finding -CheckId 'SP-001' -RunId $runId `
              -Title 'SharePoint Sharing Assessment Failed' `
              -Category 'Data Protection' -Severity 'High' -RiskScore 73 `
              -SecureScoreVisibility 'Partial' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint $null -SupportsRemediation $false `
              -ErrorMessage $_.Exception.Message))
          return $findings.ToArray()
      }

      # SharingCapability values: Disabled | ExistingExternalUserSharingOnly | ExternalUserSharingOnly | ExternalUserAndGuestSharing
      $anonSharingValues = @('ExternalUserAndGuestSharing')
      $anonEnabled       = $spoTenant.SharingCapability -in $anonSharingValues
      $anonStatus        = if (-not $anonEnabled) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'SP-001' -RunId $runId `
          -Title 'Anonymous Link Sharing Enabled at Tenant Level' `
          -Category 'Data Protection' -Severity 'High' -RiskScore 73 `
          -SecureScoreVisibility 'Partial' -Status $anonStatus `
          -Evidence @{
              sharingCapability              = $spoTenant.SharingCapability
              anonymousSharingEnabled        = $anonEnabled
              recommendedValue               = 'ExternalUserSharingOnly'
          } `
          -GraphEndpoint $null -SupportsRemediation $true))

      # --- Anonymous link expiry ---
      $expiryDays   = $spoTenant.RequireAnonymousLinksExpireInDays
      # Pass when anonymous sharing is already disabled — expiry setting is irrelevant in that case
      $expiryStatus = if (-not $anonEnabled -or ($expiryDays -gt 0 -and $expiryDays -le 30)) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'SP-001' -RunId $runId `
          -Title 'Anonymous Links Have No Expiry Policy' `
          -Category 'Data Protection' -Severity 'High' -RiskScore 68 `
          -SecureScoreVisibility 'Partial' -Status $expiryStatus `
          -Evidence @{
              requireAnonymousLinksExpireInDays = $expiryDays
              noExpiry                          = ($expiryDays -eq 0)
              recommendedMaxDays                = 30
          } `
          -GraphEndpoint $null -SupportsRemediation $true))

      # --- Site-level overrides more permissive than tenant ---
      $sites = @()
      try {
          $siteResult = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                            -CmdletName 'Get-SPOSite' -Parameters @{ Limit = 'All' } `
                            -OperationType 'Read' -Caller 'Auditor'
          $sites      = @($siteResult.Result)
      } catch { $sites = @() }

      $permissivenessOrder = @{
          'Disabled'                        = 0
          'ExistingExternalUserSharingOnly' = 1
          'ExternalUserSharingOnly'         = 2
          'ExternalUserAndGuestSharing'     = 3
      }
      $tenantLevel   = $permissivenessOrder[$spoTenant.SharingCapability]
      $overrideSites = @($sites | Where-Object {
          $siteLevel = $permissivenessOrder[$_.SharingCapability]
          $siteLevel -and $tenantLevel -and $siteLevel -gt $tenantLevel
      })
      $overrideStatus = if ($overrideSites.Count -eq 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'SP-001' -RunId $runId `
          -Title 'Sites with More Permissive Sharing Than Tenant Policy' `
          -Category 'Data Protection' -Severity 'High' -RiskScore 70 `
          -SecureScoreVisibility 'Partial' -Status $overrideStatus `
          -Evidence @{
              siteOverrideCount  = $overrideSites.Count
              siteUrlSample      = @($overrideSites | Select-Object -First 10 -ExpandProperty Url)
              tenantCapability   = $spoTenant.SharingCapability
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

      if ($Finding.title -match 'Anonymous Link Sharing Enabled') {
          if ($PSCmdlet.ShouldProcess('SPO Tenant', 'Restrict sharing to ExternalUserSharingOnly')) {
              $actions.Add((New-RemediationAction `
                  -RunId $GraphGateway.RunId -CheckId 'SP-001' `
                  -CheckName 'Check-SharePointSharing' -FindingId $Finding.id `
                  -ActionId 'ACT-SP-RESTRICT-SHARING' `
                  -Operation 'Write' -ResourceType 'SPOTenant' `
                  -ResourceId $null -Target 'Set-SPOTenant -SharingCapability ExternalUserSharingOnly' `
                  -Provider 'Exchange' -Phase 4 -Order 3 `
                  -Dependencies @() -ConflictsWith @() -Priority 2 `
                  -SafetyLevel 'High' -Category 'DataProtection' `
                  -TenantIdMasked $tenantMasked `
                  -CmdletName 'Get-SPOTenant' -Parameters @{} `
                  -WriteCmdletName 'Set-SPOTenant' `
                  -WriteParameters @{ SharingCapability = 'ExternalUserSharingOnly' }))
          }
      }

      return $actions.ToArray()
  }
  ```

- [ ] **Step 5: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-SharePointSharing.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 6: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-SharePointSharing.ps1 -Settings PSScriptAnalyzerSettings.psd1
  Invoke-ScriptAnalyzer -Path src\Private\ExchangeGateway.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/ExchangeGateway.ps1 src/Private/checks/Check-SharePointSharing.ps1 tests/checks/Check-SharePointSharing.Tests.ps1
  git commit -m "feat: implement Check-SharePointSharing (anonymous links, expiry, site overrides); extend ExchangeGateway with SPO connect"
  ```

---

### Task 37: Check-AuditLogging + Check-SensitivityLabels

**Files:**
- Create: `src/Private/checks/Check-AuditLogging.ps1`
- Create: `src/Private/checks/Check-SensitivityLabels.ps1`
- Create: `tests/checks/Check-AuditLogging.Tests.ps1`
- Create: `tests/checks/Check-SensitivityLabels.Tests.ps1`

> **API note — AUDIT-001:** `dataSource='Exchange'`. Exchange: `Get-AdminAuditLogConfig` → `UnifiedAuditLogIngestionEnabled`. `Get-OrganizationConfig` → `AuditDisabled`. Secret auth → NotAssessed.
>
> **API note — LABEL-001:** `dataSource='Graph'`. `GET /informationProtection/policy/labels` → `Get-MgInformationProtectionPolicyLabel` from `Microsoft.Graph.Security`. All auth methods supported.

- [ ] **Step 1: Write failing tests — AuditLogging**

  Create `tests/checks/Check-AuditLogging.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-AuditLogging.ps1"

      function New-MockGw  { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway';  AuthMethod='Certificate'; RunId='run-001'; Connected=$true } }
      function New-MockExGw { [PSCustomObject]@{ PSTypeName='Metis.ExchangeGateway'; AuthMethod='Certificate'; Connected=$true } }
  }

  Describe 'Get-CheckMetadata — AUDIT-001' {
      It 'id is AUDIT-001'         { (Get-CheckMetadata).id         | Should -Be 'AUDIT-001' }
      It 'dataSource is Exchange'  { (Get-CheckMetadata).dataSource | Should -Be 'Exchange' }
      It 'severity is Medium'      { (Get-CheckMetadata).severity   | Should -Be 'Medium' }
      It 'excludes Secret'         { (Get-CheckMetadata).assessAuthMethods | Should -Not -Contain 'Secret' }
  }

  Describe 'Invoke-Check — Secret auth guard' {
      It 'returns NotAssessed' {
          $gw = New-MockGw; $gw.AuthMethod = 'Secret'
          $f  = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $null }
          $f[0].status | Should -Be 'NotAssessed'
      }
  }

  Describe 'Invoke-Check — audit logging disabled' {
      It 'returns Fail AUDIT-DISABLED when UnifiedAuditLogIngestionEnabled=false' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-AdminAuditLogConfig') {
                  return [PSCustomObject]@{ Result = [PSCustomObject]@{
                      UnifiedAuditLogIngestionEnabled = $false
                      AdminAuditLogEnabled            = $false
                  }}
              }
              return [PSCustomObject]@{ Result = [PSCustomObject]@{ AuditDisabled = $true } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $disabledF = $findings | Where-Object { $_.title -match 'Disabled|Not Enabled' }
          $disabledF.status | Should -Be 'Fail'
          $disabledF.evidence.unifiedAuditLogEnabled | Should -BeFalse
      }
  }

  Describe 'Invoke-Check — audit logging enabled' {
      It 'returns Pass when UnifiedAuditLogIngestionEnabled=true' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-AdminAuditLogConfig') {
                  return [PSCustomObject]@{ Result = [PSCustomObject]@{
                      UnifiedAuditLogIngestionEnabled = $true
                      AdminAuditLogEnabled            = $true
                  }}
              }
              return [PSCustomObject]@{ Result = [PSCustomObject]@{ AuditDisabled = $false } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $disabledF = $findings | Where-Object { $_.title -match 'Disabled|Not Enabled' }
          $disabledF.status | Should -Be 'Pass'
      }
  }
  ```

- [ ] **Step 2: Implement Check-AuditLogging.ps1**

  Create `src/Private/checks/Check-AuditLogging.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-CheckMetadata {
      @{
          id                    = 'AUDIT-001'
          title                 = 'Audit Logging Assessment'
          category              = 'Compliance'
          severity              = 'Medium'
          riskScoreBaseline     = 55
          secureScoreVisibility = 'Passes'
          description           = 'Evaluates whether Microsoft 365 unified audit logging is enabled. Audit logging is prerequisite for DLP enforcement, incident investigation, and compliance reporting.'
          requiredPermissions   = @('AuditLog.Read.All')
          requiredExchangeRoles = @('View-Only Configuration')
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
          $findings.Add((New-Finding -CheckId 'AUDIT-001' -RunId $runId `
              -Title 'Audit Logging Assessment Unavailable' `
              -Category 'Compliance' -Severity 'Medium' -RiskScore 55 `
              -SecureScoreVisibility 'Passes' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint $null -SupportsRemediation $false `
              -ErrorMessage 'ExchangeAuthNotSupported'))
          return $findings.ToArray()
      }

      $auditConfig = $null
      try {
          $result      = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                             -CmdletName 'Get-AdminAuditLogConfig' -Parameters @{} `
                             -OperationType 'Read' -Caller 'Auditor'
          $auditConfig = $result.Result
      } catch {
          $findings.Add((New-Finding -CheckId 'AUDIT-001' -RunId $runId `
              -Title 'Audit Logging Assessment Failed' `
              -Category 'Compliance' -Severity 'Medium' -RiskScore 55 `
              -SecureScoreVisibility 'Passes' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint $null -SupportsRemediation $false `
              -ErrorMessage $_.Exception.Message))
          return $findings.ToArray()
      }

      $unifiedEnabled = $auditConfig.UnifiedAuditLogIngestionEnabled -eq $true
      $disabledStatus = if ($unifiedEnabled) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'AUDIT-001' -RunId $runId `
          -Title 'Unified Audit Logging Not Enabled' `
          -Category 'Compliance' -Severity 'Medium' -RiskScore 55 `
          -SecureScoreVisibility 'Passes' -Status $disabledStatus `
          -Evidence @{
              unifiedAuditLogEnabled  = $unifiedEnabled
              adminAuditLogEnabled    = $auditConfig.AdminAuditLogEnabled
          } `
          -GraphEndpoint $null -SupportsRemediation $true))

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

      if ($Finding.title -match 'Not Enabled') {
          if ($PSCmdlet.ShouldProcess('AdminAuditLogConfig', 'Enable unified audit logging')) {
              $actions.Add((New-RemediationAction `
                  -RunId $GraphGateway.RunId -CheckId 'AUDIT-001' `
                  -CheckName 'Check-AuditLogging' -FindingId $Finding.id `
                  -ActionId 'ACT-AUDIT-ENABLE' `
                  -Operation 'Write' -ResourceType 'AdminAuditLogConfig' `
                  -ResourceId $null -Target 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' `
                  -Provider 'Exchange' -Phase 4 -Order 1 `
                  -Dependencies @() -ConflictsWith @() -Priority 2 `
                  -SafetyLevel 'Low' -Category 'Compliance' `
                  -TenantIdMasked $tenantMasked `
                  -CmdletName 'Get-AdminAuditLogConfig' -Parameters @{} `
                  -WriteCmdletName 'Set-AdminAuditLogConfig' `
                  -WriteParameters @{ UnifiedAuditLogIngestionEnabled = $true }))
          }
      }

      return $actions.ToArray()
  }
  ```

- [ ] **Step 3: Write failing tests — SensitivityLabels**

  Create `tests/checks/Check-SensitivityLabels.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-SensitivityLabels.ps1"

      function New-MockGw { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; RunId='run-001'; Connected=$true } }
  }

  Describe 'Get-CheckMetadata — LABEL-001' {
      It 'id is LABEL-001'       { (Get-CheckMetadata).id         | Should -Be 'LABEL-001' }
      It 'dataSource is Graph'   { (Get-CheckMetadata).dataSource | Should -Be 'Graph' }
      It 'severity is High'      { (Get-CheckMetadata).severity   | Should -Be 'High' }
  }

  Describe 'Invoke-Check — no labels defined' {
      It 'returns Fail LABEL-NONE when no labels exist' {
          $gw = New-MockGw
          Mock Invoke-GraphRequest { [PSCustomObject]@{ Result = @{ value = @() } } }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $noneF = $findings | Where-Object { $_.title -match 'No.*Label|Label.*Not.*Defined' }
          $noneF.status | Should -Be 'Fail'
          $noneF.evidence.labelCount | Should -Be 0
      }
  }

  Describe 'Invoke-Check — labels defined' {
      It 'returns Pass LABEL-NONE when labels exist' {
          $gw = New-MockGw
          Mock Invoke-GraphRequest {
              [PSCustomObject]@{ Result = @{ value = @(
                  [PSCustomObject]@{ id='lbl-001'; displayName='Confidential'; isActive=$true }
              )}}
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $noneF = $findings | Where-Object { $_.title -match 'No.*Label|Label.*Not.*Defined' }
          $noneF.status | Should -Be 'Pass'
      }
  }
  ```

- [ ] **Step 4: Implement Check-SensitivityLabels.ps1**

  Create `src/Private/checks/Check-SensitivityLabels.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-CheckMetadata {
      @{
          id                    = 'LABEL-001'
          title                 = 'Sensitivity Labels Assessment'
          category              = 'Data Protection'
          severity              = 'High'
          riskScoreBaseline     = 75
          secureScoreVisibility = 'NotFlagged'
          description           = 'Evaluates whether sensitivity labels are defined and published to users. DLP enforcement depends on labels being present. Labels in draft or unpublished state provide no protection.'
          requiredPermissions   = @('InformationProtectionPolicy.Read.All')
          requiredExchangeRoles = @()
          dataSource            = 'Graph'
          supportsRemediation   = $false
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

      $labels = @()
      try {
          $resp   = Invoke-GraphRequest -GraphGateway $GraphGateway `
                        -Uri '/informationProtection/policy/labels' `
                        -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
          $labels = @($resp.Result.value)
      } catch {
          $findings.Add((New-Finding -CheckId 'LABEL-001' -RunId $runId `
              -Title 'Sensitivity Labels Assessment Failed' `
              -Category 'Data Protection' -Severity 'High' -RiskScore 75 `
              -SecureScoreVisibility 'NotFlagged' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint '/informationProtection/policy/labels' `
              -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
          return $findings.ToArray()
      }

      $activeLabels = @($labels | Where-Object { $_.isActive -eq $true })

      # --- Finding 1: No labels defined ---
      $noneStatus = if ($labels.Count -gt 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'LABEL-001' -RunId $runId `
          -Title 'No Sensitivity Labels Defined' `
          -Category 'Data Protection' -Severity 'High' -RiskScore 75 `
          -SecureScoreVisibility 'NotFlagged' -Status $noneStatus `
          -Evidence @{
              labelCount    = $labels.Count
              activeCount   = $activeLabels.Count
              labelsDefined = $labels.Count -gt 0
          } `
          -GraphEndpoint '/informationProtection/policy/labels' -SupportsRemediation $false))

      # --- Finding 2: Labels exist but none active/published ---
      if ($labels.Count -gt 0) {
          $unpublishedStatus = if ($activeLabels.Count -gt 0) { 'Pass' } else { 'Fail' }
          $findings.Add((New-Finding -CheckId 'LABEL-001' -RunId $runId `
              -Title 'Sensitivity Labels Defined But Not Published to Users' `
              -Category 'Data Protection' -Severity 'High' -RiskScore 68 `
              -SecureScoreVisibility 'NotFlagged' -Status $unpublishedStatus `
              -Evidence @{
                  totalLabels   = $labels.Count
                  activeLabels  = $activeLabels.Count
                  inactiveCount = ($labels.Count - $activeLabels.Count)
              } `
              -GraphEndpoint '/informationProtection/policy/labels' -SupportsRemediation $false))
      }

      return $findings.ToArray()
  }
  ```

- [ ] **Step 5: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-AuditLogging.Tests.ps1 -Output Detailed
  Invoke-Pester -Path tests\checks\Check-SensitivityLabels.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 6: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-AuditLogging.ps1 -Settings PSScriptAnalyzerSettings.psd1
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-SensitivityLabels.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/checks/Check-AuditLogging.ps1 src/Private/checks/Check-SensitivityLabels.ps1 tests/checks/Check-AuditLogging.Tests.ps1 tests/checks/Check-SensitivityLabels.Tests.ps1
  git commit -m "feat: implement Check-AuditLogging (unified audit enable) and Check-SensitivityLabels (label defined/published)"
  ```

---

### Task 38: Check-DefenderOffice365 + Check-CloudAppSecurity

**Files:**
- Create: `src/Private/checks/Check-DefenderOffice365.ps1`
- Create: `src/Private/checks/Check-CloudAppSecurity.ps1`
- Create: `tests/checks/Check-DefenderOffice365.Tests.ps1`
- Create: `tests/checks/Check-CloudAppSecurity.Tests.ps1`

> **API note — DEF-001:** `dataSource='Exchange'`. Exchange: `Get-AntiPhishPolicy`, `Get-SafeLinksPolicy`, `Get-SafeAttachmentPolicy`. Evaluates preset level (standard/strict vs default) — distinct from MAIL-001 which checks presence. Secret auth → NotAssessed.
>
> **API note — CASB-001:** `dataSource='Graph'`. `GET /security/cloudAppSecurityProfiles` endpoint availability in Microsoft Graph SDK v2.x is marked "Verify" in spec. Implementation uses `Invoke-GraphRequest` REST directly. Permission `CloudApp.Read.All`. If endpoint returns 404 or 403, treat as NotAssessed with structured reason.

- [ ] **Step 1: Write failing tests — DefenderOffice365**

  Create `tests/checks/Check-DefenderOffice365.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-DefenderOffice365.ps1"

      function New-MockGw  { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway';  AuthMethod='Certificate'; RunId='run-001'; Connected=$true } }
      function New-MockExGw { [PSCustomObject]@{ PSTypeName='Metis.ExchangeGateway'; AuthMethod='Certificate'; Connected=$true } }
  }

  Describe 'Get-CheckMetadata — DEF-001' {
      It 'id is DEF-001'           { (Get-CheckMetadata).id         | Should -Be 'DEF-001' }
      It 'dataSource is Exchange'  { (Get-CheckMetadata).dataSource | Should -Be 'Exchange' }
      It 'severity is High'        { (Get-CheckMetadata).severity   | Should -Be 'High' }
      It 'excludes Secret'         { (Get-CheckMetadata).assessAuthMethods | Should -Not -Contain 'Secret' }
  }

  Describe 'Invoke-Check — Secret auth guard' {
      It 'returns NotAssessed for Secret auth' {
          $gw = New-MockGw; $gw.AuthMethod = 'Secret'
          $f  = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $null }
          $f[0].status | Should -Be 'NotAssessed'
      }
  }

  Describe 'Invoke-Check — default anti-phish preset only' {
      It 'returns Fail DEF-ANTIPHISH when only default policy exists (PhishThresholdLevel=1)' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-AntiPhishPolicy') {
                  return [PSCustomObject]@{ Result = @(
                      [PSCustomObject]@{ Name='Default'; IsDefault=$true; PhishThresholdLevel=1; EnableMailboxIntelligence=$false; EnableSpoofIntelligence=$false }
                  )}
              }
              return [PSCustomObject]@{ Result = @() }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $apF = $findings | Where-Object { $_.title -match 'Anti-Phish' -or $_.title -match 'Phishing' }
          $apF.status | Should -Be 'Fail'
          $apF.evidence.hasStandardOrStrictPreset | Should -BeFalse
      }
  }

  Describe 'Invoke-Check — standard preset configured' {
      It 'returns Pass DEF-ANTIPHISH when non-default policy has PhishThresholdLevel >= 2' {
          $gw = New-MockGw; $exGw = New-MockExGw
          Mock Invoke-ExchangeRequest {
              param($CmdletName)
              if ($CmdletName -eq 'Get-AntiPhishPolicy') {
                  return [PSCustomObject]@{ Result = @(
                      [PSCustomObject]@{ Name='Default'; IsDefault=$true; PhishThresholdLevel=1 }
                      [PSCustomObject]@{ Name='Standard Preset'; IsDefault=$false; PhishThresholdLevel=2; EnableMailboxIntelligence=$true; EnableSpoofIntelligence=$true }
                  )}
              }
              return [PSCustomObject]@{ Result = @() }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{ ExchangeGateway = $exGw }
          $apF = $findings | Where-Object { $_.title -match 'Anti-Phish' -or $_.title -match 'Phishing' }
          $apF.status | Should -Be 'Pass'
      }
  }
  ```

- [ ] **Step 2: Implement Check-DefenderOffice365.ps1**

  Create `src/Private/checks/Check-DefenderOffice365.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-CheckMetadata {
      @{
          id                    = 'DEF-001'
          title                 = 'Microsoft Defender for Office 365 Assessment'
          category              = 'Email Security'
          severity              = 'High'
          riskScoreBaseline     = 78
          secureScoreVisibility = 'Partial'
          description           = 'Evaluates Defender for Office 365 preset configuration. Default anti-phishing, Safe Links, and Safe Attachments policies provide minimal protection. Standard or Strict preset is required for effective defence.'
          requiredPermissions   = @('SecurityEvents.Read.All')
          requiredExchangeRoles = @('View-Only Configuration')
          dataSource            = 'Exchange'
          supportsRemediation   = $false
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
          $findings.Add((New-Finding -CheckId 'DEF-001' -RunId $runId `
              -Title 'Defender for Office 365 Assessment Unavailable' `
              -Category 'Email Security' -Severity 'High' -RiskScore 78 `
              -SecureScoreVisibility 'Partial' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint $null -SupportsRemediation $false `
              -ErrorMessage 'ExchangeAuthNotSupported'))
          return $findings.ToArray()
      }

      # --- Anti-phishing preset level ---
      $antiPhishPolicies = @()
      try {
          $apResult          = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                                   -CmdletName 'Get-AntiPhishPolicy' -Parameters @{} `
                                   -OperationType 'Read' -Caller 'Auditor'
          $antiPhishPolicies = @($apResult.Result)
      } catch {
          $findings.Add((New-Finding -CheckId 'DEF-001' -RunId $runId `
              -Title 'Defender for Office 365 Assessment Failed' `
              -Category 'Email Security' -Severity 'High' -RiskScore 78 `
              -SecureScoreVisibility 'Partial' -Status 'NotAssessed' `
              -Evidence @{} -GraphEndpoint $null -SupportsRemediation $false `
              -ErrorMessage $_.Exception.Message))
          return $findings.ToArray()
      }

      # PhishThresholdLevel: 1=Standard(default) 2=Aggressive 3=More 4=Most — Standard/Strict preset >= 2
      $strictPolicies    = @($antiPhishPolicies | Where-Object { $_.IsDefault -ne $true -and $_.PhishThresholdLevel -ge 2 })
      $hasStrictPreset   = $strictPolicies.Count -gt 0
      $firstStrictPreset = $strictPolicies | Select-Object -First 1
      $apStatus          = if ($hasStrictPreset) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'DEF-001' -RunId $runId `
          -Title 'Anti-Phishing Policy at Default Preset (Insufficient Protection)' `
          -Category 'Email Security' -Severity 'High' -RiskScore 78 `
          -SecureScoreVisibility 'Partial' -Status $apStatus `
          -Evidence @{
              policyCount               = $antiPhishPolicies.Count
              hasStandardOrStrictPreset = $hasStrictPreset
              defaultOnlyPresent        = ($antiPhishPolicies.Count -eq 1 -and $antiPhishPolicies[0].IsDefault)
              strictPresetName          = if ($firstStrictPreset) { $firstStrictPreset.Name } else { $null }
          } `
          -GraphEndpoint $null -SupportsRemediation $false))

      # --- Safe Links ---
      $safeLinks = @()
      try {
          $slResult  = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                           -CmdletName 'Get-SafeLinksPolicy' -Parameters @{} `
                           -OperationType 'Read' -Caller 'Auditor'
          $safeLinks = @($slResult.Result | Where-Object { $_.IsEnabled -eq $true -or $_.EnableSafeLinksForEmail -eq $true })
      } catch { $safeLinks = @() }

      $slStatus = if ($safeLinks.Count -gt 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'DEF-001' -RunId $runId `
          -Title 'Safe Links Policy Not Configured' `
          -Category 'Email Security' -Severity 'High' -RiskScore 72 `
          -SecureScoreVisibility 'Partial' -Status $slStatus `
          -Evidence @{ enabledPolicyCount = $safeLinks.Count } `
          -GraphEndpoint $null -SupportsRemediation $false))

      # --- Safe Attachments ---
      $safeAttach = @()
      try {
          $saResult   = Invoke-ExchangeRequest -ExchangeGateway $exGw `
                            -CmdletName 'Get-SafeAttachmentPolicy' -Parameters @{} `
                            -OperationType 'Read' -Caller 'Auditor'
          $safeAttach = @($saResult.Result | Where-Object { $_.Enable -eq $true })
      } catch { $safeAttach = @() }

      $saStatus = if ($safeAttach.Count -gt 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'DEF-001' -RunId $runId `
          -Title 'Safe Attachments Policy Not Configured' `
          -Category 'Email Security' -Severity 'High' -RiskScore 72 `
          -SecureScoreVisibility 'Partial' -Status $saStatus `
          -Evidence @{ enabledPolicyCount = $safeAttach.Count } `
          -GraphEndpoint $null -SupportsRemediation $false))

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
      # Defender preset remediation is staged: report-only first, then enforce in subsequent run.
      # v1 returns empty actions — operator uses WhatIf output to plan manual preset upgrade.
      return @()
  }
  ```

- [ ] **Step 3: Write failing tests — CloudAppSecurity**

  Create `tests/checks/Check-CloudAppSecurity.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-CloudAppSecurity.ps1"

      function New-MockGw { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; RunId='run-001'; Connected=$true } }
  }

  Describe 'Get-CheckMetadata — CASB-001' {
      It 'id is CASB-001'      { (Get-CheckMetadata).id         | Should -Be 'CASB-001' }
      It 'dataSource is Graph' { (Get-CheckMetadata).dataSource | Should -Be 'Graph' }
      It 'severity is Medium'  { (Get-CheckMetadata).severity   | Should -Be 'Medium' }
  }

  Describe 'Invoke-Check — CASB not configured' {
      It 'returns Fail CASB-ABSENT when no profiles found' {
          $gw = New-MockGw
          Mock Invoke-GraphRequest { [PSCustomObject]@{ Result = @{ value = @() } } }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $absentF = $findings | Where-Object { $_.title -match 'Not Configured|Not Connected|Absent' }
          $absentF.status | Should -Be 'Fail'
      }
  }

  Describe 'Invoke-Check — endpoint unavailable (404/403)' {
      It 'returns NotAssessed when Graph returns 404 for CASB endpoint' {
          $gw = New-MockGw
          Mock Invoke-GraphRequest { throw 'Response status code does not indicate success: 404' }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $findings[0].status | Should -Be 'NotAssessed'
          $findings[0].error.message | Should -Match '404|unavailable|not licensed'
      }
  }
  ```

- [ ] **Step 4: Implement Check-CloudAppSecurity.ps1**

  Create `src/Private/checks/Check-CloudAppSecurity.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-CheckMetadata {
      @{
          id                    = 'CASB-001'
          title                 = 'Microsoft Defender for Cloud Apps (CASB) Assessment'
          category              = 'Cloud Security'
          severity              = 'Medium'
          riskScoreBaseline     = 50
          secureScoreVisibility = 'NotFlagged'
          description           = 'Evaluates whether Microsoft Defender for Cloud Apps (formerly MCAS) is licensed and configured with session/access policies. Discovery-only mode provides no enforcement. Uses REST fallback — SDK v2.x support for this endpoint requires verification at implementation time.'
          requiredPermissions   = @('CloudApp.Read.All')
          requiredExchangeRoles = @()
          dataSource            = 'Graph'
          supportsRemediation   = $false
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

      # REST fallback: SDK cmdlet availability for /security/cloudAppSecurityProfiles is unverified.
      # Invoke-GraphRequest handles the REST call directly.
      $profiles = @()
      try {
          $resp     = Invoke-GraphRequest -GraphGateway $GraphGateway `
                          -Uri '/security/cloudAppSecurityProfiles' `
                          -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
          $profiles = @($resp.Result.value)
      } catch {
          $errMsg = $_.Exception.Message
          # 404 = endpoint not available in this tenant's Graph version
          # 403 = not licensed for Defender for Cloud Apps
          if ($errMsg -imatch '404|403|Forbidden|not licensed') {
              $findings.Add((New-Finding -CheckId 'CASB-001' -RunId $runId `
                  -Title 'CASB Assessment Unavailable' `
                  -Category 'Cloud Security' -Severity 'Medium' -RiskScore 50 `
                  -SecureScoreVisibility 'NotFlagged' -Status 'NotAssessed' `
                  -Evidence @{ endpointAvailable = $false } `
                  -GraphEndpoint '/security/cloudAppSecurityProfiles' `
                  -SupportsRemediation $false `
                  -ErrorMessage "Endpoint unavailable or not licensed: $errMsg"))
          } else {
              $findings.Add((New-Finding -CheckId 'CASB-001' -RunId $runId `
                  -Title 'CASB Assessment Failed' `
                  -Category 'Cloud Security' -Severity 'Medium' -RiskScore 50 `
                  -SecureScoreVisibility 'NotFlagged' -Status 'NotAssessed' `
                  -Evidence @{} -GraphEndpoint '/security/cloudAppSecurityProfiles' `
                  -SupportsRemediation $false -ErrorMessage $errMsg))
          }
          return $findings.ToArray()
      }

      # --- Finding 1: CASB not configured ---
      $casbStatus = if ($profiles.Count -gt 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'CASB-001' -RunId $runId `
          -Title 'Microsoft Defender for Cloud Apps Not Configured' `
          -Category 'Cloud Security' -Severity 'Medium' -RiskScore 50 `
          -SecureScoreVisibility 'NotFlagged' -Status $casbStatus `
          -Evidence @{
              profileCount    = $profiles.Count
              casbConfigured  = ($profiles.Count -gt 0)
          } `
          -GraphEndpoint '/security/cloudAppSecurityProfiles' -SupportsRemediation $false))

      return $findings.ToArray()
  }
  ```

- [ ] **Step 5: Run all new tests**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-DefenderOffice365.Tests.ps1 -Output Detailed
  Invoke-Pester -Path tests\checks\Check-CloudAppSecurity.Tests.ps1 -Output Detailed
  ```

  Expected: all tests pass.

- [ ] **Step 6: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-DefenderOffice365.ps1 -Settings PSScriptAnalyzerSettings.psd1
  Invoke-ScriptAnalyzer -Path src\Private\checks\Check-CloudAppSecurity.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/checks/Check-DefenderOffice365.ps1 src/Private/checks/Check-CloudAppSecurity.ps1 tests/checks/Check-DefenderOffice365.Tests.ps1 tests/checks/Check-CloudAppSecurity.Tests.ps1
  git commit -m "feat: implement Check-DefenderOffice365 (preset level) and Check-CloudAppSecurity (CASB configured)"
  ```

- [ ] **Step 7: Full check suite test run**

  Run all 10 new check tests together to verify no cross-contamination from shared Mocks:

  ```powershell
  Invoke-Pester -Path tests\checks\ -Output Detailed
  ```

  Expected: all check tests pass. No unexpected Mock bleed between describe blocks.

- [ ] **Step 8: CheckContract validation sweep**

  Verify all 10 new checks pass `Test-CheckContract`:

  ```powershell
  $checks = Get-ChildItem src\Private\checks\Check-*.ps1
  foreach ($check in $checks) {
      $result = Test-CheckContract -ModulePath $check.FullName
      if (-not $result.IsValid) {
          Write-Error "$($check.Name): $($result.Violations -join '; ')"
      } else {
          Write-Host "$($check.Name): PASS" -ForegroundColor Green
      }
  }
  ```

  Expected: all 13 checks (3 original + 10 new) print PASS.

- [ ] **Step 9: Full test suite**

  ```powershell
  Invoke-Pester -Path tests\ -Output Detailed
  ```

  Expected: all tests pass. Zero failures.

- [ ] **Step 10: Final commit**

  ```powershell
  git add -A
  git commit -m "test: all 13 checks pass CheckContract; full test suite green"
  ```
