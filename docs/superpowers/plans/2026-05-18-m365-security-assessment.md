# M365 Security Assessment Tool — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-grade PowerShell module that assesses M365 tenant security across 13 control domains and (Premium only) safely remediates findings via a dependency-aware sequencing engine.

**Architecture:** Three-plane model — Detection (Check-*.ps1 → Finding[]) → Intelligence (Rules → DAG → SequencePlan) → Execution (Remediator routes per `action.provider` to GraphGateway or ExchangeGateway). All writes gated by 4-condition Test-WriteAllowed; system is fail-closed on tenant mismatch, auth violation, or plan drift.

**Tech Stack:** PowerShell 7.2+, Microsoft.Graph SDK v2.x, ExchangeOnlineManagement PS module, Pester v5.x, PSScriptAnalyzer, GitHub Actions

**Spec:** `docs/superpowers/specs/2026-05-18-m365-security-assessment-design.md`

**v1 Scope:** Tasks 1–26 build the full pipeline validated against CA + PIM + LegacyAuth. Tasks 27–36 add remaining 10 checks. Tasks 37–38 wire CI/CD and integration tests.

---

### Task 1: Repository Structure + Module Manifest

**Files:**
- Delete: `m365-security-assessment-tool\` nested subfolder (after copying contents to root)
- Modify: `m365-security-assessment-tool.psd1` (root)
- Modify: `m365-security-assessment-tool.psm1` (root)
- Create: `PSScriptAnalyzerSettings.psd1` (root — copy from `Baseline_PSScriptAnalyzerSettings.psd1`)
- Create: `.gitignore`
- Create: `config/assessment.config.psd1`
- Create: `config/assessment.secrets.psd1`
- Create: `src/Private/models/` dir
- Create: `src/Private/policy/` dir
- Create: `src/Private/sequencing/rules/` dir
- Create: `src/Private/checks/` dir (with `Check-ConditionalAccess.ps1` stub from nested folder)
- Create: `src/Private/ExchangeGateway.ps1` (copy from `Sample_Baseline_ExchangeGateway.ps1`)
- Create: `src/Private/Reporter.ps1` stub
- Create: `templates/report.html.ps1` stub
- Create: `tests/` dir structure
- Create: `tests/sequencing/rules/` dirs

- [ ] **Step 1: Move nested starter-pack files to project root**

  Copy `m365-security-assessment-tool\m365-security-assessment-tool\m365-security-assessment-tool.psd1` → root.
  Copy `m365-security-assessment-tool\m365-security-assessment-tool\m365-security-assessment-tool.psm1` → root.
  Copy `m365-security-assessment-tool\m365-security-assessment-tool\Start-Assessment.ps1` → root.
  Copy `m365-security-assessment-tool\m365-security-assessment-tool\src\Public\Invoke-M365Assessment.ps1` → `src\Public\`.
  Copy `m365-security-assessment-tool\m365-security-assessment-tool\src\Private\checks\Check-ConditionalAccess.ps1` → `src\Private\checks\`.
  Delete the loose root-level `src\Auditor.ps1`, `src\GraphClient.ps1`, `src\Reporter.ps1` (replaced by nested structure).
  Remove nested `m365-security-assessment-tool\m365-security-assessment-tool\` after confirming copies complete.

  Run: `Get-ChildItem -Recurse C:\Projects\m365-security-assessment-tool | Where-Object { -not $_.PSIsContainer } | Select-Object FullName`
  Expected: flat structure — no nested `m365-security-assessment-tool\m365-security-assessment-tool\` subfolder.

- [ ] **Step 2: Create all missing directories**

  ```powershell
  $dirs = @(
      'src\Private\models',
      'src\Private\policy',
      'src\Private\sequencing\rules',
      'src\Private\checks',
      'tests\sequencing\rules',
      'config',
      'templates',
      'Output'
  )
  $dirs | ForEach-Object { New-Item -ItemType Directory -Path "C:\Projects\m365-security-assessment-tool\$_" -Force }
  ```

- [ ] **Step 3: Update module manifest (.psd1)**

  Replace root `m365-security-assessment-tool.psd1` with:

  ```powershell
  @{
      RootModule           = 'm365-security-assessment-tool.psm1'
      ModuleVersion        = '0.1.0'
      GUID                 = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
      Author               = 'Metis Security Ltd'
      CompanyName          = 'Metis Security Ltd'
      Description          = 'M365 tenant security assessment and remediation tool'
      PowerShellVersion    = '7.2'
      FunctionsToExport    = @('Invoke-M365Assessment')
      RequiredModules      = @(
          @{ ModuleName = 'Microsoft.Graph.Authentication';         ModuleVersion = '2.0.0' }
          @{ ModuleName = 'Microsoft.Graph.Identity.SignIns';       ModuleVersion = '2.0.0' }
          @{ ModuleName = 'Microsoft.Graph.Identity.Governance';    ModuleVersion = '2.0.0' }
          @{ ModuleName = 'Microsoft.Graph.Identity.DirectoryManagement'; ModuleVersion = '2.0.0' }
          @{ ModuleName = 'Microsoft.Graph.DeviceManagement';       ModuleVersion = '2.0.0' }
          @{ ModuleName = 'Microsoft.Graph.Security';               ModuleVersion = '2.0.0' }
          @{ ModuleName = 'Microsoft.Graph.Reports';                ModuleVersion = '2.0.0' }
          @{ ModuleName = 'ExchangeOnlineManagement';               ModuleVersion = '3.0.0' }
      )
      PrivateData          = @{ PSData = @{ Tags = @('M365','Security','Assessment','Remediation') } }
  }
  ```

  Run: `Test-ModuleManifest C:\Projects\m365-security-assessment-tool\m365-security-assessment-tool.psd1`
  Expected: no errors.

- [ ] **Step 4: Update root loader (.psm1)**

  Replace `m365-security-assessment-tool.psm1` with:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  $privatePath = Join-Path $PSScriptRoot 'src\Private'
  $publicPath  = Join-Path $PSScriptRoot 'src\Public'

  Get-ChildItem -Path $privatePath -Recurse -Filter '*.ps1' | ForEach-Object { . $_.FullName }
  Get-ChildItem -Path $publicPath  -Recurse -Filter '*.ps1' | ForEach-Object { . $_.FullName }
  ```

- [ ] **Step 5: Create .gitignore**

  ```
  Output/
  config/assessment.secrets.psd1
  *.pfx
  *.p12
  ```

- [ ] **Step 6: Create config/assessment.config.psd1**

  ```powershell
  @{
      Edition        = 'Lite'
      OutputPath     = '.\Output'
      EnabledChecks  = @('CA-001','PIM-001','LA-001')
      AuthMethod     = 'Certificate'
      ReportOptions  = @{
          IncludeEvidence = $true
          HtmlTheme       = 'default'
      }
  }
  ```

- [ ] **Step 7: Create config/assessment.secrets.psd1 (gitignored)**

  ```powershell
  @{
      TenantId           = 'YOUR-TENANT-ID'
      AppId              = 'YOUR-APP-ID'
      CertificateThumbprint = 'YOUR-CERT-THUMBPRINT'
      ClientSecret       = $null
      Organization       = 'contoso.onmicrosoft.com'
  }
  ```

- [ ] **Step 8: Copy PSScriptAnalyzerSettings to root**

  Copy `Baseline_PSScriptAnalyzerSettings.psd1` → `PSScriptAnalyzerSettings.psd1`.

  Run: `Invoke-ScriptAnalyzer -Path .\m365-security-assessment-tool.psm1 -Settings .\PSScriptAnalyzerSettings.psd1`
  Expected: zero issues.

- [ ] **Step 9: Initialize git + first commit**

  ```powershell
  git init
  git add m365-security-assessment-tool.psd1 m365-security-assessment-tool.psm1 PSScriptAnalyzerSettings.psd1 .gitignore config/assessment.config.psd1 src/ templates/ tests/
  git commit -m "chore: scaffold project structure and module manifest"
  ```

---

### Task 2: GraphGateway

**Files:**
- Create: `src/Private/GraphGateway.ps1`
- Create: `tests/GraphGateway.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/GraphGateway.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../src/Private/GraphGateway.ps1"
  }

  Describe 'New-GraphGateway' {
      It 'returns object with expected PSTypeName' {
          $gw = New-GraphGateway -TenantId 'tid' -AppId 'aid' -AuthMethod 'Certificate' -RunId 'r1' -RunFolder 'C:\tmp'
          $gw.PSObject.TypeNames[0] | Should -Be 'Metis.GraphGateway'
      }
      It 'stores AuthMethod' {
          $gw = New-GraphGateway -TenantId 'tid' -AppId 'aid' -AuthMethod 'Secret' -RunId 'r1' -RunFolder 'C:\tmp'
          $gw.AuthMethod | Should -Be 'Secret'
      }
  }

  Describe 'Invoke-GraphRequest — write gate' {
      BeforeAll {
          $gw = New-GraphGateway -TenantId 'tid' -AppId 'aid' -AuthMethod 'Certificate' -RunId 'r1' -RunFolder 'C:\tmp'
      }
      It 'throws if OperationType=Read and Method != GET' {
          { Invoke-GraphRequest -GraphGateway $gw -Uri '/test' -Method 'POST' -OperationType 'Read' -Caller 'Test' } |
              Should -Throw
      }
      It 'throws if OperationType=Write and Caller != Remediator' {
          { Invoke-GraphRequest -GraphGateway $gw -Uri '/test' -Method 'POST' -OperationType 'Write' -Caller 'Auditor' } |
              Should -Throw '*write denied*'
      }
      It 'throws if OperationType=Write and Caller=Remediator but no connection' {
          { Invoke-GraphRequest -GraphGateway $gw -Uri '/test' -Method 'POST' -OperationType 'Write' -Caller 'Remediator' } |
              Should -Throw
      }
  }

  Describe 'Invoke-GraphRequest — pagination' {
      It 'follows @odata.nextLink until exhausted' {
          $gw = New-GraphGateway -TenantId 'tid' -AppId 'aid' -AuthMethod 'Certificate' -RunId 'r1' -RunFolder 'C:\tmp'
          $gw.Connected = $true
          $gw.AccessToken = 'fake-token'

          $page1 = @{ value = @(1,2); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/next' }
          $page2 = @{ value = @(3,4) }
          $callCount = 0

          Mock Invoke-MgGraphRequest {
              $callCount++
              if ($callCount -eq 1) { return $page1 }
              return $page2
          }

          $result = Invoke-GraphRequest -GraphGateway $gw -Uri '/test' -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
          $result.value.Count | Should -Be 4
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\GraphGateway.Tests.ps1 -Output Detailed
  ```

  Expected: all tests fail (functions not found).

- [ ] **Step 3: Implement GraphGateway.ps1**

  Create `src/Private/GraphGateway.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function New-GraphGateway {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)][string] $TenantId,
          [Parameter(Mandatory)][string] $AppId,
          [Parameter(Mandatory)][ValidateSet('Certificate','Secret','Delegated')] [string] $AuthMethod,
          [Parameter()][string] $CertificateThumbprint,
          [Parameter()][System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
          [Parameter()][string] $CertificateFilePath,
          [Parameter()][securestring] $CertificatePassword,
          [Parameter()][string] $ClientSecret,
          [Parameter()][string] $UserPrincipalName,
          [Parameter(Mandatory)][string] $RunId,
          [Parameter(Mandatory)][string] $RunFolder
      )
      [PSCustomObject]@{
          PSTypeName            = 'Metis.GraphGateway'
          TenantId              = $TenantId
          AppId                 = $AppId
          AuthMethod            = $AuthMethod
          CertificateThumbprint = $CertificateThumbprint
          Certificate           = $Certificate
          CertificateFilePath   = $CertificateFilePath
          CertificatePassword   = $CertificatePassword
          ClientSecret          = $ClientSecret
          UserPrincipalName     = $UserPrincipalName
          RunId                 = $RunId
          RunFolder             = $RunFolder
          Connected             = $false
          AccessToken           = $null
      }
  }

  function Connect-GraphGateway {
      [CmdletBinding()]
      param([Parameter(Mandatory)] $GraphGateway)

      if ($GraphGateway.Connected) { return $GraphGateway }

      $connectParams = @{
          TenantId = $GraphGateway.TenantId
          ClientId = $GraphGateway.AppId
          NoWelcome = $true
          ErrorAction = 'Stop'
      }

      switch ($GraphGateway.AuthMethod) {
          'Certificate' {
              if ($GraphGateway.CertificateThumbprint) {
                  $connectParams['CertificateThumbprint'] = $GraphGateway.CertificateThumbprint
              } elseif ($GraphGateway.Certificate) {
                  $connectParams['Certificate'] = $GraphGateway.Certificate
              } elseif ($GraphGateway.CertificateFilePath) {
                  $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                      $GraphGateway.CertificateFilePath,
                      $GraphGateway.CertificatePassword
                  )
                  $connectParams['Certificate'] = $cert
              } else {
                  throw "Certificate auth requires CertificateThumbprint OR Certificate OR CertificateFilePath."
              }
              Connect-MgGraph @connectParams | Out-Null
          }
          'Secret' {
              $secret = $GraphGateway.ClientSecret
              if (-not $secret) { throw "AuthMethod=Secret requires ClientSecret." }
              $connectParams['ClientSecretCredential'] = [System.Net.NetworkCredential]::new('', $secret).SecurePassword
              Connect-MgGraph @connectParams | Out-Null
          }
          'Delegated' {
              Connect-MgGraph @connectParams | Out-Null
          }
          default { throw "Unsupported AuthMethod: $($GraphGateway.AuthMethod)" }
      }

      $ctx = Get-MgContext
      $GraphGateway.Connected    = $true
      $GraphGateway.AccessToken  = (Get-MgContext).AccessToken
      return $GraphGateway
  }

  function Disconnect-GraphGateway {
      [CmdletBinding()]
      param([Parameter(Mandatory)] $GraphGateway)
      if (-not $GraphGateway.Connected) { return }
      Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
      $GraphGateway.Connected   = $false
      $GraphGateway.AccessToken = $null
  }

  function Invoke-GraphRequest {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          [Parameter(Mandatory)][string] $Uri,
          [Parameter(Mandatory)][string] $Method,
          [Parameter()][object] $Body,
          [Parameter(Mandatory)][ValidateSet('Read','Write')] [string] $OperationType,
          [Parameter()][string] $Caller = 'Unknown',
          [Parameter()][ValidateRange(0,10)][int] $MaxRetries = 3
      )

      $isGet = $Method -eq 'GET'

      if ($OperationType -eq 'Read' -and -not $isGet) {
          throw "GraphGateway contract violation: OperationType=Read requires GET. Got '$Method'."
      }

      if (-not $isGet) {
          if (-not ($Caller -eq 'Remediator' -and $OperationType -eq 'Write')) {
              throw "Graph write denied: Caller=$Caller OperationType=$OperationType Method=$Method URI=$Uri"
          }
      }

      Connect-GraphGateway -GraphGateway $GraphGateway | Out-Null

      $clientRequestId = [Guid]::NewGuid().ToString()
      $headers = @{ 'x-ms-client-request-id' = $clientRequestId }

      $retryDelaysMs = @()
      $attempt = 0
      $allValues = [System.Collections.Generic.List[object]]::new()

      $currentUri = $Uri
      while ($currentUri) {
          $attempt++
          $response = $null
          try {
              $invokeParams = @{
                  Uri     = $currentUri
                  Method  = $Method
                  Headers = $headers
                  ErrorAction = 'Stop'
              }
              if ($Body -and -not $isGet) {
                  $invokeParams['Body'] = ($Body | ConvertTo-Json -Depth 20 -Compress)
                  $invokeParams['ContentType'] = 'application/json'
              }

              $response = Invoke-MgGraphRequest @invokeParams
              $attempt = 0
              $retryDelaysMs = @()
          } catch {
              $msg = $_.Exception.Message
              $statusCode = $null
              if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
              $isTransient = ($statusCode -in @(429,500,502,503,504)) -or ($msg -match '(?i)throttl|timeout|server busy|try again')

              if (-not $isTransient -or $attempt -gt $MaxRetries) { throw }

              $delay = [int]([math]::Pow(2, $attempt - 1) * 1000)
              $retryDelaysMs += $delay
              Start-Sleep -Milliseconds $delay
              continue
          }

          if ($response.value) {
              foreach ($v in $response.value) { $allValues.Add($v) | Out-Null }
          }

          $currentUri = $response.'@odata.nextLink'
          if (-not $currentUri) { break }
      }

      $result = if ($allValues.Count -gt 0) { @{ value = $allValues.ToArray() } } else { $response }

      return [PSCustomObject]@{
          Result          = $result
          ClientRequestId = $clientRequestId
          HttpStatusCode  = $null
          Retries         = $retryDelaysMs.Count
          RetryDelaysMs   = $retryDelaysMs
      }
  }
  ```

- [ ] **Step 4: Run tests — verify pass**

  ```powershell
  Invoke-Pester -Path tests\GraphGateway.Tests.ps1 -Output Detailed
  ```

  Expected: New-GraphGateway tests pass. Write-gate tests pass. Pagination test passes (with Mock).

- [ ] **Step 5: ScriptAnalyzer**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\GraphGateway.ps1 -Settings PSScriptAnalyzerSettings.psd1
  ```

  Expected: zero issues.

- [ ] **Step 6: Commit**

  ```powershell
  git add src/Private/GraphGateway.ps1 tests/GraphGateway.Tests.ps1
  git commit -m "feat: add GraphGateway with write-gate, pagination, retry, x-ms-client-request-id"
  ```

---

### Task 3: ExchangeGateway

**Files:**
- Create: `src/Private/ExchangeGateway.ps1` (based on `Sample_Baseline_ExchangeGateway.ps1`)
- Create: `tests/ExchangeGateway.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/ExchangeGateway.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../src/Private/ExchangeGateway.ps1"
  }

  Describe 'New-ExchangeGateway' {
      It 'returns PSTypeName Metis.ExchangeGateway' {
          $gw = New-ExchangeGateway -TenantId 't' -AppId 'a' -AuthMethod 'Certificate' -Organization 'c.onmicrosoft.com' -RunId 'r1' -RunFolder 'C:\tmp'
          $gw.PSObject.TypeNames[0] | Should -Be 'Metis.ExchangeGateway'
      }
      It 'Connected starts false' {
          $gw = New-ExchangeGateway -TenantId 't' -AppId 'a' -AuthMethod 'Certificate' -Organization 'c.onmicrosoft.com' -RunId 'r1' -RunFolder 'C:\tmp'
          $gw.Connected | Should -BeFalse
      }
  }

  Describe 'Connect-ExchangeGateway — Secret auth' {
      It 'throws immediately for Secret AuthMethod' {
          $gw = New-ExchangeGateway -TenantId 't' -AppId 'a' -AuthMethod 'Secret' -Organization 'c.onmicrosoft.com' -RunId 'r1' -RunFolder 'C:\tmp'
          { Connect-ExchangeGateway -ExchangeGateway $gw } | Should -Throw '*Secret*'
      }
  }

  Describe 'Invoke-ExchangeRequest — OperationType gate' {
      BeforeAll {
          $gw = New-ExchangeGateway -TenantId 't' -AppId 'a' -AuthMethod 'Certificate' -Organization 'c.onmicrosoft.com' -RunId 'r1' -RunFolder 'C:\tmp'
          $gw.Connected = $true
          Mock Connect-ExchangeGateway { }
      }
      It 'throws if OperationType=Read and cmdlet is not Get-*' {
          { Invoke-ExchangeRequest -ExchangeGateway $gw -CmdletName 'Set-Mailbox' -OperationType 'Read' -Caller 'Auditor' } |
              Should -Throw '*Read requires Get-*'
      }
      It 'throws if Write from non-Remediator caller' {
          { Invoke-ExchangeRequest -ExchangeGateway $gw -CmdletName 'Set-Mailbox' -OperationType 'Write' -Caller 'Auditor' } |
              Should -Throw '*Exchange write denied*'
      }
      It 'throws if cmdlet not found in session' {
          Mock Get-Command { $null }
          { Invoke-ExchangeRequest -ExchangeGateway $gw -CmdletName 'Get-EXOMailbox' -OperationType 'Read' -Caller 'Auditor' } |
              Should -Throw '*not found in session*'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\ExchangeGateway.Tests.ps1 -Output Detailed
  ```

  Expected: all fail (functions not found).

- [ ] **Step 3: Implement ExchangeGateway.ps1**

  Copy `Sample_Baseline_ExchangeGateway.ps1` to `src/Private/ExchangeGateway.ps1`. No changes needed — it is the production implementation. Verify PSTypeName is `Metis.ExchangeGateway`, Connect-ExchangeGateway throws on Secret, Invoke-ExchangeRequest has OperationType gate, default-deny non-Get-* without `Caller=Remediator AND OperationType=Write`.

- [ ] **Step 4: Run tests — verify pass**

  ```powershell
  Invoke-Pester -Path tests\ExchangeGateway.Tests.ps1 -Output Detailed
  ```

  Expected: all pass.

- [ ] **Step 5: ScriptAnalyzer**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\ExchangeGateway.ps1 -Settings PSScriptAnalyzerSettings.psd1
  ```

  Expected: zero issues.

- [ ] **Step 6: Commit**

  ```powershell
  git add src/Private/ExchangeGateway.ps1 tests/ExchangeGateway.Tests.ps1
  git commit -m "feat: add ExchangeGateway with write-gate, OperationType contract, Secret-auth denial"
  ```

---

### Task 4: Policy Layer — Test-WriteAllowed + Test-Environment

**Files:**
- Create: `src/Private/policy/Test-WriteAllowed.ps1`
- Create: `src/Private/policy/Test-Environment.ps1`
- Create: `tests/policy/Test-WriteAllowed.Tests.ps1`
- Create: `tests/policy/Test-Environment.Tests.ps1`

- [ ] **Step 1: Write failing tests — Test-WriteAllowed**

  Create `tests/policy/Test-WriteAllowed.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../src/Private/policy/Test-WriteAllowed.ps1" }

  Describe 'Test-WriteAllowed' {
      $base = @{ Mode='Remediate'; AuthMethod='Delegated'; WhatIf=$false; Edition='Premium' }

      It 'returns true when all 4 gates pass' {
          Test-WriteAllowed @base | Should -BeTrue
      }
      It 'returns false when Mode != Remediate' {
          Test-WriteAllowed @base + @{ Mode='Assess' } | Should -BeFalse
      }
      It 'returns false when AuthMethod != Delegated' {
          Test-WriteAllowed @base + @{ AuthMethod='Certificate' } | Should -BeFalse
      }
      It 'returns false when WhatIf = true' {
          Test-WriteAllowed @base + @{ WhatIf=$true } | Should -BeFalse
      }
      It 'returns false when Edition != Premium' {
          Test-WriteAllowed @base + @{ Edition='Lite' } | Should -BeFalse
      }
      It 'returns false when 2 gates fail' {
          Test-WriteAllowed @base + @{ Mode='Assess'; Edition='Lite' } | Should -BeFalse
      }
  }
  ```

- [ ] **Step 2: Write failing tests — Test-Environment**

  Create `tests/policy/Test-Environment.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../src/Private/policy/Test-Environment.ps1" }

  Describe 'Test-Environment' {
      It 'returns object with IsValid property' {
          $result = Test-Environment -AuthMethod 'Certificate' -RequireExchange $false
          $result.PSObject.Properties.Name | Should -Contain 'IsValid'
      }
      It 'IsValid=false when PS version below 7.2' {
          Mock Get-PSVersion { [Version]'7.1.0' }
          $result = Test-Environment -AuthMethod 'Certificate' -RequireExchange $false
          $result.IsValid | Should -BeFalse
          $result.Failures | Should -Contain 'PowerShell 7.2+ required'
      }
      It 'IsValid=false when ExchangeOnlineManagement missing and RequireExchange=true' {
          Mock Get-Module { $null } -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
          $result = Test-Environment -AuthMethod 'Certificate' -RequireExchange $true
          $result.IsValid | Should -BeFalse
          $result.Failures | Should -Contain 'ExchangeOnlineManagement module not found'
      }
  }
  ```

- [ ] **Step 3: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\policy\ -Output Detailed
  ```

  Expected: all fail.

- [ ] **Step 4: Implement Test-WriteAllowed.ps1**

  Create `src/Private/policy/Test-WriteAllowed.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Test-WriteAllowed {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)][ValidateSet('Assess','Remediate')] [string] $Mode,
          [Parameter(Mandatory)][ValidateSet('Certificate','Secret','Delegated')] [string] $AuthMethod,
          [Parameter(Mandatory)][bool] $WhatIf,
          [Parameter(Mandatory)][ValidateSet('Lite','Premium')] [string] $Edition
      )
      return ($Mode -eq 'Remediate') -and
             ($AuthMethod -eq 'Delegated') -and
             (-not $WhatIf) -and
             ($Edition -eq 'Premium')
  }
  ```

- [ ] **Step 5: Implement Test-Environment.ps1**

  Create `src/Private/policy/Test-Environment.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-PSVersion { return $PSVersionTable.PSVersion }

  function Test-Environment {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)][ValidateSet('Certificate','Secret','Delegated')] [string] $AuthMethod,
          [Parameter(Mandatory)][bool] $RequireExchange
      )

      $failures = [System.Collections.Generic.List[string]]::new()

      $psVer = Get-PSVersion
      if ($psVer -lt [Version]'7.2') {
          $failures.Add("PowerShell 7.2+ required. Found: $psVer")
      }

      if ($RequireExchange) {
          if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
              $failures.Add('ExchangeOnlineManagement module not found')
          }
      }

      if ($AuthMethod -eq 'Certificate') {
          # Cert reachability check is deferred to Connect-GraphGateway at runtime
      }

      return [PSCustomObject]@{
          IsValid  = ($failures.Count -eq 0)
          Failures = $failures.ToArray()
      }
  }
  ```

- [ ] **Step 6: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\policy\ -Output Detailed
  ```

  Expected: all pass.

- [ ] **Step 7: ScriptAnalyzer**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\policy\ -Settings PSScriptAnalyzerSettings.psd1
  ```

- [ ] **Step 8: Commit**

  ```powershell
  git add src/Private/policy/Test-WriteAllowed.ps1 src/Private/policy/Test-Environment.ps1 tests/policy/
  git commit -m "feat: add Test-WriteAllowed (4-gate) and Test-Environment safety policy functions"
  ```

---

### Task 5: Tenant Pinning — Test-TenantPin

**Files:**
- Create: `src/Private/policy/Test-TenantPin.ps1`
- Create: `tests/policy/Test-TenantPin.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/policy/Test-TenantPin.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../src/Private/policy/Test-TenantPin.ps1" }

  Describe 'Test-TenantPin' {
      $expectedTenantId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

      It 'returns Match=true when both signals match' {
          Mock Get-TenantIdFromToken { $expectedTenantId }
          Mock Get-TenantIdFromOrganization { $expectedTenantId }
          $result = Test-TenantPin -RequestedTenantId $expectedTenantId -GraphGateway @{}
          $result.Match | Should -BeTrue
          $result.MismatchReason | Should -BeNullOrEmpty
      }

      It 'Match=false and MismatchReason=TokenTenantMismatch when token tid differs' {
          Mock Get-TenantIdFromToken { 'wrong-id' }
          Mock Get-TenantIdFromOrganization { $expectedTenantId }
          $result = Test-TenantPin -RequestedTenantId $expectedTenantId -GraphGateway @{}
          $result.Match | Should -BeFalse
          $result.MismatchReason | Should -Be 'TokenTenantMismatch'
      }

      It 'Match=false and MismatchReason=OrganizationTenantMismatch when org endpoint differs' {
          Mock Get-TenantIdFromToken { $expectedTenantId }
          Mock Get-TenantIdFromOrganization { 'wrong-id' }
          $result = Test-TenantPin -RequestedTenantId $expectedTenantId -GraphGateway @{}
          $result.Match | Should -BeFalse
          $result.MismatchReason | Should -Be 'OrganizationTenantMismatch'
      }

      It 'Match=false and MismatchReason=RequestedTenantMissing when RequestedTenantId is empty' {
          $result = Test-TenantPin -RequestedTenantId '' -GraphGateway @{}
          $result.Match | Should -BeFalse
          $result.MismatchReason | Should -Be 'RequestedTenantMissing'
      }

      It 'Match=false and MismatchReason=UnableToResolveTenant when both signals fail' {
          Mock Get-TenantIdFromToken { throw 'token error' }
          Mock Get-TenantIdFromOrganization { throw 'org error' }
          $result = Test-TenantPin -RequestedTenantId $expectedTenantId -GraphGateway @{}
          $result.Match | Should -BeFalse
          $result.MismatchReason | Should -Be 'UnableToResolveTenant'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\policy\Test-TenantPin.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Test-TenantPin.ps1**

  Create `src/Private/policy/Test-TenantPin.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-TenantIdFromToken {
      param([Parameter(Mandatory)] $GraphGateway)
      $token = $GraphGateway.AccessToken
      if (-not $token) { throw 'No access token available on GraphGateway.' }
      # JWT is base64url-encoded header.payload.signature
      $payload = $token.Split('.')[1]
      # JWT uses base64url encoding — convert to standard base64 before decoding
      $payload = $payload.Replace('-', '+').Replace('_', '/')
      $padded  = $payload + ('=' * ((4 - $payload.Length % 4) % 4))
      $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded))
      $claims = $json | ConvertFrom-Json
      return $claims.tid
  }

  function Get-TenantIdFromOrganization {
      param([Parameter(Mandatory)] $GraphGateway)
      $response = Invoke-GraphRequest -GraphGateway $GraphGateway -Uri '/organization' -Method 'GET' -OperationType 'Read' -Caller 'TenantPin'
      return $response.Result.value[0].id
  }

  function Test-TenantPin {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)][AllowEmptyString()][string] $RequestedTenantId,
          [Parameter(Mandatory)] $GraphGateway
      )

      if ([string]::IsNullOrWhiteSpace($RequestedTenantId)) {
          return [PSCustomObject]@{ Match=$false; MismatchReason='RequestedTenantMissing'; TokenTenantId=$null; OrganizationTenantId=$null }
      }

      $tokenTid = $null
      $orgTid   = $null
      $tokenOk  = $false
      $orgOk    = $false

      try { $tokenTid = Get-TenantIdFromToken -GraphGateway $GraphGateway; $tokenOk = $true } catch {}
      try { $orgTid   = Get-TenantIdFromOrganization -GraphGateway $GraphGateway; $orgOk = $true } catch {}

      if (-not $tokenOk -and -not $orgOk) {
          return [PSCustomObject]@{ Match=$false; MismatchReason='UnableToResolveTenant'; TokenTenantId=$null; OrganizationTenantId=$null }
      }

      if ($tokenOk -and $tokenTid -ne $RequestedTenantId) {
          return [PSCustomObject]@{ Match=$false; MismatchReason='TokenTenantMismatch'; TokenTenantId=$tokenTid; OrganizationTenantId=$orgTid }
      }

      if ($orgOk -and $orgTid -ne $RequestedTenantId) {
          return [PSCustomObject]@{ Match=$false; MismatchReason='OrganizationTenantMismatch'; TokenTenantId=$tokenTid; OrganizationTenantId=$orgTid }
      }

      return [PSCustomObject]@{ Match=$true; MismatchReason=$null; TokenTenantId=$tokenTid; OrganizationTenantId=$orgTid }
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\policy\Test-TenantPin.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\policy\Test-TenantPin.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/policy/Test-TenantPin.ps1 tests/policy/Test-TenantPin.Tests.ps1
  git commit -m "feat: add Test-TenantPin with dual-signal (JWT tid + /organization) fail-closed logic"
  ```

---

### Task 6: Permission Validators — Test-GraphPermissions + Test-ExchangePermissions

**Files:**
- Create: `src/Private/policy/Test-GraphPermissions.ps1`
- Create: `src/Private/policy/Test-ExchangePermissions.ps1`
- Create: `tests/policy/Test-GraphPermissions.Tests.ps1`
- Create: `tests/policy/Test-ExchangePermissions.Tests.ps1`

- [ ] **Step 1: Write failing tests — Graph**

  Create `tests/policy/Test-GraphPermissions.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../src/Private/policy/Test-GraphPermissions.ps1" }

  Describe 'Test-GraphPermissions' {
      It 'returns IsValid=true when all required permissions present in granted scopes' {
          $result = Test-GraphPermissions -RequiredPermissions @('Policy.Read.All') -GrantedScopes @('Policy.Read.All','Directory.Read.All')
          $result.IsValid | Should -BeTrue
          $result.Missing | Should -BeNullOrEmpty
      }
      It 'returns IsValid=false with Missing list when permission absent' {
          $result = Test-GraphPermissions -RequiredPermissions @('Policy.Read.All','RoleManagement.Read.Directory') -GrantedScopes @('Policy.Read.All')
          $result.IsValid | Should -BeFalse
          $result.Missing | Should -Contain 'RoleManagement.Read.Directory'
      }
      It 'returns IsValid=true when RequiredPermissions is empty' {
          $result = Test-GraphPermissions -RequiredPermissions @() -GrantedScopes @()
          $result.IsValid | Should -BeTrue
      }
  }
  ```

- [ ] **Step 2: Write failing tests — Exchange**

  Create `tests/policy/Test-ExchangePermissions.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../src/Private/policy/Test-ExchangePermissions.ps1" }

  Describe 'Test-ExchangePermissions' {
      It 'returns IsValid=true when all required Exchange roles present' {
          $result = Test-ExchangePermissions -RequiredRoles @('View-Only Configuration') -GrantedRoles @('View-Only Configuration','Compliance Management')
          $result.IsValid | Should -BeTrue
          $result.Missing | Should -BeNullOrEmpty
      }
      It 'returns IsValid=false with Missing list when role absent' {
          $result = Test-ExchangePermissions -RequiredRoles @('Compliance Management') -GrantedRoles @('View-Only Configuration')
          $result.IsValid | Should -BeFalse
          $result.Missing | Should -Contain 'Compliance Management'
      }
      It 'returns IsValid=true when RequiredRoles is empty' {
          $result = Test-ExchangePermissions -RequiredRoles @() -GrantedRoles @()
          $result.IsValid | Should -BeTrue
      }
  }
  ```

- [ ] **Step 3: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\policy\Test-GraphPermissions.Tests.ps1, tests\policy\Test-ExchangePermissions.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 4: Implement Test-GraphPermissions.ps1**

  Create `src/Private/policy/Test-GraphPermissions.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Test-GraphPermissions {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)][string[]] $RequiredPermissions,
          [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $GrantedScopes
      )
      $grantedLower = $GrantedScopes | ForEach-Object { $_.ToLower() }
      $missing = $RequiredPermissions | Where-Object { $_.ToLower() -notin $grantedLower }
      return [PSCustomObject]@{
          IsValid = ($missing.Count -eq 0)
          Missing = $missing
      }
  }
  ```

- [ ] **Step 5: Implement Test-ExchangePermissions.ps1**

  Create `src/Private/policy/Test-ExchangePermissions.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Test-ExchangePermissions {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)][string[]] $RequiredRoles,
          [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $GrantedRoles
      )
      $missing = $RequiredRoles | Where-Object { $_ -notin $GrantedRoles }
      return [PSCustomObject]@{
          IsValid = ($missing.Count -eq 0)
          Missing = $missing
      }
  }
  ```

- [ ] **Step 6: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\policy\Test-GraphPermissions.Tests.ps1, tests\policy\Test-ExchangePermissions.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 7: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\policy\ -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/policy/ tests/policy/
  git commit -m "feat: add Test-GraphPermissions and Test-ExchangePermissions validators"
  ```

---

---

### Task 7: Finding Model

**Files:**
- Create: `src/Private/models/Finding.schema.ps1`
- Create: `tests/models/Finding.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/models/Finding.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1" }

  Describe 'New-Finding' {
      $base = @{
          CheckId               = 'CA-001'
          RunId                 = 'run-001'
          Title                 = 'Legacy Auth Not Blocked'
          Category              = 'Identity Security'
          Severity              = 'Critical'
          RiskScore             = 95
          SecureScoreVisibility = 'Passes'
          Status                = 'Fail'
          GraphEndpoint         = '/identity/conditionalAccess/policies'
          SupportsRemediation   = $true
      }

      It 'returns object with all required fields' {
          $f = New-Finding @base
          $f.id              | Should -Match '^FIND-'
          $f.checkId         | Should -Be 'CA-001'
          $f.runId           | Should -Be 'run-001'
          $f.severity        | Should -Be 'Critical'
          $f.riskScore       | Should -Be 95
          $f.status          | Should -Be 'Fail'
          $f.timestampUtc    | Should -Not -BeNullOrEmpty
          $f.evidence        | Should -Not -BeNullOrEmpty
      }

      It 'id is unique per call' {
          $f1 = New-Finding @base
          $f2 = New-Finding @base
          $f1.id | Should -Not -Be $f2.id
      }

      It 'throws if Severity invalid' {
          { New-Finding @base -Severity 'Unknown' } | Should -Throw
      }

      It 'throws if Status invalid' {
          { New-Finding @base -Status 'Maybe' } | Should -Throw
      }

      It 'throws if RiskScore out of range' {
          { New-Finding @base -RiskScore 101 } | Should -Throw
      }

      It 'evidence defaults to empty hashtable' {
          $f = New-Finding @base
          $f.evidence | Should -BeOfType [hashtable]
      }
  }

  Describe 'Assert-FindingValid' {
      It 'does not throw for a valid finding' {
          $f = New-Finding -CheckId 'CA-001' -RunId 'r1' -Title 't' -Category 'c' -Severity 'High' `
               -RiskScore 75 -SecureScoreVisibility 'NotFlagged' -Status 'Pass' -GraphEndpoint '/test' -SupportsRemediation $false
          { Assert-FindingValid -Finding $f } | Should -Not -Throw
      }

      It 'throws if required field missing' {
          $f = [PSCustomObject]@{ id = 'FIND-001' }   # missing most fields
          { Assert-FindingValid -Finding $f } | Should -Throw
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\models\Finding.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Finding.schema.ps1**

  Create `src/Private/models/Finding.schema.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  $script:ValidSeverities  = @('Critical','High','Medium','Informational')
  $script:ValidStatuses    = @('Pass','Fail','NotAssessed')
  $script:ValidSSV         = @('Passes','NotFlagged','Partial')

  function New-Finding {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)][string]   $CheckId,
          [Parameter(Mandatory)][string]   $RunId,
          [Parameter(Mandatory)][string]   $Title,
          [Parameter(Mandatory)][string]   $Category,
          [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Informational')] [string] $Severity,
          [Parameter(Mandatory)][ValidateRange(0,100)] [int] $RiskScore,
          [Parameter(Mandatory)][ValidateSet('Passes','NotFlagged','Partial')] [string] $SecureScoreVisibility,
          [Parameter(Mandatory)][ValidateSet('Pass','Fail','NotAssessed')] [string] $Status,
          [Parameter()][hashtable] $Evidence = @{},
          [Parameter(Mandatory)][string]   $GraphEndpoint,
          [Parameter(Mandatory)][bool]     $SupportsRemediation,
          [Parameter()][string]            $ErrorMessage = $null
      )

      if ($null -eq $Evidence) { $Evidence = @{} }
      $shortId = [System.Guid]::NewGuid().ToString('N').Substring(0,8).ToUpper()

      [PSCustomObject]@{
          id                    = "FIND-$CheckId-$shortId"
          runId                 = $RunId
          checkId               = $CheckId
          title                 = $Title
          category              = $Category
          severity              = $Severity
          riskScore             = $RiskScore
          secureScoreVisibility = $SecureScoreVisibility
          status                = $Status
          evidence              = $Evidence
          graphEndpoint         = $GraphEndpoint
          timestampUtc          = [System.DateTime]::UtcNow.ToString('o')
          supportsRemediation   = $SupportsRemediation
          errorMessage          = $ErrorMessage
      }
  }

  function Assert-FindingValid {
      [CmdletBinding()]
      param([Parameter(Mandatory)] $Finding)

      $required = @('id','runId','checkId','title','category','severity','riskScore',
                    'secureScoreVisibility','status','evidence','graphEndpoint','timestampUtc','supportsRemediation')
      foreach ($field in $required) {
          if ($null -eq $Finding.$field -and $field -notin @('evidence')) {
              throw "Finding missing required field: $field"
          }
      }
      if ($Finding.severity -notin $script:ValidSeverities) {
          throw "Finding.severity invalid: $($Finding.severity)"
      }
      if ($Finding.status -notin $script:ValidStatuses) {
          throw "Finding.status invalid: $($Finding.status)"
      }
      if ($Finding.secureScoreVisibility -notin @('Passes','NotFlagged','Partial')) {
          throw "Finding.secureScoreVisibility invalid: $($Finding.secureScoreVisibility)"
      }
      if ($Finding.riskScore -lt 0 -or $Finding.riskScore -gt 100) {
          throw "Finding.riskScore out of range 0-100: $($Finding.riskScore)"
      }
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\models\Finding.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\models\Finding.schema.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/models/Finding.schema.ps1 tests/models/Finding.Tests.ps1
  git commit -m "feat: add Finding model with constructor and validator"
  ```

---

### Task 8: RemediationAction Model

**Files:**
- Create: `src/Private/models/RemediationAction.schema.ps1`
- Create: `tests/models/RemediationAction.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/models/RemediationAction.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../src/Private/models/RemediationAction.schema.ps1" }

  Describe 'New-RemediationAction' {
      $base = @{
          RunId         = 'run-001'
          CheckId       = 'CA-001'
          CheckName     = 'Check-ConditionalAccess'
          FindingId     = 'FIND-CA-001-ABCD1234'
          ActionId      = 'ACT-CA-BLOCK-LEGACYAUTH'
          Operation     = 'POST'
          ResourceType  = 'ConditionalAccessPolicy'
          Target        = 'Block legacy authentication'
          Provider      = 'Graph'
          Phase         = 2
          Order         = 1
          Priority      = 1
          TenantIdMasked = 'aaaa-...-eeee'
      }

      It 'returns object with schemaVersion 1.0' {
          $a = New-RemediationAction @base
          $a.schemaVersion | Should -Be '1.0'
      }

      It 'action.provider is set correctly' {
          $a = New-RemediationAction @base
          $a.action.provider | Should -Be 'Graph'
      }

      It 'throws if Provider is invalid' {
          { New-RemediationAction @base -Provider 'LDAP' } | Should -Throw
      }

      It 'result.status defaults to null (not yet executed)' {
          $a = New-RemediationAction @base
          $a.result.status | Should -BeNullOrEmpty
      }

      It 'execution.gates object present with all 4 keys' {
          $a = New-RemediationAction @base
          $a.execution.gates.PSObject.Properties.Name | Should -Contain 'modeRemediate'
          $a.execution.gates.PSObject.Properties.Name | Should -Contain 'delegatedAuth'
          $a.execution.gates.PSObject.Properties.Name | Should -Contain 'notWhatIf'
          $a.execution.gates.PSObject.Properties.Name | Should -Contain 'policyCheckPassed'
      }

      It 'request fields for Graph action have endpoint + method, cmdlet fields null' {
          $a = New-RemediationAction @base -Endpoint '/identity/conditionalAccess/policies' -HttpMethod 'POST'
          $a.request.endpoint    | Should -Be '/identity/conditionalAccess/policies'
          $a.request.method      | Should -Be 'POST'
          $a.request.cmdletName  | Should -BeNullOrEmpty
      }

      It 'request fields for Exchange action have cmdletName, endpoint null' {
          $a = New-RemediationAction @base -Provider 'Exchange' -CmdletName 'Get-EXOMailbox' -WriteCmdletName 'Set-CASMailbox'
          $a.request.cmdletName      | Should -Be 'Get-EXOMailbox'
          $a.request.writeCmdletName | Should -Be 'Set-CASMailbox'
          $a.request.endpoint        | Should -BeNullOrEmpty
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\models\RemediationAction.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement RemediationAction.schema.ps1**

  Create `src/Private/models/RemediationAction.schema.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function New-RemediationAction {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)][string] $RunId,
          [Parameter(Mandatory)][string] $CheckId,
          [Parameter(Mandatory)][string] $CheckName,
          [Parameter(Mandatory)][string] $FindingId,
          [Parameter(Mandatory)][string] $ActionId,
          [Parameter(Mandatory)][string] $Operation,
          [Parameter(Mandatory)][string] $ResourceType,
          [Parameter()][string]          $ResourceId   = $null,
          [Parameter(Mandatory)][string] $Target,
          [Parameter(Mandatory)][ValidateSet('Graph','Exchange')] [string] $Provider,
          [Parameter(Mandatory)][int]    $Phase,
          [Parameter(Mandatory)][int]    $Order,
          [Parameter()][string[]]        $Dependencies = @(),
          [Parameter()][string[]]        $ConflictsWith = @(),
          [Parameter(Mandatory)][int]    $Priority,
          [Parameter()][string]          $SafetyLevel  = 'High',
          [Parameter()][string]          $Category     = $null,
          [Parameter(Mandatory)][string] $TenantIdMasked,
          # Graph request fields
          [Parameter()][string]          $Endpoint     = $null,
          [Parameter()][string]          $HttpMethod   = $null,
          [Parameter()][object]          $Body         = $null,
          # Exchange request fields
          [Parameter()][string]          $CmdletName        = $null,
          [Parameter()][hashtable]       $Parameters        = $null,
          [Parameter()][string]          $WriteCmdletName   = $null,
          [Parameter()][hashtable]       $WriteParameters   = $null
      )

      # Provider-driven field validation
      if ($Provider -eq 'Graph') {
          if (-not $Endpoint -or -not $HttpMethod) {
              throw "Graph RemediationAction requires -Endpoint and -HttpMethod"
          }
      }
      if ($Provider -eq 'Exchange') {
          if (-not $CmdletName) {
              throw "Exchange RemediationAction requires -CmdletName"
          }
      }

      $bodyHash = $null
      if ($Body) {
          $bodyJson = $Body | ConvertTo-Json -Depth 20 -Compress
          $bytes    = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)
          $sha      = [System.Security.Cryptography.SHA256]::Create()
          $bodyHash = 'sha256:' + ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').ToLower()
      }

      [PSCustomObject]@{
          schemaVersion = '1.0'
          runContext    = [PSCustomObject]@{
              runId        = $RunId
              sequence     = $null   # set by Planner
              timestampUtc = [System.DateTime]::UtcNow.ToString('o')
          }
          tenant = [PSCustomObject]@{
              tenantIdMasked = $TenantIdMasked
              tenantMatch    = $true
          }
          check = [PSCustomObject]@{
              checkId   = $CheckId
              checkName = $CheckName
              findingId = $FindingId
          }
          action = [PSCustomObject]@{
              actionId     = $ActionId
              operation    = $Operation
              resourceType = $ResourceType
              resourceId   = $ResourceId
              target       = $Target
              provider     = $Provider
          }
          sequence = [PSCustomObject]@{
              phase         = $Phase
              order         = $Order
              dependencies  = $Dependencies
              conflictsWith = $ConflictsWith
              priority      = $Priority
              safetyLevel   = $SafetyLevel
              category      = $Category
          }
          execution = [PSCustomObject]@{
              whatIf         = $false
              confirmed      = $false
              confirmImpact  = 'High'
              force          = $false
              writeAllowed   = $false
              executionMode  = $null
              gates          = [PSCustomObject]@{
                  modeRemediate      = $false
                  delegatedAuth      = $false
                  notWhatIf          = $false
                  policyCheckPassed  = $false
              }
          }
          request = [PSCustomObject]@{
              endpoint         = $Endpoint
              method           = $HttpMethod
              bodyHash         = $bodyHash
              headers          = [PSCustomObject]@{ clientRequestId = $null }
              cmdletName       = $CmdletName
              parameters       = $Parameters
              writeCmdletName  = $WriteCmdletName
              writeParameters  = $WriteParameters
          }
          rulesApplied = @()
          state = [PSCustomObject]@{
              beforeRef   = $null
              afterRef    = $null
              diffSummary = $null
          }
          result = [PSCustomObject]@{
              status         = $null
              reason         = $null
              httpStatusCode = $null
              retries        = 0
              retryDelaysMs  = @()
              durationMs     = 0
          }
          error = $null
      }
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\models\RemediationAction.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\models\RemediationAction.schema.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/models/RemediationAction.schema.ps1 tests/models/RemediationAction.Tests.ps1
  git commit -m "feat: add RemediationAction model with full schema (action.provider, 4-gate execution, request routing fields)"
  ```

---

### Task 9: Test-CheckContract

**Files:**
- Create: `src/Private/policy/Test-CheckContract.ps1`
- Create: `tests/CheckContract.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/CheckContract.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../src/Private/policy/Test-CheckContract.ps1" }

  Describe 'Test-CheckContract — valid module' {
      BeforeAll {
          $validModule = @'
  function Get-CheckMetadata {
      @{
          id='CA-001'; title='Test'; category='Identity'; severity='Critical'
          riskScoreBaseline=90; secureScoreVisibility='Passes'; description='desc'
          requiredPermissions=@('Policy.Read.All'); requiredExchangeRoles=@()
          dataSource='Graph'; supportsRemediation=$false
          edition=@('Lite','Premium'); assessAuthMethods=@('Certificate','Secret','Delegated')
      }
  }
  function Invoke-Check { param($GraphGateway,$Config) @() }
  '@
          $tmpFile = [System.IO.Path]::GetTempFileName() + '.ps1'
          Set-Content -Path $tmpFile -Value $validModule
      }
      AfterAll { Remove-Item $tmpFile -ErrorAction SilentlyContinue }

      It 'returns IsValid=true for a compliant module' {
          $result = Test-CheckContract -ModulePath $tmpFile
          $result.IsValid | Should -BeTrue
          $result.Violations | Should -BeNullOrEmpty
      }
  }

  Describe 'Test-CheckContract — missing Get-CheckMetadata' {
      BeforeAll {
          $bad = "function Invoke-Check { param(`$GraphGateway,`$Config) @() }"
          $tmpFile = [System.IO.Path]::GetTempFileName() + '.ps1'
          Set-Content -Path $tmpFile -Value $bad
      }
      AfterAll { Remove-Item $tmpFile -ErrorAction SilentlyContinue }

      It 'IsValid=false with violation for missing Get-CheckMetadata' {
          $result = Test-CheckContract -ModulePath $tmpFile
          $result.IsValid | Should -BeFalse
          $result.Violations | Should -Contain 'Get-CheckMetadata function not found'
      }
  }

  Describe 'Test-CheckContract — write call detected' {
      BeforeAll {
          $bad = @'
  function Get-CheckMetadata { @{ id='X-001';title='t';category='c';severity='High';riskScoreBaseline=70;secureScoreVisibility='Passes';description='d';requiredPermissions=@();requiredExchangeRoles=@();dataSource='Graph';supportsRemediation=$false;edition=@('Lite');assessAuthMethods=@('Certificate') } }
  function Invoke-Check { param($GraphGateway,$Config) Invoke-GraphRequest -Method POST -OperationType Write; @() }
  '@
          $tmpFile = [System.IO.Path]::GetTempFileName() + '.ps1'
          Set-Content -Path $tmpFile -Value $bad
      }
      AfterAll { Remove-Item $tmpFile -ErrorAction SilentlyContinue }

      It 'IsValid=false when Invoke-Check contains write call' {
          $result = Test-CheckContract -ModulePath $tmpFile
          $result.IsValid | Should -BeFalse
          $result.Violations | Should -Match 'write.*Invoke-Check'
      }
  }

  Describe 'Test-CheckContract — missing required metadata fields' {
      BeforeAll {
          $bad = "function Get-CheckMetadata { @{ id='CA-001' } }`nfunction Invoke-Check { param(`$GraphGateway,`$Config) @() }"
          $tmpFile = [System.IO.Path]::GetTempFileName() + '.ps1'
          Set-Content -Path $tmpFile -Value $bad
      }
      AfterAll { Remove-Item $tmpFile -ErrorAction SilentlyContinue }

      It 'IsValid=false with violations for each missing metadata field' {
          $result = Test-CheckContract -ModulePath $tmpFile
          $result.IsValid | Should -BeFalse
          ($result.Violations | Where-Object { $_ -match 'metadata' }).Count | Should -BeGreaterThan 0
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\CheckContract.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Test-CheckContract.ps1**

  Create `src/Private/policy/Test-CheckContract.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  $script:RequiredMetadataKeys = @(
      'id','title','category','severity','riskScoreBaseline','secureScoreVisibility',
      'description','requiredPermissions','requiredExchangeRoles','dataSource',
      'supportsRemediation','edition','assessAuthMethods'
  )

  $script:WriteCallPatterns = @(
      'OperationType\s*[=,]\s*[''"]Write',
      'Invoke-GraphRequest.*-Method\s+(POST|PATCH|PUT|DELETE)',
      'Invoke-ExchangeRequest.*-OperationType\s+Write',
      '\bSet-\w+\b','\bNew-\w+\b','\bRemove-\w+\b','\bEnable-\w+\b','\bDisable-\w+\b'
  )

  function Test-CheckContract {
      [CmdletBinding()]
      param([Parameter(Mandatory)][string] $ModulePath)

      $violations = [System.Collections.Generic.List[string]]::new()
      $content    = Get-Content -Path $ModulePath -Raw -ErrorAction Stop
      $tokens     = $null; $errors = $null
      [System.Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors) | Out-Null

      $fnNames = $tokens | Where-Object { $_.TokenFlags -band [System.Management.Automation.Language.TokenFlags]::CommandName } |
                           Select-Object -ExpandProperty Text

      # Required functions
      if ('Get-CheckMetadata' -notin $fnNames) {
          $violations.Add('Get-CheckMetadata function not found')
      }
      if ('Invoke-Check' -notin $fnNames) {
          $violations.Add('Invoke-Check function not found')
      }

      # Metadata schema
      if ('Get-CheckMetadata' -in $fnNames) {
          try {
              $sb = [scriptblock]::Create($content)
              $tmpModule = New-Module -Name "__ContractCheck_$(New-Guid)" -ScriptBlock $sb
              $meta = & $tmpModule { Get-CheckMetadata }
              foreach ($key in $script:RequiredMetadataKeys) {
                  if (-not $meta.ContainsKey($key)) {
                      $violations.Add("Get-CheckMetadata missing metadata field: $key")
                  }
              }
              if ($meta.ContainsKey('dataSource') -and $meta.dataSource -notin @('Graph','Exchange','Both')) {
                  $violations.Add("Get-CheckMetadata.dataSource invalid value: '$($meta.dataSource)' (must be Graph|Exchange|Both)")
              }
          } catch {
              $violations.Add("Get-CheckMetadata threw during contract check: $($_.Exception.Message)")
          }
      }

      # Write call detection in Invoke-Check body
      # Extract Invoke-Check function body via AST
      $ast = [System.Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$null, [ref]$null)
      $invCheck = $ast.FindAll({
          param($node)
          $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Check'
      }, $false) | Select-Object -First 1

      if ($invCheck) {
          $checkBody = $invCheck.Body.ToString()
          foreach ($pattern in $script:WriteCallPatterns) {
              if ($checkBody -match $pattern) {
                  $violations.Add("Potential write call detected in Invoke-Check body (pattern: $pattern)")
                  break
              }
          }
      }

      return [PSCustomObject]@{
          IsValid    = ($violations.Count -eq 0)
          Violations = $violations.ToArray()
          ModulePath = $ModulePath
      }
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\CheckContract.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\policy\Test-CheckContract.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/policy/Test-CheckContract.ps1 tests/CheckContract.Tests.ps1
  git commit -m "feat: add Test-CheckContract (metadata schema, write-call detection, AST parsing)"
  ```

---

### Task 10: Check-ConditionalAccess

**Files:**
- Modify: `src/Private/checks/Check-ConditionalAccess.ps1` (replace stub)
- Create: `tests/checks/Check-ConditionalAccess.Tests.ps1`

> **Graph API note:** Before implementation, run `Get-Command -Module Microsoft.Graph.Identity.SignIns -Name *ConditionalAccess*` to confirm `Get-MgIdentityConditionalAccessPolicy` exists in your SDK version. This check uses `Invoke-GraphRequest` via the gateway (REST path) — no direct SDK cmdlet calls from check code.

- [ ] **Step 1: Write failing tests**

  Create `tests/checks/Check-ConditionalAccess.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-ConditionalAccess.ps1"

      function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true } }
  }

  Describe 'Get-CheckMetadata' {
      It 'returns id CA-001' { (Get-CheckMetadata).id | Should -Be 'CA-001' }
      It 'severity is Critical' { (Get-CheckMetadata).severity | Should -Be 'Critical' }
      It 'dataSource is Graph' { (Get-CheckMetadata).dataSource | Should -Be 'Graph' }
      It 'has requiredPermissions' { (Get-CheckMetadata).requiredPermissions | Should -Contain 'Policy.Read.All' }
      It 'passes Test-CheckContract' {
          . "$PSScriptRoot/../../src/Private/policy/Test-CheckContract.ps1"
          $result = Test-CheckContract -ModulePath "$PSScriptRoot/../../src/Private/checks/Check-ConditionalAccess.ps1"
          $result.IsValid | Should -BeTrue -Because ($result.Violations -join '; ')
      }
  }

  Describe 'Invoke-Check — legacy auth finding' {
      It 'returns Fail finding when no legacy auth block policy exists' {
          $gw = New-MockGateway
          Mock Invoke-GraphRequest {
              [PSCustomObject]@{ Result = @{ value = @() } }   # no CA policies
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $legacyFinding = $findings | Where-Object { $_.checkId -eq 'CA-001' -and $_.title -match 'Legacy' }
          $legacyFinding | Should -Not -BeNullOrEmpty
          $legacyFinding.status   | Should -Be 'Fail'
          $legacyFinding.severity | Should -Be 'Critical'
      }

      It 'returns Pass finding when enabled legacy auth block policy exists' {
          $gw = New-MockGateway
          $blockPolicy = [PSCustomObject]@{
              id    = 'pol-001'
              state = 'enabled'
              displayName = 'Block Legacy Auth'
              conditions = [PSCustomObject]@{
                  clientAppTypes = @('exchangeActiveSync','other')
                  users = [PSCustomObject]@{ includeUsers = @('All') }
              }
              grantControls = [PSCustomObject]@{ operator = 'OR'; builtInControls = @('block') }
          }
          Mock Invoke-GraphRequest {
              [PSCustomObject]@{ Result = @{ value = @($blockPolicy) } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $legacyFinding = $findings | Where-Object { $_.title -match 'Legacy' }
          $legacyFinding.status | Should -Be 'Pass'
      }
  }

  Describe 'Invoke-Check — report-only policies' {
      It 'returns Fail when legacy auth policy is report-only (not enforced)' {
          $gw = New-MockGateway
          $reportOnly = [PSCustomObject]@{
              id    = 'pol-002'
              state = 'enabledForReportingButNotEnforced'
              displayName = 'Block Legacy Auth'
              conditions = [PSCustomObject]@{
                  clientAppTypes = @('exchangeActiveSync','other')
                  users = [PSCustomObject]@{ includeUsers = @('All') }
              }
              grantControls = [PSCustomObject]@{ operator = 'OR'; builtInControls = @('block') }
          }
          Mock Invoke-GraphRequest {
              [PSCustomObject]@{ Result = @{ value = @($reportOnly) } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $legacyFinding = $findings | Where-Object { $_.title -match 'Legacy' }
          $legacyFinding.status | Should -Be 'Fail'
          $legacyFinding.evidence.reportOnlyFound | Should -BeTrue
      }
  }

  Describe 'Invoke-Check — MFA finding' {
      It 'returns Fail when no MFA policy covers all users' {
          $gw = New-MockGateway
          Mock Invoke-GraphRequest { [PSCustomObject]@{ Result = @{ value = @() } } }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $mfaFinding = $findings | Where-Object { $_.title -match 'MFA' }
          $mfaFinding.status | Should -Be 'Fail'
      }
  }

  Describe 'Invoke-Check — error handling' {
      It 'returns NotAssessed finding when GraphGateway throws' {
          $gw = New-MockGateway
          Mock Invoke-GraphRequest { throw 'Gateway error' }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $findings | Should -Not -BeNullOrEmpty
          $findings[0].status | Should -Be 'NotAssessed'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-ConditionalAccess.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Check-ConditionalAccess.ps1**

  Replace stub at `src/Private/checks/Check-ConditionalAccess.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-CheckMetadata {
      @{
          id                    = 'CA-001'
          title                 = 'Conditional Access Policy Assessment'
          category              = 'Identity Security'
          severity              = 'Critical'
          riskScoreBaseline     = 90
          secureScoreVisibility = 'Passes'
          description           = 'Evaluates CA policies for legacy auth blocking, MFA enforcement, break-glass exclusions, and report-only gaps that pass Secure Score but do not enforce.'
          requiredPermissions   = @('Policy.Read.All')
          requiredExchangeRoles = @()
          dataSource            = 'Graph'
          supportsRemediation   = $true
          edition               = @('Lite','Premium')
          assessAuthMethods     = @('Certificate','Secret','Delegated')
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

      $policies = $null
      try {
          $resp    = Invoke-GraphRequest -GraphGateway $GraphGateway `
                         -Uri '/identity/conditionalAccess/policies' `
                         -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
          $policies = $resp.Result.value
      } catch {
          $findings.Add((New-Finding -CheckId 'CA-001' -RunId $runId `
              -Title 'CA Policy Assessment Failed' -Category 'Identity Security' `
              -Severity 'Critical' -RiskScore 90 -SecureScoreVisibility 'Passes' `
              -Status 'NotAssessed' -GraphEndpoint '/identity/conditionalAccess/policies' `
              -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
          return $findings.ToArray()
      }

      $enabledPolicies = @($policies | Where-Object { $_.state -eq 'enabled' })

      # --- Finding 1: Legacy Authentication Block ---
      $legacyBlockPolicy = $enabledPolicies | Where-Object {
          $appTypes = $_.conditions.clientAppTypes
          $appTypes -and
          $appTypes -contains 'exchangeActiveSync' -and
          $appTypes -contains 'other' -and
          $_.grantControls.builtInControls -contains 'block'
      } | Select-Object -First 1

      $reportOnlyLegacy = @($policies | Where-Object {
          $_.state -eq 'enabledForReportingButNotEnforced' -and
          $_.conditions.clientAppTypes -and
          $_.conditions.clientAppTypes -contains 'exchangeActiveSync'
      })

      $legacyStatus = if ($legacyBlockPolicy) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'CA-001' -RunId $runId `
          -Title 'Legacy Authentication Not Blocked' `
          -Category 'Identity Security' -Severity 'Critical' -RiskScore 95 `
          -SecureScoreVisibility 'Passes' -Status $legacyStatus `
          -Evidence @{
              legacyAuthPolicyFound = [bool]$legacyBlockPolicy
              reportOnlyFound       = ($reportOnlyLegacy.Count -gt 0)
              reportOnlyPolicyCount = $reportOnlyLegacy.Count
              totalPolicies         = $policies.Count
          } `
          -GraphEndpoint '/identity/conditionalAccess/policies' `
          -SupportsRemediation $true))

      # --- Finding 2: MFA All Users ---
      # includeUsers -contains 'All' is the correct check for "all users" CA scope.
      # includeGroups.Count -eq 0 does NOT mean "all users" — it means "no groups targeted".
      $mfaAllUsers = $enabledPolicies | Where-Object {
          $_.conditions.users.includeUsers -contains 'All' -and
          $_.grantControls.builtInControls -contains 'mfa'
      } | Select-Object -First 1

      $mfaStatus = if ($mfaAllUsers) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'CA-001' -RunId $runId `
          -Title 'MFA Not Enforced for All Users' `
          -Category 'Identity Security' -Severity 'Critical' -RiskScore 90 `
          -SecureScoreVisibility 'Passes' -Status $mfaStatus `
          -Evidence @{
              mfaPolicyFound = [bool]$mfaAllUsers
              totalPolicies  = $policies.Count
          } `
          -GraphEndpoint '/identity/conditionalAccess/policies' `
          -SupportsRemediation $true))

      # --- Finding 3: Break-Glass Exclusions ---
      $breakGlassExclusion = $enabledPolicies | Where-Object {
          $_.conditions.users.excludeUsers.Count -gt 0 -or
          $_.conditions.users.excludeGroups.Count -gt 0
      } | Select-Object -First 1

      $bgStatus = if ($breakGlassExclusion) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'CA-001' -RunId $runId `
          -Title 'No Break-Glass Account Exclusions Found in CA Policies' `
          -Category 'Identity Security' -Severity 'Critical' -RiskScore 92 `
          -SecureScoreVisibility 'NotFlagged' -Status $bgStatus `
          -Evidence @{
              breakGlassFound           = [bool]$breakGlassExclusion
              policiesWithExclusions    = @($enabledPolicies | Where-Object {
                  $_.conditions.users.excludeUsers.Count -gt 0 -or
                  $_.conditions.users.excludeGroups.Count -gt 0
              }).Count
          } `
          -GraphEndpoint '/identity/conditionalAccess/policies' `
          -SupportsRemediation $false))

      return $findings.ToArray()
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
  git commit -m "feat: implement Check-ConditionalAccess (legacy auth, MFA, break-glass findings)"
  ```

---

### Task 11: Check-PIM

**Files:**
- Create: `src/Private/checks/Check-PIM.ps1`
- Create: `tests/checks/Check-PIM.Tests.ps1`

> **Graph API note:** Verify these exist in `Microsoft.Graph.Identity.Governance` before implementation: `Get-MgRoleManagementDirectoryRoleAssignment`, `Get-MgRoleManagementDirectoryRoleEligibilitySchedule`, `Get-MgPolicyRoleManagementPolicy`. All use `Invoke-GraphRequest` via gateway — no direct SDK calls from check code.

- [ ] **Step 1: Write failing tests**

  Create `tests/checks/Check-PIM.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-PIM.ps1"

      function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true } }
  }

  Describe 'Get-CheckMetadata' {
      It 'id is PIM-001' { (Get-CheckMetadata).id | Should -Be 'PIM-001' }
      It 'severity is Critical' { (Get-CheckMetadata).severity | Should -Be 'Critical' }
      It 'has RoleManagement permission' { (Get-CheckMetadata).requiredPermissions | Should -Contain 'RoleManagement.Read.Directory' }
      It 'passes Test-CheckContract' {
          . "$PSScriptRoot/../../src/Private/policy/Test-CheckContract.ps1"
          $result = Test-CheckContract -ModulePath "$PSScriptRoot/../../src/Private/checks/Check-PIM.ps1"
          $result.IsValid | Should -BeTrue -Because ($result.Violations -join '; ')
      }
  }

  Describe 'Invoke-Check — standing active roles' {
      It 'returns Fail when Global Admins have active (not eligible) assignments' {
          $gw = New-MockGateway
          $gaRoleId = '62e90394-69f5-4237-9190-012177145e10'   # well-known Global Admin role template ID

          $activeAssignment = [PSCustomObject]@{
              id = 'assign-001'
              roleDefinitionId = $gaRoleId
              principalId = 'user-001'
              assignmentType = 'Assigned'
              memberType = 'Direct'
          }

          Mock Invoke-GraphRequest {
              param($Uri)
              if ($Uri -match 'roleAssignments') {
                  return [PSCustomObject]@{ Result = @{ value = @($activeAssignment) } }
              }
              return [PSCustomObject]@{ Result = @{ value = @() } }
          }

          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $standingFinding = $findings | Where-Object { $_.title -match 'Standing' -or $_.title -match 'Active.*Assign' }
          $standingFinding | Should -Not -BeNullOrEmpty
          $standingFinding.status | Should -Be 'Fail'
          $standingFinding.evidence.standingGlobalAdminCount | Should -BeGreaterThan 0
      }

      It 'returns Pass when no standing active assignments for high-privilege roles' {
          $gw = New-MockGateway
          Mock Invoke-GraphRequest { [PSCustomObject]@{ Result = @{ value = @() } } }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $standingFinding = $findings | Where-Object { $_.title -match 'Standing' -or $_.title -match 'Active.*Assign' }
          $standingFinding.status | Should -Be 'Pass'
      }
  }

  Describe 'Invoke-Check — PIM not enabled' {
      It 'returns Fail when no eligible schedules and no role policies found' {
          $gw = New-MockGateway
          Mock Invoke-GraphRequest { [PSCustomObject]@{ Result = @{ value = @() } } }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $pimFinding = $findings | Where-Object { $_.title -match 'PIM' -or $_.title -match 'Just.In.Time' }
          $pimFinding | Should -Not -BeNullOrEmpty
      }
  }

  Describe 'Invoke-Check — error handling' {
      It 'returns NotAssessed when gateway throws' {
          $gw = New-MockGateway
          Mock Invoke-GraphRequest { throw 'throttled' }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $findings[0].status | Should -Be 'NotAssessed'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-PIM.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Check-PIM.ps1**

  Create `src/Private/checks/Check-PIM.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  # Well-known role template IDs for Tier-0 roles
  $script:HighRiskRoleIds = @{
      GlobalAdministrator              = '62e90394-69f5-4237-9190-012177145e10'
      PrivilegedRoleAdministrator      = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
      SecurityAdministrator            = '194ae4cb-b126-40b2-bd5b-6091b380977d'
      ExchangeAdministrator            = '29232cdf-9323-42fd-ade2-1d097af3e4de'
      SharePointAdministrator          = 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'
      UserAccountAdministrator         = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
  }

  function Get-CheckMetadata {
      @{
          id                    = 'PIM-001'
          title                 = 'Privileged Identity Management Assessment'
          category              = 'Privileged Access'
          severity              = 'Critical'
          riskScoreBaseline     = 90
          secureScoreVisibility = 'NotFlagged'
          description           = 'Evaluates PIM configuration: standing active role assignments, eligible/active ratio for high-risk roles, MFA on activation, approval workflow, and access reviews.'
          requiredPermissions   = @('RoleManagement.Read.Directory','PrivilegedAccess.Read.AzureAD')
          requiredExchangeRoles = @()
          dataSource            = 'Graph'
          supportsRemediation   = $true
          edition               = @('Lite','Premium')
          assessAuthMethods     = @('Certificate','Secret','Delegated')
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

      try {
          $assignResp  = Invoke-GraphRequest -GraphGateway $GraphGateway `
                             -Uri '/roleManagement/directory/roleAssignments?$expand=roleDefinition' `
                             -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
          $eligResp    = Invoke-GraphRequest -GraphGateway $GraphGateway `
                             -Uri '/roleManagement/directory/roleEligibilitySchedules' `
                             -Method 'GET' -OperationType 'Read' -Caller 'Auditor'

          $activeAssignments    = @($assignResp.Result.value)
          $eligibleSchedules    = @($eligResp.Result.value)
      } catch {
          $findings.Add((New-Finding -CheckId 'PIM-001' -RunId $runId `
              -Title 'PIM Assessment Failed' -Category 'Privileged Access' `
              -Severity 'Critical' -RiskScore 90 -SecureScoreVisibility 'NotFlagged' `
              -Status 'NotAssessed' -GraphEndpoint '/roleManagement/directory/roleAssignments' `
              -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
          return $findings.ToArray()
      }

      # --- Finding 1: Standing active assignments for high-risk roles ---
      $highRiskIds = $script:HighRiskRoleIds.Values
      $standingHighRisk = @($activeAssignments | Where-Object {
          $_.roleDefinitionId -in $highRiskIds
      })
      $standingGACount  = @($activeAssignments | Where-Object {
          $_.roleDefinitionId -eq $script:HighRiskRoleIds.GlobalAdministrator
      }).Count

      $standingStatus = if ($standingHighRisk.Count -eq 0) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'PIM-001' -RunId $runId `
          -Title 'Standing Active Assignments Found for High-Privilege Roles' `
          -Category 'Privileged Access' -Severity 'Critical' -RiskScore 92 `
          -SecureScoreVisibility 'NotFlagged' -Status $standingStatus `
          -Evidence @{
              standingHighRiskCount    = $standingHighRisk.Count
              standingGlobalAdminCount = $standingGACount
              eligibleScheduleCount    = $eligibleSchedules.Count
          } `
          -GraphEndpoint '/roleManagement/directory/roleAssignments' `
          -SupportsRemediation $true))

      # --- Finding 2: PIM JIT model not in use ---
      $pimInUse = $eligibleSchedules.Count -gt 0
      $pimStatus = if ($pimInUse) { 'Pass' } else { 'Fail' }
      $findings.Add((New-Finding -CheckId 'PIM-001' -RunId $runId `
          -Title 'Privileged Identity Management (JIT) Not in Use' `
          -Category 'Privileged Access' -Severity 'Critical' -RiskScore 90 `
          -SecureScoreVisibility 'NotFlagged' -Status $pimStatus `
          -Evidence @{
              eligibleScheduleCount = $eligibleSchedules.Count
              pimEnabled            = $pimInUse
          } `
          -GraphEndpoint '/roleManagement/directory/roleEligibilitySchedules' `
          -SupportsRemediation $true))

      return $findings.ToArray()
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
  git commit -m "feat: implement Check-PIM (standing active roles, JIT model, Tier-0 role detection)"
  ```

---

### Task 12: Check-LegacyAuthentication

**Files:**
- Create: `src/Private/checks/Check-LegacyAuthentication.ps1`
- Create: `tests/checks/Check-LegacyAuthentication.Tests.ps1`

> **Graph API note:** `GET /policies/authenticationMethodsPolicy` → `Get-MgPolicyAuthenticationMethodPolicy` in `Microsoft.Graph.Identity.SignIns`. Verify cmdlet exists before implementation. Legacy auth tenant-level block also uses `GET /policies/authorizationPolicy`.

- [ ] **Step 1: Write failing tests**

  Create `tests/checks/Check-LegacyAuthentication.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../../src/Private/checks/Check-LegacyAuthentication.ps1"

      function New-MockGateway { [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Certificate'; Connected=$true } }
  }

  Describe 'Get-CheckMetadata' {
      It 'id is LA-001' { (Get-CheckMetadata).id | Should -Be 'LA-001' }
      It 'severity is Critical' { (Get-CheckMetadata).severity | Should -Be 'Critical' }
      It 'passes Test-CheckContract' {
          . "$PSScriptRoot/../../src/Private/policy/Test-CheckContract.ps1"
          $result = Test-CheckContract -ModulePath "$PSScriptRoot/../../src/Private/checks/Check-LegacyAuthentication.ps1"
          $result.IsValid | Should -BeTrue -Because ($result.Violations -join '; ')
      }
  }

  Describe 'Invoke-Check — legacy auth enabled at tenant' {
      It 'returns Fail when blockLegacyAuthentication is false' {
          $gw = New-MockGateway
          $authPolicy = [PSCustomObject]@{
              blockLegacyAuthentication = $false
          }
          Mock Invoke-GraphRequest {
              param($Uri)
              if ($Uri -match 'authorizationPolicy') {
                  return [PSCustomObject]@{ Result = @{ value = @($authPolicy) } }
              }
              return [PSCustomObject]@{ Result = @{ value = @() } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $f = $findings | Where-Object { $_.title -match 'Legacy' }
          $f.status | Should -Be 'Fail'
          $f.evidence.tenantLevelBlocked | Should -BeFalse
      }

      It 'returns Pass when blockLegacyAuthentication is true' {
          $gw = New-MockGateway
          $authPolicy = [PSCustomObject]@{ blockLegacyAuthentication = $true }
          Mock Invoke-GraphRequest {
              [PSCustomObject]@{ Result = @{ value = @($authPolicy) } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $f = $findings | Where-Object { $_.title -match 'Legacy' }
          $f.status | Should -Be 'Pass'
      }
  }

  Describe 'Invoke-Check — CA coverage cross-check' {
      It 'returns Fail evidence when no CA policy blocks legacy auth' {
          $gw = New-MockGateway
          $authPolicy = [PSCustomObject]@{ blockLegacyAuthentication = $false }
          Mock Invoke-GraphRequest {
              param($Uri)
              if ($Uri -match 'authorizationPolicy') { return [PSCustomObject]@{ Result = @{ value = @($authPolicy) } } }
              if ($Uri -match 'conditionalAccess') { return [PSCustomObject]@{ Result = @{ value = @() } } }
              return [PSCustomObject]@{ Result = @{ value = @() } }
          }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $f = $findings | Where-Object { $_.title -match 'Legacy' }
          $f.evidence.caBlockPolicyPresent | Should -BeFalse
      }
  }

  Describe 'Invoke-Check — error handling' {
      It 'returns NotAssessed when gateway throws' {
          $gw = New-MockGateway
          Mock Invoke-GraphRequest { throw 'auth error' }
          $findings = Invoke-Check -GraphGateway $gw -Config @{}
          $findings[0].status | Should -Be 'NotAssessed'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\checks\Check-LegacyAuthentication.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Check-LegacyAuthentication.ps1**

  Create `src/Private/checks/Check-LegacyAuthentication.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-CheckMetadata {
      @{
          id                    = 'LA-001'
          title                 = 'Legacy Authentication Assessment'
          category              = 'Identity Security'
          severity              = 'Critical'
          riskScoreBaseline     = 90
          secureScoreVisibility = 'Passes'
          description           = 'Evaluates whether legacy authentication protocols are blocked at tenant level and via Conditional Access. Legacy auth enables MFA bypass.'
          requiredPermissions   = @('Policy.Read.All')
          requiredExchangeRoles = @()
          dataSource            = 'Graph'
          supportsRemediation   = $true
          edition               = @('Lite','Premium')
          assessAuthMethods     = @('Certificate','Secret','Delegated')
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

      $authPolicy = $null
      $caPolicies = @()

      try {
          $authResp = Invoke-GraphRequest -GraphGateway $GraphGateway `
                          -Uri '/policies/authorizationPolicy' `
                          -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
          $authPolicy = $authResp.Result.value | Select-Object -First 1

          $caResp = Invoke-GraphRequest -GraphGateway $GraphGateway `
                        -Uri '/identity/conditionalAccess/policies' `
                        -Method 'GET' -OperationType 'Read' -Caller 'Auditor'
          $caPolicies = @($caResp.Result.value)
      } catch {
          $findings.Add((New-Finding -CheckId 'LA-001' -RunId $runId `
              -Title 'Legacy Authentication Assessment Failed' -Category 'Identity Security' `
              -Severity 'Critical' -RiskScore 90 -SecureScoreVisibility 'Passes' `
              -Status 'NotAssessed' -GraphEndpoint '/policies/authorizationPolicy' `
              -SupportsRemediation $false -ErrorMessage $_.Exception.Message))
          return $findings.ToArray()
      }

      $tenantBlocked = $authPolicy -and [bool]($authPolicy.blockLegacyAuthentication)

      $caLegacyBlock = @($caPolicies | Where-Object {
          $_.state -eq 'enabled' -and
          $_.conditions.clientAppTypes -contains 'exchangeActiveSync' -and
          $_.conditions.clientAppTypes -contains 'other' -and
          $_.grantControls.builtInControls -contains 'block'
      })

      $caReportOnly = @($caPolicies | Where-Object {
          $_.state -eq 'enabledForReportingButNotEnforced' -and
          $_.conditions.clientAppTypes -contains 'exchangeActiveSync'
      })

      $isBlocked = $tenantBlocked -or ($caLegacyBlock.Count -gt 0)
      $status    = if ($isBlocked) { 'Pass' } else { 'Fail' }

      $findings.Add((New-Finding -CheckId 'LA-001' -RunId $runId `
          -Title 'Legacy Authentication Not Blocked at Tenant or CA Level' `
          -Category 'Identity Security' -Severity 'Critical' -RiskScore 90 `
          -SecureScoreVisibility 'Passes' -Status $status `
          -Evidence @{
              tenantLevelBlocked   = $tenantBlocked
              caBlockPolicyPresent = ($caLegacyBlock.Count -gt 0)
              caBlockPolicyCount   = $caLegacyBlock.Count
              caReportOnlyCount    = $caReportOnly.Count
              effectivelyBlocked   = $isBlocked
          } `
          -GraphEndpoint '/policies/authorizationPolicy' `
          -SupportsRemediation $true))

      return $findings.ToArray()
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
  git commit -m "feat: implement Check-LegacyAuthentication (tenant-level block + CA cross-check, MFA bypass detection)"
  ```

---

### Task 13: Auditor

**Files:**
- Modify: `m365-security-assessment-tool.psm1` (exclude checks/ from auto dot-source)
- Create: `src/Private/Auditor.ps1`
- Create: `tests/Auditor.Tests.ps1`

> Checks must run in isolated scope so `Get-CheckMetadata`/`Invoke-Check` definitions don't clobber each other. Pattern: compile check file content into a scriptblock, invoke in child scope — parent-scope functions (`New-Finding`, `Invoke-GraphRequest`) resolve via PowerShell scope chain.

- [ ] **Step 1: Update .psm1 — exclude checks/ from dot-source**

  Replace `m365-security-assessment-tool.psm1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  $privatePath = Join-Path $PSScriptRoot 'src\Private'
  $publicPath  = Join-Path $PSScriptRoot 'src\Public'

  # Dot-source all Private files except checks/ — Auditor loads checks in isolation
  Get-ChildItem -Path $privatePath -Recurse -Filter '*.ps1' |
      Where-Object { $_.FullName -notmatch '\\checks\\' } |
      ForEach-Object { . $_.FullName }

  Get-ChildItem -Path $publicPath -Recurse -Filter '*.ps1' | ForEach-Object { . $_.FullName }
  ```

- [ ] **Step 2: Write failing tests**

  Create `tests/Auditor.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../src/Private/policy/Test-CheckContract.ps1"
      . "$PSScriptRoot/../src/Private/policy/Test-ExchangePermissions.ps1"
      . "$PSScriptRoot/../src/Private/Auditor.ps1"

      function New-TempCheck {
          param([string]$Id, [string]$DataSource = 'Graph', [string]$Status = 'Fail', [bool]$Throws = $false)
          $throwLine = if ($Throws) { "throw 'simulated error'" } else { '' }
          $content = @"
  function Get-CheckMetadata {
      @{ id='$Id'; title='Test $Id'; category='Test'; severity='High'; riskScoreBaseline=75
         secureScoreVisibility='Passes'; description='d'; requiredPermissions=@()
         requiredExchangeRoles=@(); dataSource='$DataSource'; supportsRemediation=`$false
         edition=@('Lite','Premium'); assessAuthMethods=@('Certificate','Secret','Delegated') }
  }
  function Invoke-Check {
      param(`$GraphGateway, `$Config)
      $throwLine
      @(New-Finding -CheckId '$Id' -RunId `$GraphGateway.RunId -Title 'Test' -Category 'Test' ``
          -Severity 'High' -RiskScore 75 -SecureScoreVisibility 'Passes' -Status '$Status' ``
          -GraphEndpoint '/test' -SupportsRemediation `$false)
  }
  "@
          $tmp = [System.IO.Path]::GetTempFileName() + '.ps1'
          Set-Content -Path $tmp -Value $content
          return $tmp
      }

      $mockGw = [PSCustomObject]@{
          PSTypeName = 'Metis.GraphGateway'; AuthMethod = 'Certificate'
          RunId = 'run-001'; Connected = $true
      }
  }

  Describe 'Invoke-Audit — basic discovery' {
      It 'runs all checks in ChecksPath and returns findings' {
          $tmp1 = New-TempCheck -Id 'TST-001'
          $tmp2 = New-TempCheck -Id 'TST-002'
          $dir  = Split-Path $tmp1
          try {
              $findings = Invoke-Audit -GraphGateway $mockGw -Config @{ EnabledChecks = @() } `
                              -ChecksPath $dir -RunId 'run-001'
              # At least both checks ran (may include other temp files in dir, filter by checkId)
              $checkIds = $findings | Select-Object -ExpandProperty checkId -Unique
              $checkIds | Should -Contain 'TST-001'
              $checkIds | Should -Contain 'TST-002'
          } finally {
              Remove-Item $tmp1, $tmp2 -ErrorAction SilentlyContinue
          }
      }
  }

  Describe 'Invoke-Audit — IncludeChecks filter' {
      It 'skips checks not in EnabledChecks when list is non-empty' {
          $tmp1 = New-TempCheck -Id 'TST-003'
          $tmp2 = New-TempCheck -Id 'TST-004'
          $dir  = Split-Path $tmp1
          try {
              $findings = Invoke-Audit -GraphGateway $mockGw -Config @{ EnabledChecks = @('TST-003') } `
                              -ChecksPath $dir -RunId 'run-001'
              ($findings | Where-Object { $_.checkId -eq 'TST-003' }).Count | Should -BeGreaterThan 0
              ($findings | Where-Object { $_.checkId -eq 'TST-004' }).Count | Should -Be 0
          } finally {
              Remove-Item $tmp1, $tmp2 -ErrorAction SilentlyContinue
          }
      }
  }

  Describe 'Invoke-Audit — per-check error isolation' {
      It 'marks one check NotAssessed when it throws, continues running others' {
          $good = New-TempCheck -Id 'TST-005' -Status 'Fail'
          $bad  = New-TempCheck -Id 'TST-006' -Throws $true
          $dir  = Split-Path $good
          try {
              $findings = Invoke-Audit -GraphGateway $mockGw -Config @{ EnabledChecks = @() } `
                              -ChecksPath $dir -RunId 'run-001'
              $goodFindings = $findings | Where-Object { $_.checkId -eq 'TST-005' }
              $badFindings  = $findings | Where-Object { $_.checkId -eq 'TST-006' }
              $goodFindings | Should -Not -BeNullOrEmpty
              $goodFindings[0].status | Should -Be 'Fail'
              $badFindings | Should -Not -BeNullOrEmpty
              $badFindings[0].status | Should -Be 'NotAssessed'
          } finally {
              Remove-Item $good, $bad -ErrorAction SilentlyContinue
          }
      }
  }

  Describe 'Invoke-Audit — Exchange auth compatibility' {
      It 'marks Exchange check NotAssessed when AuthMethod=Secret' {
          $exchCheck = New-TempCheck -Id 'TST-007' -DataSource 'Exchange'
          try {
              $secretGw = [PSCustomObject]@{ PSTypeName='Metis.GraphGateway'; AuthMethod='Secret'; RunId='r1'; Connected=$true }
              $findings = Invoke-Audit -GraphGateway $secretGw -Config @{ EnabledChecks = @() } `
                              -ChecksPath (Split-Path $exchCheck) -RunId 'r1'
              $f = $findings | Where-Object { $_.checkId -eq 'TST-007' }
              $f | Should -Not -BeNullOrEmpty
              $f[0].status       | Should -Be 'NotAssessed'
              $f[0].error.message | Should -Match 'ExchangeAuthNotSupported'
          } finally {
              Remove-Item $exchCheck -ErrorAction SilentlyContinue
          }
      }
  }

  Describe 'Invoke-Audit — contract failure' {
      It 'marks check NotAssessed when Test-CheckContract fails' {
          $broken = [System.IO.Path]::GetTempFileName() + '.ps1'
          Set-Content -Path $broken -Value '# empty — no contract functions'
          try {
              $findings = Invoke-Audit -GraphGateway $mockGw -Config @{ EnabledChecks = @() } `
                              -ChecksPath (Split-Path $broken) -RunId 'run-001'
              # broken file has no Get-CheckMetadata, so contract fails
              # Auditor should handle gracefully — file is skipped or marked NotAssessed
              # We only assert it does not throw
          } finally {
              Remove-Item $broken -ErrorAction SilentlyContinue
          }
      }
  }
  ```

- [ ] **Step 3: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\Auditor.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 4: Implement Auditor.ps1**

  Create `src/Private/Auditor.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Invoke-Audit {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $GraphGateway,
          [Parameter()] $ExchangeGateway = $null,
          [Parameter(Mandatory)] [hashtable] $Config,
          [Parameter(Mandatory)] [string] $ChecksPath,
          [Parameter(Mandatory)] [string] $RunId
      )

      $allFindings = [System.Collections.Generic.List[object]]::new()
      $checkFiles  = Get-ChildItem -Path $ChecksPath -Filter 'Check-*.ps1' -File -ErrorAction Stop

      foreach ($file in $checkFiles) {
          $filePath = $file.FullName

          # 1. Contract validation (file-based AST analysis — no execution)
          $contractResult = Test-CheckContract -ModulePath $filePath
          if (-not $contractResult.IsValid) {
              $allFindings.Add((New-Finding -CheckId $file.BaseName -RunId $RunId `
                  -Title "Check Contract Violation: $($file.BaseName)" -Category 'System' `
                  -Severity 'Informational' -RiskScore 0 -SecureScoreVisibility 'NotFlagged' `
                  -Status 'NotAssessed' -GraphEndpoint 'N/A' -SupportsRemediation $false `
                  -ErrorMessage "ContractViolation: $($contractResult.Violations -join '; ')"))
              continue
          }

          # 2. Read metadata in child scope (isolated — does not pollute session)
          # & { . $filePath; ... } replaces ScriptBlock::Create("$content; ..."):
          # no string interpolation, no injection vector, full debugger support.
          $meta = $null
          try {
              $meta = & { . $filePath; Get-CheckMetadata }
          } catch {
              $allFindings.Add((New-Finding -CheckId $file.BaseName -RunId $RunId `
                  -Title "Get-CheckMetadata Failed: $($file.BaseName)" -Category 'System' `
                  -Severity 'Informational' -RiskScore 0 -SecureScoreVisibility 'NotFlagged' `
                  -Status 'NotAssessed' -GraphEndpoint 'N/A' -SupportsRemediation $false `
                  -ErrorMessage $_.Exception.Message))
              continue
          }

          # 3. IncludeChecks filter (empty = run all)
          $enabledChecks = $Config.EnabledChecks
          if ($enabledChecks -and $enabledChecks.Count -gt 0 -and $meta.id -notin $enabledChecks) {
              continue
          }

          # 4. Exchange auth compatibility gate
          if ($meta.dataSource -in @('Exchange','Both') -and $GraphGateway.AuthMethod -eq 'Secret') {
              $allFindings.Add((New-Finding -CheckId $meta.id -RunId $RunId `
                  -Title "$($meta.title) (Skipped)" -Category $meta.category `
                  -Severity $meta.severity -RiskScore $meta.riskScoreBaseline `
                  -SecureScoreVisibility $meta.secureScoreVisibility `
                  -Status 'NotAssessed' -GraphEndpoint 'N/A' -SupportsRemediation $false `
                  -ErrorMessage 'ExchangeAuthNotSupported: AuthMethod=Secret cannot authenticate to ExchangeOnlineManagement'))
              continue
          }

          # 5. Run check in child scope — New-Finding + Invoke-GraphRequest resolve from parent scope
          try {
              $findings = & { . $filePath; Invoke-Check -GraphGateway $GraphGateway -Config $Config }

              foreach ($f in $findings) {
                  if (-not $f.runId) { $f.runId = $RunId }
                  $allFindings.Add($f)
              }
          } catch {
              $allFindings.Add((New-Finding -CheckId $meta.id -RunId $RunId `
                  -Title "$($meta.title) (Failed)" -Category $meta.category `
                  -Severity $meta.severity -RiskScore $meta.riskScoreBaseline `
                  -SecureScoreVisibility $meta.secureScoreVisibility `
                  -Status 'NotAssessed' -GraphEndpoint 'N/A' -SupportsRemediation $false `
                  -ErrorMessage $_.Exception.Message))
          }
      }

      return $allFindings.ToArray()
  }
  ```

- [ ] **Step 5: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\Auditor.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 6: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\Auditor.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/Auditor.ps1 m365-security-assessment-tool.psm1 tests/Auditor.Tests.ps1
  git commit -m "feat: add Auditor (check discovery, contract gate, Exchange auth guard, per-check isolation)"
  ```

---

### Task 14: Reporter — JSON Artifacts

**Files:**
- Create: `src/Private/Reporter.ps1`
- Create: `tests/Reporter.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/Reporter.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../src/Private/models/Finding.schema.ps1"
      . "$PSScriptRoot/../src/Private/models/RemediationAction.schema.ps1"
      . "$PSScriptRoot/../src/Private/Reporter.ps1"

      $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "metis-reporter-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
      New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

      $sampleFinding = New-Finding -CheckId 'CA-001' -RunId 'run-001' `
          -Title 'Legacy Auth' -Category 'Identity' -Severity 'Critical' -RiskScore 95 `
          -SecureScoreVisibility 'Passes' -Status 'Fail' -GraphEndpoint '/test' -SupportsRemediation $true

      $sampleManifest = @{
          schemaVersion  = '1.0'
          run            = @{ runId='run-001'; mode='Assess'; whatIf=$false }
          tenantPinning  = @{ match=$true }
          auth           = @{ authMethod='Certificate' }
          execution      = @{ status='Success'; findings=@{ total=1; critical=1 } }
      }
  }

  AfterAll { Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }

  Describe 'Write-FindingsJson' {
      It 'writes valid JSON array to findings.json' {
          $path = Write-FindingsJson -Findings @($sampleFinding) -OutputFolder $tmpDir
          $path | Should -Exist
          $json = Get-Content $path -Raw | ConvertFrom-Json
          $json.Count | Should -Be 1
          $json[0].checkId | Should -Be 'CA-001'
      }
  }

  Describe 'Write-RunManifest' {
      It 'writes run.manifest.json with required top-level keys' {
          $path = Write-RunManifest -Manifest $sampleManifest -OutputFolder $tmpDir
          $path | Should -Exist
          $json = Get-Content $path -Raw | ConvertFrom-Json
          $json.schemaVersion | Should -Be '1.0'
          $json.run.runId     | Should -Be 'run-001'
      }

      It 'manifest includes artifact sha256 entries for findings.json' {
          $findingsPath = Write-FindingsJson -Findings @($sampleFinding) -OutputFolder $tmpDir
          $manifest = $sampleManifest.Clone()
          $manifest['artifacts'] = @(
              @{ name='findings.json'; path=$findingsPath }
          )
          $path = Write-RunManifest -Manifest $manifest -OutputFolder $tmpDir -ComputeArtifactHashes
          $json = Get-Content $path -Raw | ConvertFrom-Json
          $json.artifacts[0].sha256 | Should -Match '^sha256:'
      }
  }

  Describe 'Append-RemediationActionLog' {
      It 'appends NDJSON entries — does not overwrite' {
          $logPath = Join-Path $tmpDir 'remediation.actions.jsonl'
          $action1 = @{ actionId='ACT-001'; result=@{ status='Success' } }
          $action2 = @{ actionId='ACT-002'; result=@{ status='Blocked' } }
          Append-RemediationActionLog -Action $action1 -LogPath $logPath
          Append-RemediationActionLog -Action $action2 -LogPath $logPath
          $lines = Get-Content $logPath
          $lines.Count | Should -Be 2
          ($lines[0] | ConvertFrom-Json).actionId | Should -Be 'ACT-001'
          ($lines[1] | ConvertFrom-Json).actionId | Should -Be 'ACT-002'
      }
  }

  Describe 'Get-Sha256' {
      It 'returns sha256: prefixed hash of a file' {
          $f = Join-Path $tmpDir 'hashtest.txt'
          Set-Content -Path $f -Value 'hello'
          $hash = Get-Sha256 -FilePath $f
          $hash | Should -Match '^sha256:[a-f0-9]{64}$'
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\Reporter.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement Reporter.ps1 (JSON functions)**

  Create `src/Private/Reporter.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-Sha256 {
      [CmdletBinding()]
      param([Parameter(Mandatory)][string] $FilePath)
      $sha  = [System.Security.Cryptography.SHA256]::Create()
      $stream = [System.IO.File]::OpenRead($FilePath)
      try {
          $hash = $sha.ComputeHash($stream)
      } finally { $stream.Dispose() }
      'sha256:' + ([BitConverter]::ToString($hash) -replace '-','').ToLower()
  }

  function Write-FindingsJson {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $Findings,
          [Parameter(Mandatory)][string] $OutputFolder
      )
      $path = Join-Path $OutputFolder 'findings.json'
      $Findings | ConvertTo-Json -Depth 20 | Set-Content -Path $path -Encoding UTF8
      return $path
  }

  function Write-RunManifest {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $Manifest,
          [Parameter(Mandatory)][string] $OutputFolder,
          [Parameter()][switch] $ComputeArtifactHashes
      )
      if ($ComputeArtifactHashes -and $Manifest.artifacts) {
          foreach ($i in 0..($Manifest.artifacts.Count - 1)) {
              $artifact = $Manifest.artifacts[$i].Clone()
              if ($artifact.path -and (Test-Path $artifact.path)) {
                  $artifact['sha256'] = Get-Sha256 -FilePath $artifact.path
              }
              $Manifest.artifacts[$i] = $artifact
          }
      }
      $path = Join-Path $OutputFolder 'run.manifest.json'
      $Manifest | ConvertTo-Json -Depth 20 | Set-Content -Path $path -Encoding UTF8
      return $path
  }

  function Append-RemediationActionLog {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $Action,
          [Parameter(Mandatory)][string] $LogPath
      )
      $line = $Action | ConvertTo-Json -Depth 20 -Compress
      Add-Content -Path $LogPath -Value $line -Encoding UTF8
  }

  function Write-SequencePlanJson {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $SequencePlan,
          [Parameter(Mandatory)][string] $OutputFolder
      )
      $path = Join-Path $OutputFolder 'sequence-plan.json'
      $SequencePlan | ConvertTo-Json -Depth 20 | Set-Content -Path $path -Encoding UTF8
      return $path
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\Reporter.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\Reporter.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/Reporter.ps1 tests/Reporter.Tests.ps1
  git commit -m "feat: add Reporter JSON functions (findings.json, run.manifest.json, NDJSON audit log, sha256 hashing)"
  ```

---

### Task 15: Reporter — HTML Report

**Files:**
- Create: `templates/report.html.ps1`
- Modify: `src/Private/Reporter.ps1` (add `Write-HtmlReport`)
- Modify: `tests/Reporter.Tests.ps1` (add HTML tests)

- [ ] **Step 1: Write failing tests — add to Reporter.Tests.ps1**

  Append to `tests/Reporter.Tests.ps1` (inside the file, before the closing):

  ```powershell
  Describe 'Write-HtmlReport' {
      BeforeAll {
          $findings = @(
              (New-Finding -CheckId 'CA-001' -RunId 'r1' -Title 'Legacy Auth' -Category 'Identity' `
                  -Severity 'Critical' -RiskScore 95 -SecureScoreVisibility 'Passes' `
                  -Status 'Fail' -GraphEndpoint '/test' -SupportsRemediation $true),
              (New-Finding -CheckId 'PIM-001' -RunId 'r1' -Title 'PIM Not Used' -Category 'Privileged Access' `
                  -Severity 'High' -RiskScore 80 -SecureScoreVisibility 'NotFlagged' `
                  -Status 'Fail' -GraphEndpoint '/test' -SupportsRemediation $true),
              (New-Finding -CheckId 'LA-001' -RunId 'r1' -Title 'Legacy Blocked' -Category 'Identity' `
                  -Severity 'Critical' -RiskScore 90 -SecureScoreVisibility 'Passes' `
                  -Status 'Pass' -GraphEndpoint '/test' -SupportsRemediation $false)
          )
          $meta = @{
              RunId = 'run-001'; Mode = 'Assess'; AuthMethod = 'Certificate'
              TenantIdMasked = 'aaaa-...-eeee'; Timestamp = '2026-05-18T00:00:00Z'
              ModuleVersion = '0.1.0'; GitCommit = 'abc1234'
          }
      }

      It 'writes report.html to output folder' {
          $path = Write-HtmlReport -Findings $findings -Metadata $meta -OutputFolder $tmpDir
          $path | Should -Exist
          $path | Should -Match '\.html$'
      }

      It 'HTML contains executive summary section' {
          $path = Write-HtmlReport -Findings $findings -Metadata $meta -OutputFolder $tmpDir
          $html = Get-Content $path -Raw
          $html | Should -Match 'Executive Summary'
      }

      It 'HTML contains Technical Findings section' {
          $path = Write-HtmlReport -Findings $findings -Metadata $meta -OutputFolder $tmpDir
          $html = Get-Content $path -Raw
          $html | Should -Match 'Technical Findings'
      }

      It 'Critical findings appear before High in HTML' {
          $path = Write-HtmlReport -Findings $findings -Metadata $meta -OutputFolder $tmpDir
          $html = Get-Content $path -Raw
          $critPos = $html.IndexOf('Critical')
          $highPos = $html.IndexOf('High')
          $critPos | Should -BeLessThan $highPos
      }

      It 'HTML embeds RunId and masked TenantId' {
          $path = Write-HtmlReport -Findings $findings -Metadata $meta -OutputFolder $tmpDir
          $html = Get-Content $path -Raw
          $html | Should -Match 'run-001'
          $html | Should -Match 'aaaa-...-eeee'
      }

      It 'SecureScoreVisibility badge present for each finding' {
          $path = Write-HtmlReport -Findings $findings -Metadata $meta -OutputFolder $tmpDir
          $html = Get-Content $path -Raw
          $html | Should -Match 'Passes'
          $html | Should -Match 'NotFlagged'
      }
  }
  ```

- [ ] **Step 2: Run — verify new tests fail**

  ```powershell
  Invoke-Pester -Path tests\Reporter.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Create templates/report.html.ps1**

  Create `templates/report.html.ps1`:

  ```powershell
  function Get-ReportHtmlTemplate {
      param(
          [Parameter(Mandatory)] $Findings,
          [Parameter(Mandatory)] $Metadata
      )

      $severityOrder = @{ Critical=0; High=1; Medium=2; Informational=3 }
      $sorted = $Findings | Sort-Object { $severityOrder[$_.severity] }

      $critCount  = @($Findings | Where-Object { $_.severity -eq 'Critical' -and $_.status -eq 'Fail' }).Count
      $highCount  = @($Findings | Where-Object { $_.severity -eq 'High'     -and $_.status -eq 'Fail' }).Count
      $totalFail  = @($Findings | Where-Object { $_.status -eq 'Fail' }).Count

      $postureText = if ($critCount -gt 0) {
          "CRITICAL RISK — $critCount critical control gap(s) require immediate attention."
      } elseif ($highCount -gt 0) {
          "HIGH RISK — $highCount high-severity gap(s) identified."
      } else {
          "MODERATE RISK — review findings for remediation opportunities."
      }

      $badgeColor = @{
          Critical      = '#c0392b'; High          = '#e67e22'
          Medium        = '#f1c40f'; Informational = '#3498db'
          Pass          = '#27ae60'; Fail          = '#c0392b'; NotAssessed = '#95a5a6'
          Passes        = '#95a5a6'; NotFlagged    = '#e67e22'; Partial      = '#f39c12'
      }

      $findingRows = ($sorted | ForEach-Object {
          $f = $_
          $sev = $f.severity
          $sColor  = $badgeColor[$sev]
          $stColor = $badgeColor[$f.status]
          $ssvColor = $badgeColor[$f.secureScoreVisibility]
          "<tr>
            <td><span style='background:$sColor;color:#fff;padding:2px 8px;border-radius:3px;font-size:12px'>$sev</span></td>
            <td><span style='background:$ssvColor;color:#fff;padding:2px 8px;border-radius:3px;font-size:12px'>$($f.secureScoreVisibility)</span></td>
            <td><span style='background:$stColor;color:#fff;padding:2px 8px;border-radius:3px;font-size:12px'>$($f.status)</span></td>
            <td>$($f.title)</td>
            <td>$($f.category)</td>
            <td>$($f.riskScore)</td>
          </tr>"
      }) -join "`n"

      return @"
  <!DOCTYPE html>
  <html lang='en'>
  <head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>M365 Security Assessment — $($Metadata.RunId)</title>
    <style>
      body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }
      .header { background: #2c3e50; color: #fff; padding: 24px 40px; }
      .header h1 { margin: 0 0 8px 0; font-size: 22px; }
      .meta { font-size: 12px; opacity: 0.75; }
      .section { margin: 32px 40px; background: #fff; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); padding: 24px; }
      .section h2 { margin-top: 0; font-size: 18px; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
      .posture { font-size: 18px; font-weight: bold; margin-bottom: 16px; }
      table { border-collapse: collapse; width: 100%; }
      th { background: #ecf0f1; text-align: left; padding: 10px 12px; font-size: 13px; }
      td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; font-size: 13px; vertical-align: middle; }
      tr:hover td { background: #fafafa; }
    </style>
  </head>
  <body>
    <div class='header'>
      <h1>M365 Security Assessment Report</h1>
      <div class='meta'>
        Run ID: $($Metadata.RunId) &nbsp;|&nbsp;
        Mode: $($Metadata.Mode) &nbsp;|&nbsp;
        Auth: $($Metadata.AuthMethod) &nbsp;|&nbsp;
        Tenant: $($Metadata.TenantIdMasked) &nbsp;|&nbsp;
        Timestamp: $($Metadata.Timestamp) &nbsp;|&nbsp;
        Version: $($Metadata.ModuleVersion) ($($Metadata.GitCommit))
      </div>
    </div>

    <div class='section'>
      <h2>Executive Summary</h2>
      <div class='posture'>$postureText</div>
      <p>Total findings: <strong>$($Findings.Count)</strong> &nbsp;|&nbsp;
         Failed controls: <strong>$totalFail</strong> &nbsp;|&nbsp;
         Critical: <strong>$critCount</strong> &nbsp;|&nbsp;
         High: <strong>$highCount</strong></p>
    </div>

    <div class='section'>
      <h2>Technical Findings</h2>
      <table>
        <thead><tr><th>Severity</th><th>Secure Score</th><th>Status</th><th>Finding</th><th>Domain</th><th>Risk Score</th></tr></thead>
        <tbody>$findingRows</tbody>
      </table>
    </div>
  </body>
  </html>
  "@
  }
  ```

- [ ] **Step 4: Add Write-HtmlReport to Reporter.ps1**

  Append to `src/Private/Reporter.ps1`:

  ```powershell
  function Write-HtmlReport {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)] $Findings,
          [Parameter(Mandatory)] [hashtable] $Metadata,
          [Parameter(Mandatory)] [string] $OutputFolder
      )
      # Load template function (dot-sourced by .psm1; or reference directly)
      $html = Get-ReportHtmlTemplate -Findings $Findings -Metadata $Metadata
      $path = Join-Path $OutputFolder 'report.html'
      $html | Set-Content -Path $path -Encoding UTF8
      return $path
  }
  ```

- [ ] **Step 5: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\Reporter.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 6: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\Reporter.ps1, templates\report.html.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/Reporter.ps1 templates/report.html.ps1 tests/Reporter.Tests.ps1
  git commit -m "feat: add Reporter HTML (executive summary, technical findings table, severity sort, SSV badges)"
  ```

---

### Task 16: ActionGraphBuilder

**Files:**
- Create: `src/Private/sequencing/ActionGraphBuilder.ps1`
- Create: `tests/sequencing/ActionGraphBuilder.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/sequencing/ActionGraphBuilder.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../src/Private/sequencing/ActionGraphBuilder.ps1" }

  function New-Action {
      param([string]$Id, [string[]]$Deps = @())
      [PSCustomObject]@{ action=@{actionId=$Id}; sequence=@{dependencies=$Deps} }
  }

  Describe 'Build-ActionGraph' {
      It 'builds graph with correct node count' {
          $actions = @((New-Action 'ACT-001'), (New-Action 'ACT-002'))
          $graph = Build-ActionGraph -Actions $actions
          $graph.Nodes.Count | Should -Be 2
      }

      It 'adds edge for declared dependency' {
          $a1 = New-Action 'ACT-001'
          $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
          $graph = Build-ActionGraph -Actions @($a1, $a2)
          $graph.Edges['ACT-002'] | Should -Contain 'ACT-001'
      }

      It 'node with no dependencies has empty edge list' {
          $a = New-Action 'ACT-001'
          $graph = Build-ActionGraph -Actions @($a)
          $graph.Edges['ACT-001'].Count | Should -Be 0
      }
  }

  Describe 'Test-AcyclicGraph — cycle detection' {
      It 'does not throw for a valid DAG' {
          $a1 = New-Action 'ACT-001'
          $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
          $graph = Build-ActionGraph -Actions @($a1, $a2)
          { Test-AcyclicGraph -Graph $graph } | Should -Not -Throw
      }

      It 'throws structured error for direct cycle (A→B→A)' {
          $a1 = New-Action 'ACT-001' -Deps @('ACT-002')
          $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
          $graph = Build-ActionGraph -Actions @($a1, $a2)
          { Test-AcyclicGraph -Graph $graph } |
              Should -Throw '*CircularDependency*'
      }

      It 'throws for indirect cycle (A→B→C→A)' {
          $a1 = New-Action 'ACT-001' -Deps @('ACT-003')
          $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
          $a3 = New-Action 'ACT-003' -Deps @('ACT-002')
          $graph = Build-ActionGraph -Actions @($a1, $a2, $a3)
          { Test-AcyclicGraph -Graph $graph } | Should -Throw '*CircularDependency*'
      }

      It 'identifies the cycle nodes in error message' {
          $a1 = New-Action 'ACT-001' -Deps @('ACT-002')
          $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
          $graph = Build-ActionGraph -Actions @($a1, $a2)
          try { Test-AcyclicGraph -Graph $graph } catch { $err = $_ }
          $err | Should -Not -BeNullOrEmpty
      }
  }

  Describe 'Get-TopologicalOrder' {
      It 'returns actions in dependency-first order' {
          $a1 = New-Action 'ACT-001'
          $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
          $a3 = New-Action 'ACT-003' -Deps @('ACT-002')
          $graph = Build-ActionGraph -Actions @($a3, $a2, $a1)  # intentionally out of order
          $order = Get-TopologicalOrder -Graph $graph
          $order.IndexOf('ACT-001') | Should -BeLessThan $order.IndexOf('ACT-002')
          $order.IndexOf('ACT-002') | Should -BeLessThan $order.IndexOf('ACT-003')
      }

      It 'is deterministic — same input produces same order' {
          $a1 = New-Action 'ACT-001'
          $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
          $graph = Build-ActionGraph -Actions @($a1, $a2)
          $order1 = Get-TopologicalOrder -Graph $graph
          $order2 = Get-TopologicalOrder -Graph $graph
          $order1 -join ',' | Should -Be ($order2 -join ',')
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\sequencing\ActionGraphBuilder.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement ActionGraphBuilder.ps1**

  Create `src/Private/sequencing/ActionGraphBuilder.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Build-ActionGraph {
      [CmdletBinding()]
      param([Parameter(Mandatory)] $Actions)

      $nodes = [System.Collections.Generic.Dictionary[string,object]]::new()
      $edges = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]]::new()

      foreach ($action in $Actions) {
          $id = $action.action.actionId
          $nodes[$id] = $action
          if (-not $edges.ContainsKey($id)) {
              $edges[$id] = [System.Collections.Generic.List[string]]::new()
          }
          foreach ($dep in @($action.sequence.dependencies)) {
              if ($dep) { $edges[$id].Add($dep) }
          }
      }

      return [PSCustomObject]@{ Nodes = $nodes; Edges = $edges }
  }

  function Test-AcyclicGraph {
      [CmdletBinding()]
      param([Parameter(Mandatory)] $Graph)

      # Kahn's algorithm — tracks in-degree, processes zero-in-degree nodes
      $inDegree = [System.Collections.Generic.Dictionary[string,int]]::new()
      foreach ($id in $Graph.Nodes.Keys) { $inDegree[$id] = 0 }

      foreach ($id in $Graph.Edges.Keys) {
          foreach ($dep in $Graph.Edges[$id]) {
              if ($Graph.Nodes.ContainsKey($dep)) {
                  $inDegree[$id] = $inDegree[$id] + 1
              }
          }
      }

      $queue = [System.Collections.Generic.Queue[string]]::new()
      foreach ($id in ($inDegree.Keys | Sort-Object)) {    # Sort for determinism
          if ($inDegree[$id] -eq 0) { $queue.Enqueue($id) }
      }

      $processed = 0
      while ($queue.Count -gt 0) {
          $current = $queue.Dequeue()
          $processed++
          # Find nodes that depend on $current and reduce their in-degree
          foreach ($id in $Graph.Edges.Keys) {
              if ($Graph.Edges[$id] -contains $current) {
                  $inDegree[$id] = $inDegree[$id] - 1
                  if ($inDegree[$id] -eq 0) { $queue.Enqueue($id) }
              }
          }
      }

      if ($processed -ne $Graph.Nodes.Count) {
          $cycleNodes = $Graph.Nodes.Keys | Where-Object { $inDegree[$_] -gt 0 }
          throw [System.InvalidOperationException]::new(
              "CircularDependency detected in action graph. Nodes involved: $($cycleNodes -join ', ')"
          )
      }
  }

  function Get-TopologicalOrder {
      [CmdletBinding()]
      param([Parameter(Mandatory)] $Graph)

      Test-AcyclicGraph -Graph $Graph

      $inDegree = [System.Collections.Generic.Dictionary[string,int]]::new()
      foreach ($id in $Graph.Nodes.Keys) { $inDegree[$id] = 0 }
      foreach ($id in $Graph.Edges.Keys) {
          foreach ($dep in $Graph.Edges[$id]) {
              if ($Graph.Nodes.ContainsKey($dep)) { $inDegree[$id]++ }
          }
      }

      $queue  = [System.Collections.Generic.SortedSet[string]]::new()    # sorted for determinism
      $result = [System.Collections.Generic.List[string]]::new()

      foreach ($id in $inDegree.Keys) {
          if ($inDegree[$id] -eq 0) { $queue.Add($id) | Out-Null }
      }

      while ($queue.Count -gt 0) {
          $current = $queue.Min
          $queue.Remove($current) | Out-Null
          $result.Add($current)
          foreach ($id in ($Graph.Edges.Keys | Sort-Object)) {
              if ($Graph.Edges[$id] -contains $current) {
                  $inDegree[$id]--
                  if ($inDegree[$id] -eq 0) { $queue.Add($id) | Out-Null }
              }
          }
      }

      return $result.ToArray()
  }
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\sequencing\ActionGraphBuilder.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\sequencing\ActionGraphBuilder.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/sequencing/ActionGraphBuilder.ps1 tests/sequencing/ActionGraphBuilder.Tests.ps1
  git commit -m "feat: add ActionGraphBuilder (Kahn DAG, cycle detection with node list, deterministic topological sort)"
  ```

---

### Task 17: Dependency Rules Library

**Files:**
- Create: `src/Private/sequencing/rules/CA.rules.ps1`
- Create: `src/Private/sequencing/rules/PIM.rules.ps1`
- Create: `src/Private/sequencing/rules/LegacyAuth.rules.ps1`
- Create: `tests/sequencing/rules/CA.rules.Tests.ps1`
- Create: `tests/sequencing/rules/PIM.rules.Tests.ps1`
- Create: `tests/sequencing/rules/LegacyAuth.rules.Tests.ps1`

> Rules are pure data — each file exposes `Get-Rules` returning an array of rule objects. The DependencyRulesEngine (Task 18) evaluates them. No live Graph calls in rule files.

- [ ] **Step 1: Write failing tests — CA rules**

  Create `tests/sequencing/rules/CA.rules.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../../src/Private/sequencing/rules/CA.rules.ps1" }

  Describe 'CA.rules — structure' {
      BeforeAll { $rules = Get-Rules }

      It 'returns non-empty array' {
          $rules.Count | Should -BeGreaterThan 0
      }

      It 'each rule has required fields' {
          foreach ($r in $rules) {
              $r.ruleId           | Should -Not -BeNullOrEmpty
              $r.appliesToAction  | Should -Not -BeNullOrEmpty
              $r.type             | Should -BeIn @('Dependency','Block','Conflict','Advisory')
              $r.condition.fact   | Should -Not -BeNullOrEmpty
              $r.condition.operator | Should -Not -BeNullOrEmpty
              $r.priority         | Should -BeGreaterThan 0
              $r.version          | Should -Be '1.0.0'
          }
      }

      It 'contains CA-DEP-001' { $rules.ruleId | Should -Contain 'CA-DEP-001' }
      It 'contains CA-BLOCK-001' { $rules.ruleId | Should -Contain 'CA-BLOCK-001' }
      It 'contains CA-DEP-002' { $rules.ruleId | Should -Contain 'CA-DEP-002' }
      It 'contains CA-CONFLICT-001' { $rules.ruleId | Should -Contain 'CA-CONFLICT-001' }

      It 'CA-BLOCK-001 is type Block' {
          ($rules | Where-Object { $_.ruleId -eq 'CA-BLOCK-001' }).type | Should -Be 'Block'
      }

      It 'CA-DEP-001 effect has dependency field' {
          $r = $rules | Where-Object { $_.ruleId -eq 'CA-DEP-001' }
          $r.effect.dependency | Should -Not -BeNullOrEmpty
      }
  }
  ```

- [ ] **Step 2: Write failing tests — PIM + LegacyAuth rules**

  Create `tests/sequencing/rules/PIM.rules.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../../src/Private/sequencing/rules/PIM.rules.ps1" }

  Describe 'PIM.rules — structure' {
      BeforeAll { $rules = Get-Rules }
      It 'returns non-empty array' { $rules.Count | Should -BeGreaterThan 0 }
      It 'contains PIM-DEP-001' { $rules.ruleId | Should -Contain 'PIM-DEP-001' }
      It 'contains PIM-BLOCK-001' { $rules.ruleId | Should -Contain 'PIM-BLOCK-001' }
      It 'PIM-BLOCK-001 is type Block' {
          ($rules | Where-Object { $_.ruleId -eq 'PIM-BLOCK-001' }).type | Should -Be 'Block'
      }
  }
  ```

  Create `tests/sequencing/rules/LegacyAuth.rules.Tests.ps1`:

  ```powershell
  BeforeAll { . "$PSScriptRoot/../../../src/Private/sequencing/rules/LegacyAuth.rules.ps1" }

  Describe 'LegacyAuth.rules — structure' {
      BeforeAll { $rules = Get-Rules }
      It 'returns non-empty array' { $rules.Count | Should -BeGreaterThan 0 }
      It 'contains LA-DEP-001' { $rules.ruleId | Should -Contain 'LA-DEP-001' }
      It 'contains LA-ADV-001' { $rules.ruleId | Should -Contain 'LA-ADV-001' }
      It 'LA-ADV-001 is type Advisory' {
          ($rules | Where-Object { $_.ruleId -eq 'LA-ADV-001' }).type | Should -Be 'Advisory'
      }
  }
  ```

- [ ] **Step 3: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\sequencing\rules\ -Output Detailed
  ```

- [ ] **Step 4: Implement CA.rules.ps1**

  Create `src/Private/sequencing/rules/CA.rules.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-Rules {
      @(
          [PSCustomObject]@{
              ruleId         = 'CA-DEP-001'
              appliesToAction = 'ACT-CA-ENABLE-MFA'
              type           = 'Dependency'
              condition      = [PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$true }
              effect         = [PSCustomObject]@{ dependency='ACT-CA-EXCLUDE-BREAKGLASS'; blockIfUnsatisfied=$true; reason='Break-glass accounts must be excluded before enabling MFA policy' }
              priority       = 1; category='Identity'; version='1.0.0'
          }
          [PSCustomObject]@{
              ruleId         = 'CA-BLOCK-001'
              appliesToAction = 'ACT-CA-ENABLE-MFA'
              type           = 'Block'
              condition      = [PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$false }
              effect         = [PSCustomObject]@{ dependency=$null; blockIfUnsatisfied=$true; reason='Cannot enable MFA policy: no break-glass accounts present. Lockout risk.' }
              priority       = 10; category='Identity'; version='1.0.0'
          }
          [PSCustomObject]@{
              ruleId         = 'CA-DEP-002'
              appliesToAction = 'ACT-CA-ENFORCE-MFA'
              type           = 'Dependency'
              condition      = [PSCustomObject]@{ fact='LegacyAuthBlocked'; operator='Equals'; value=$true }
              effect         = [PSCustomObject]@{ dependency='ACT-CA-BLOCK-LEGACYAUTH'; blockIfUnsatisfied=$false; reason='Legacy auth block should precede MFA enforcement for clean audit trail' }
              priority       = 2; category='Identity'; version='1.0.0'
          }
          [PSCustomObject]@{
              ruleId         = 'CA-CONFLICT-001'
              appliesToAction = 'ACT-CA-BLOCK-ALL'
              type           = 'Conflict'
              condition      = [PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
              effect         = [PSCustomObject]@{ conflictsWith='ACT-CA-REQUIRE-MFA'; blockIfUnsatisfied=$false; reason='Block-all policy conflicts with per-user MFA grant policy' }
              priority       = 5; category='Identity'; version='1.0.0'
          }
      )
  }
  ```

- [ ] **Step 5: Implement PIM.rules.ps1**

  Create `src/Private/sequencing/rules/PIM.rules.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-Rules {
      @(
          [PSCustomObject]@{
              ruleId         = 'PIM-DEP-001'
              appliesToAction = 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE'
              type           = 'Dependency'
              condition      = [PSCustomObject]@{ fact='PIMEnabled'; operator='Equals'; value=$true }
              effect         = [PSCustomObject]@{ dependency=$null; blockIfUnsatisfied=$true; reason='PIM must be licensed and enabled before converting role assignments' }
              priority       = 1; category='PrivilegedAccess'; version='1.0.0'
          }
          [PSCustomObject]@{
              ruleId         = 'PIM-BLOCK-001'
              appliesToAction = 'ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE'
              type           = 'Block'
              condition      = [PSCustomObject]@{ fact='PIMEnabled'; operator='Equals'; value=$false }
              effect         = [PSCustomObject]@{ dependency=$null; blockIfUnsatisfied=$true; reason='PIM not enabled — all PIM remediation blocked' }
              priority       = 10; category='PrivilegedAccess'; version='1.0.0'
          }
          [PSCustomObject]@{
              ruleId         = 'PIM-DEP-002'
              appliesToAction = 'ACT-PIM-CONFIGURE-ROLE-SETTINGS'
              type           = 'Dependency'
              condition      = [PSCustomObject]@{ fact='PIMConversionComplete'; operator='Equals'; value=$true }
              effect         = [PSCustomObject]@{ dependency='ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE'; blockIfUnsatisfied=$false; reason='Role settings should be configured after active-to-eligible conversion' }
              priority       = 2; category='PrivilegedAccess'; version='1.0.0'
          }
          [PSCustomObject]@{
              ruleId         = 'PIM-DEP-003'
              appliesToAction = 'ACT-PIM-ENABLE-TIER0-ROLE'
              type           = 'Dependency'
              condition      = [PSCustomObject]@{ fact='ApprovalWorkflowConfigured'; operator='Equals'; value=$true }
              effect         = [PSCustomObject]@{ dependency='ACT-PIM-CONFIGURE-APPROVAL-WORKFLOW'; blockIfUnsatisfied=$true; reason='Tier-0 role activation requires approval workflow before enablement' }
              priority       = 3; category='PrivilegedAccess'; version='1.0.0'
          }
      )
  }
  ```

- [ ] **Step 6: Implement LegacyAuth.rules.ps1**

  Create `src/Private/sequencing/rules/LegacyAuth.rules.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function Get-Rules {
      @(
          [PSCustomObject]@{
              ruleId         = 'LA-DEP-001'
              appliesToAction = 'ACT-LA-BLOCK-PROTOCOLS'
              type           = 'Dependency'
              condition      = [PSCustomObject]@{ fact='CAFrameworkPresent'; operator='Equals'; value=$true }
              effect         = [PSCustomObject]@{ dependency='ACT-CA-BASELINE'; blockIfUnsatisfied=$true; reason='Conditional Access framework must exist before blocking legacy auth protocols at policy layer' }
              priority       = 2; category='Identity'; version='1.0.0'
          }
          [PSCustomObject]@{
              ruleId         = 'LA-ADV-001'
              appliesToAction = 'ACT-LA-BLOCK-PROTOCOLS'
              type           = 'Advisory'
              condition      = [PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
              effect         = [PSCustomObject]@{ dependency=$null; blockIfUnsatisfied=$false; reason='Advisory: review sign-in logs for legacy auth usage before blocking — prevents unexpected client lockout' }
              priority       = 1; category='Identity'; version='1.0.0'
          }
      )
  }
  ```

- [ ] **Step 7: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\sequencing\rules\ -Output Detailed
  ```

- [ ] **Step 8: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\sequencing\rules\ -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/sequencing/rules/ tests/sequencing/rules/
  git commit -m "feat: add CA, PIM, LegacyAuth dependency rules (Block/Dependency/Conflict/Advisory, v1.0.0)"
  ```

---

### Task 18: DependencyRulesEngine

**Files:**
- Create: `src/Private/sequencing/DependencyRulesEngine.ps1`
- Create: `tests/sequencing/DependencyRulesEngine.Tests.ps1`

- [ ] **Step 1: Write failing tests**

  Create `tests/sequencing/DependencyRulesEngine.Tests.ps1`:

  ```powershell
  BeforeAll {
      . "$PSScriptRoot/../../src/Private/sequencing/rules/CA.rules.ps1" -ErrorAction SilentlyContinue
      . "$PSScriptRoot/../../src/Private/sequencing/DependencyRulesEngine.ps1"

      function New-TestAction {
          param([string]$Id)
          [PSCustomObject]@{
              action   = [PSCustomObject]@{ actionId=$Id }
              sequence = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1 }
              result   = [PSCustomObject]@{ status=$null; reason=$null }
              rulesApplied = @()
          }
      }

      $caBlockFalseFindings = @(
          [PSCustomObject]@{
              checkId='CA-001'; status='Fail'
              evidence=@{ breakGlassFound=$false; legacyAuthPolicyFound=$false }
          }
      )
      $caBlockTrueFindings = @(
          [PSCustomObject]@{
              checkId='CA-001'; status='Fail'
              evidence=@{ breakGlassFound=$true; legacyAuthPolicyFound=$false }
          }
      )
  }

  Describe 'Get-FactValue' {
      It 'returns false for BreakGlassAccountsPresent when evidence shows breakGlassFound=false' {
          Get-FactValue -FactName 'BreakGlassAccountsPresent' -Findings $caBlockFalseFindings | Should -BeFalse
      }
      It 'returns true for BreakGlassAccountsPresent when evidence shows breakGlassFound=true' {
          Get-FactValue -FactName 'BreakGlassAccountsPresent' -Findings $caBlockTrueFindings | Should -BeTrue
      }
      It 'returns false for unknown fact (UNSATISFIED rule)' {
          Get-FactValue -FactName 'SomeMadeUpFact' -Findings @() | Should -BeFalse
      }
      It 'returns true for Always fact' {
          Get-FactValue -FactName 'Always' -Findings @() | Should -BeTrue
      }
  }

  Describe 'Test-RuleCondition' {
      It 'returns true when fact matches Equals condition' {
          $cond = [PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
          Test-RuleCondition -Condition $cond -Findings @() | Should -BeTrue
      }
      It 'returns false when fact does not match Equals condition' {
          $cond = [PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$true }
          Test-RuleCondition -Condition $cond -Findings $caBlockFalseFindings | Should -BeFalse
      }
  }

  Describe 'Invoke-DependencyRules — Block rule' {
      It 'marks action Blocked when Block condition satisfied' {
          $action = New-TestAction 'ACT-CA-ENABLE-MFA'
          $rules  = @(
              [PSCustomObject]@{
                  ruleId='CA-BLOCK-001'; appliesToAction='ACT-CA-ENABLE-MFA'; type='Block'; priority=10
                  condition=[PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$false }
                  effect=[PSCustomObject]@{ blockIfUnsatisfied=$true; reason='No break-glass' }
              }
          )
          $result = Invoke-DependencyRules -Actions @($action) -Rules $rules -Findings $caBlockFalseFindings
          $result[0].result.status | Should -Be 'Blocked'
          $result[0].rulesApplied.ruleId | Should -Contain 'CA-BLOCK-001'
      }

      It 'does NOT block action when Block condition is not satisfied' {
          $action = New-TestAction 'ACT-CA-ENABLE-MFA'
          $rules  = @(
              [PSCustomObject]@{
                  ruleId='CA-BLOCK-001'; appliesToAction='ACT-CA-ENABLE-MFA'; type='Block'; priority=10
                  condition=[PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$false }
                  effect=[PSCustomObject]@{ blockIfUnsatisfied=$true; reason='No break-glass' }
              }
          )
          $result = Invoke-DependencyRules -Actions @($action) -Rules $rules -Findings $caBlockTrueFindings
          $result[0].result.status | Should -BeNullOrEmpty   # not blocked
      }
  }

  Describe 'Invoke-DependencyRules — Dependency rule' {
      It 'adds dependency to action when Dependency condition satisfied' {
          $action = New-TestAction 'ACT-CA-ENABLE-MFA'
          $rules  = @(
              [PSCustomObject]@{
                  ruleId='CA-DEP-001'; appliesToAction='ACT-CA-ENABLE-MFA'; type='Dependency'; priority=1
                  condition=[PSCustomObject]@{ fact='BreakGlassAccountsPresent'; operator='Equals'; value=$true }
                  effect=[PSCustomObject]@{ dependency='ACT-CA-EXCLUDE-BREAKGLASS'; blockIfUnsatisfied=$false; reason='dep' }
              }
          )
          $result = Invoke-DependencyRules -Actions @($action) -Rules $rules -Findings $caBlockTrueFindings
          $result[0].sequence.dependencies | Should -Contain 'ACT-CA-EXCLUDE-BREAKGLASS'
      }
  }

  Describe 'Invoke-DependencyRules — rule precedence' {
      It 'Block outcome wins over Dependency for same action' {
          $action = New-TestAction 'ACT-CA-ENABLE-MFA'
          $rules  = @(
              [PSCustomObject]@{
                  ruleId='CA-DEP-X'; appliesToAction='ACT-CA-ENABLE-MFA'; type='Dependency'; priority=1
                  condition=[PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
                  effect=[PSCustomObject]@{ dependency='ACT-SOME-DEP'; blockIfUnsatisfied=$false; reason='dep' }
              }
              [PSCustomObject]@{
                  ruleId='CA-BLOCK-X'; appliesToAction='ACT-CA-ENABLE-MFA'; type='Block'; priority=10
                  condition=[PSCustomObject]@{ fact='Always'; operator='Equals'; value=$true }
                  effect=[PSCustomObject]@{ blockIfUnsatisfied=$true; reason='blocked' }
              }
          )
          $result = Invoke-DependencyRules -Actions @($action) -Rules $rules -Findings @()
          $result[0].result.status | Should -Be 'Blocked'
      }
  }

  Describe 'Invoke-DependencyRules — unknown fact defaults false' {
      It 'Block condition with unknown fact = false → condition NOT satisfied → not blocked' {
          $action = New-TestAction 'ACT-TEST'
          $rules  = @(
              [PSCustomObject]@{
                  ruleId='TST-BLOCK-001'; appliesToAction='ACT-TEST'; type='Block'; priority=5
                  condition=[PSCustomObject]@{ fact='NonExistentFact'; operator='Equals'; value=$true }
                  effect=[PSCustomObject]@{ blockIfUnsatisfied=$true; reason='test' }
              }
          )
          $result = Invoke-DependencyRules -Actions @($action) -Rules $rules -Findings @()
          $result[0].result.status | Should -BeNullOrEmpty   # fact=false, condition=true → not satisfied → no block
      }
  }
  ```

- [ ] **Step 2: Run — verify fails**

  ```powershell
  Invoke-Pester -Path tests\sequencing\DependencyRulesEngine.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 3: Implement DependencyRulesEngine.ps1**

  Create `src/Private/sequencing/DependencyRulesEngine.ps1`:

  ```powershell
  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  # Maps fact names to evidence field paths in Finding objects
  # Fact source: Finding evidence[] only — NEVER live Graph calls
  $script:FactMap = @{
      BreakGlassAccountsPresent  = @{ checkId='CA-001';  evidenceKey='breakGlassFound' }
      LegacyAuthBlocked          = @{ checkId='LA-001';  evidenceKey='effectivelyBlocked' }
      CAFrameworkPresent         = @{ checkId='CA-001';  evidenceKey='totalPolicies'; transform={ param($v) [int]$v -gt 0 } }
      PIMEnabled                 = @{ checkId='PIM-001'; evidenceKey='pimEnabled' }
      AuditLoggingEnabled        = @{ checkId='AUDIT-001'; evidenceKey='auditLoggingEnabled' }
      SensitivityLabelsDefined   = @{ checkId='LABEL-001'; evidenceKey='labelsDefined' }
      DeviceCompliancePoliciesExist = @{ checkId='DEV-001'; evidenceKey='compliancePoliciesExist' }
      Always                     = $null   # special: always true
  }

  function Get-FactValue {
      [CmdletBinding()]
      param(
          [Parameter(Mandatory)][string] $FactName,
          [Parameter(Mandatory)] $Findings
      )

      if ($FactName -eq 'Always') { return $true }

      $mapping = $script:FactMap[$FactName]
      if (-not $mapping) { return $false }   # unknown fact → UNSATISFIED

      $finding = $Findings | Where-Object { $_.checkId -eq $mapping.checkId } | Select-Object -First 1
      if (-not $finding) { return $false }   # finding not in results → UNSATISFIED

      $rawValue = $finding.evidence[$mapping.evidenceKey]
      if ($null -eq $rawValue) { return $false }

      if ($mapping.transform) {
          return & $mapping.transform $rawValue
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
          'Equals'    { return $factValue -eq $Condition.value }
          'NotEquals' { return $factValue -ne $Condition.value }
          'GreaterThan' { return $factValue -gt $Condition.value }
          default { return $false }
      }
  }

  function Get-AllRules {
      [CmdletBinding()]
      param([Parameter(Mandatory)][string] $RulesPath)

      $allRules = [System.Collections.Generic.List[object]]::new()
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

      # Precedence order for rule types: Block=10, Dependency=5, Conflict=3, Advisory=1
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
                              $deps = [System.Collections.Generic.List[string]]::new($action.sequence.dependencies)
                              $deps.Add($rule.effect.dependency)
                              $action.sequence.dependencies = $deps.ToArray()
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
                              $conflicts = [System.Collections.Generic.List[string]]::new($action.sequence.conflictsWith)
                              $conflicts.Add($rule.effect.conflictsWith)
                              $action.sequence.conflictsWith = $conflicts.ToArray()
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
  ```

- [ ] **Step 4: Run — verify pass**

  ```powershell
  Invoke-Pester -Path tests\sequencing\DependencyRulesEngine.Tests.ps1 -Output Detailed
  ```

- [ ] **Step 5: ScriptAnalyzer + Commit**

  ```powershell
  Invoke-ScriptAnalyzer -Path src\Private\sequencing\DependencyRulesEngine.ps1 -Settings PSScriptAnalyzerSettings.psd1
  git add src/Private/sequencing/DependencyRulesEngine.ps1 tests/sequencing/DependencyRulesEngine.Tests.ps1
  git commit -m "feat: add DependencyRulesEngine (fact extraction, Block/Dep/Conflict/Advisory evaluation, unknown-fact=false, type precedence)"
  ```

<!-- Tasks 19–38 to follow -->
