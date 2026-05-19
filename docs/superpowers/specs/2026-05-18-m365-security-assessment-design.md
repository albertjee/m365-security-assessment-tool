# M365 Security Assessment Tool — Design Specification

**Date:** 2026-05-18  
**Status:** Approved — Ready for Implementation  
**Review series:** Rev0.80 → Rev0.90  
**Owner:** Albert Jee, Entreprise Architect

---

## 1. Glossary

| Term                  | Definition                                                                             |
| --------------------- | -------------------------------------------------------------------------------------- |
| Break-glass account   | Emergency admin account excluded from CA policies to prevent tenant lockout            |
| Eligible role (PIM)   | Privileged role requiring explicit activation before use — JIT model                   |
| Active role (PIM)     | Always-on privileged role assignment — standing access                                 |
| JIT                   | Just-in-time access: privilege granted on demand, time-limited, via PIM activation     |
| Report-only mode      | CA policy state that logs decisions but enforces nothing                               |
| SecureScoreVisibility | Whether a misconfiguration is visible to Secure Score: Passes / NotFlagged / Partial   |
| Tenant pinning        | Dual-signal validation that the token and org endpoint both match the intended tenant  |
| planHash              | SHA-256 of the SequencePlan — proves determinism and detects drift before execution    |
| rulesVersion          | Semver of the Dependency Rule Library used to build a plan — required for audit replay |
| WhatIf                | Simulation mode: plan is generated and logged as Blocked; no writes dispatched         |

---

## 2. Non-Goals

This tool does NOT:

- Simulate attacks or perform penetration testing
- Perform per-file or per-site content analysis
- Replace SIEM / Microsoft Sentinel architecture
- Execute multi-tenant portfolio orchestration (single tenant per run)
- Deliver remediation as a managed service
- Perform deep DLP logic review

---

## 3. Assumptions

- Microsoft Graph API is available and responsive during execution
- Required app permissions are granted and consented before the run
- The tenant is not under an active outage or maintenance window during assessment
- Break-glass accounts exist and are known before Premium remediation of CA policies
- The operator running Remediate mode has Global Admin or equivalent delegated rights
- PowerShell 7.2+ is installed on the execution host
- `ExchangeOnlineManagement` PS module is installed and available for checks requiring Exchange/Defender/SharePoint data not accessible via Microsoft Graph SDK v2.x
- Exchange Online PS session auth uses the same app-only certificate or delegated credential as the Graph session — no separate credential set required

---

## 4. Purpose and Context

Automate the Metis Security M365 independent control verification service. The tool performs deep configuration assessment of Microsoft 365 tenants across 13 control domains — detecting misconfigurations that **pass Secure Score** but leave tenants exposed. In Premium edition, it safely remediates confirmed findings using a dependency-aware sequencing engine.

The core insight from the service: Secure Score measures feature *presence*, not *enforcement*. A CA policy in report-only mode, a DLP policy in simulation mode, and DMARC at p=none all pass Secure Score. This tool detects the difference.

---

## 5. System Architecture

### 2.1 Three-Plane Model

```
Detection Plane       │  Intelligence Plane (IP moat)  │  Execution Plane
──────────────────────┼─────────────────────────────────┼──────────────────────
Checks → Findings     │  Rules → Sequencing → Plan      │  Remediator → GraphGateway
```

### 2.2 Component Responsibilities

| Component           | Role                                                                                 |
| ------------------- | ------------------------------------------------------------------------------------ |
| `GraphGateway`      | Auth, throttling, pagination, write enforcement boundary (Graph only)                |
| `ExchangeGateway`   | ExchangeOnlineManagement session, write enforcement boundary (Exchange/Defender/SPO) |
| `Auditor`           | Check discovery, execution, finding aggregation                                      |
| `SequencingEngine`  | DAG construction, dependency evaluation, topological planning                        |
| `Remediator`        | Sole writer — routes per `action.provider` to GraphGateway or ExchangeGateway        |
| `Reporter`          | Findings + audit trail → JSON + HTML                                                 |
| `models/`           | Canonical Finding and RemediationAction schemas                                      |
| `policy/`           | Safety gates — write allowed, permissions, environment, tenant pin                   |
| `checks/`           | 13 domain check modules — each implements standard contract                          |
| `sequencing/rules/` | Dependency Rule Library — encoded remediation intelligence                           |

### 2.3 Data Flow

```
Start-Assessment.ps1
  │
  ├─ Test-Environment (PS 7.2+, modules, cert/secret)
  ├─ Test-TenantPin (token tid + /organization → fail-closed on mismatch)
  ├─ Test-GraphPermissions (required roles for selected checks)
  │
  ├─ Auditor.Invoke-Check[] → Finding[]
  │     │
  │     └─ Each check: GraphGateway (Read only) → evaluate → New-Finding[]
  │
  ├─ [If Mode=Remediate AND Edition=Premium]
  │     SequencingEngine
  │       ├─ ActionGraphBuilder → DAG
  │       ├─ DependencyRulesEngine (facts from Findings + Env, NOT live Graph)
  │       ├─ Planner → topological sort → SequencePlan + planHash
  │       └─ Executor
  │             ├─ Drift guard: recompute planHash → fail if mismatch
  │             └─ foreach action: Test-WriteAllowed → ShouldProcess → Remediator
  │
  └─ Reporter → findings.json + report.html + run.manifest.json
                remediation.actions.jsonl (append-only)
                sequence-plan.json (Premium)
                state/before|after/<checkId>/<findingId>.json (Premium)
```

---

## 6. File Layout

```
m365-security-assessment-tool/
├── Start-Assessment.ps1
│     # Parameters:
│     #   -Mode [Assess|Remediate]
│     #   -AuthMethod [Certificate|Secret|Delegated]
│     #   -WhatIf -Confirm:$false -Force
│     #   -IncludeChecks <string[]>
│     #   -TenantId -AppId
├── m365-security-assessment-tool.psd1     # Manifest: version, PS 7.2+ min, explicit exports
├── m365-security-assessment-tool.psm1    # Root loader: dot-sources Public + Private
├── PSScriptAnalyzerSettings.psd1         # Exists — lint + security rules
├── README.md
├── CHANGELOG.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
│
├── src/
│   ├── Public/
│   │   └── Invoke-M365Assessment.ps1
│   │         # [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
│   │         # Exported cmdlet surface only — no business logic
│   │
│   └── Private/
│       ├── GraphGateway.ps1
│       │     # Auth modes: Certificate | Secret | Delegated
│       │     # Invoke-GraphRequest -Uri -Method -Body -OperationType [Read|Write]
│       │     #   Read  = GET only
│       │     #   Write = POST, PATCH, PUT, DELETE
│       │     # Default-deny ALL non-GET — throws terminating exception unless:
│       │     #   Caller=Remediator AND OperationType=Write AND Test-WriteAllowed passed
│       │     # Attaches x-ms-client-request-id per request
│       │     # Retry: exponential backoff on 429 + 5xx; logs retries + retryDelaysMs[]
│       │     # Auto-follows @odata.nextLink (pagination)
│       │     # MUST NOT be used for Exchange/Defender/SPO calls — use ExchangeGateway
│       │
│       ├── ExchangeGateway.ps1
│       │     # Wraps ExchangeOnlineManagement PS module
│       │     # Connect-ExchangeOnline using same cert or delegated credential as Graph session
│       │     # Invoke-ExchangeRequest -CmdletName -Parameters -OperationType [Read|Write]
│       │     #   Read  = Get-* cmdlets only
│       │     #   Write = Set-*, Enable-*, Disable-*, New-* cmdlets
│       │     # Default-deny ALL non-Get-* unless:
│       │     #   Caller=Remediator AND OperationType=Write AND Test-WriteAllowed passed
│       │     # Same fail-closed and write-gate invariants as GraphGateway
│       │     # Session lifecycle: Connect once per run; Disconnect MUST run in finally block
│       │     #   even on termination — prevents session leak across runs
│       │     # AuthMethod=Secret NOT supported by ExchangeOnlineManagement natively;
│       │     #   Secret + Exchange-backed check → check MUST return status=NotAssessed
│       │     # Used by: Check-DLP, Check-DefenderOffice365, Check-SharePointSharing,
│       │     #   Check-SmtpAuth (mailbox-level), Check-AuditLogging (audit config)
│       │     # Reference implementation: Sample_Baseline_ExchangeGateway.ps1
│       │
│       ├── Auditor.ps1
│       │     # Discovers checks/ via Get-ChildItem Check-*.ps1
│       │     # Runs Test-CheckContract per module before execution
│       │     # Calls Get-CheckMetadata + Invoke-Check per module
│       │     # Propagates RunId to all findings
│       │     # Per-check failure: status=NotAssessed + structured error {type,message,checkId}
│       │
│       ├── Remediator.ps1
│       │     # ONLY component permitted to call Write operations
│       │     # Accepts both GraphGateway and ExchangeGateway (nullable for Graph-only runs)
│       │     # Receives ordered SequencePlan from Executor
│       │     # Per action: Test-WriteAllowed → $PSCmdlet.ShouldProcess → before→WRITE→after
│       │     # Routes per action.provider:
│       │     #   'Graph'    → Invoke-GraphRequest via GraphGateway
│       │     #   'Exchange' → Invoke-ExchangeRequest via ExchangeGateway
│       │     # Lite: generates WhatIf plan only, never dispatches writes
│       │     # Premium: executes in topological order, no parallel writes (v1)
│       │     # Appends every attempt to remediation.actions.jsonl
│       │
│       ├── Reporter.ps1
│       │     # Consumes Finding[] + RemediationAction[] + SequencePlan + RunManifest
│       │     # All artifacts embed: version, git commit, RunId, masked TenantId
│       │     # HTML: executive summary (plain language) + technical findings by domain
│       │     # Findings sorted: Critical → High → Medium → Informational
│       │     # Each finding: severity badge + SecureScoreVisibility badge
│       │
│       ├── models/
│       │   ├── Finding.schema.ps1
│       │   │     # New-Finding constructor + validator
│       │   │     # Fields: id, runId, checkId, title, category,
│       │   │     #   severity (Critical|High|Medium|Informational),
│       │   │     #   riskScore (0-100), secureScoreVisibility (Passes|NotFlagged|Partial),
│       │   │     #   status (Pass|Fail|NotAssessed), evidence{},
│       │   │     #   graphEndpoint, timestampUtc, supportsRemediation
│       │   │
│       │   └── RemediationAction.schema.ps1
│       │         # New-RemediationAction constructor + validator
│       │         # Fields: schemaVersion, runContext{runId,sequence,timestampUtc},
│       │         #   tenant{tenantIdMasked,tenantMatch},
│       │         #   check{checkId,checkName,findingId},
│       │         #   action{actionId,operation,resourceType,resourceId,target},
│       │         #   sequence{phase,order,dependencies[],requires{},
│       │         #     conflictsWith[],priority,safetyLevel,category},
│       │         #   execution{whatIf,confirmed,confirmImpact,force,writeAllowed,
│       │         #     executionMode (WhatIf|Execute), gates{modeRemediate,delegatedAuth,
│       │         #     notWhatIf,policyCheckPassed}},
│       │         #   request{endpoint,method,bodyHash,headers{clientRequestId}},
│       │         #   rulesApplied[{ruleId,outcome}],
│       │         #   state{beforeRef,afterRef,diffSummary},
│       │         #   result{status,reason,httpStatusCode,retries,retryDelaysMs[],durationMs},
│       │         #   error{type,code,message,requestId,nodes[]}
│       │
│       ├── policy/
│       │   ├── Test-WriteAllowed.ps1
│       │   │     # All 4 gates must pass simultaneously:
│       │   │     #   Mode = Remediate
│       │   │     #   AuthMethod = Delegated
│       │   │     #   -WhatIf not set
│       │   │     #   Edition = Premium
│       │   │
│       │   ├── Test-GraphPermissions.ps1
│       │   │     # Validates required app roles / delegated scopes present
│       │   │     # for the selected check set
│       │   │
│       │   ├── Test-ExchangePermissions.ps1
│       │   │     # Validates required Exchange RBAC roles present
│       │   │     # for checks declaring dataSource = 'Exchange' or 'Both'
│       │   │     # Called by Auditor before running Exchange-backed checks
│       │   │     # Failure → check returns status=NotAssessed with structured error
│       │   │
│       │   ├── Test-Environment.ps1
│       │   │     # PS 7.2+, required modules present, cert/secret reachable
│       │   │
│       │   ├── Test-TenantPin.ps1
│       │   │     # Signal 1: extracts tid JWT claim from access token
│       │   │     # Signal 2: GET /organization → tenantId
│       │   │     # Both must match -TenantId → fail closed on ANY mismatch
│       │   │     # mismatchReason enum:
│       │   │     #   TokenTenantMismatch | OrganizationTenantMismatch |
│       │   │     #   AuthorityTenantMismatch | RequestedTenantMissing |
│       │   │     #   UnableToResolveTenant
│       │   │
│       │   └── Test-CheckContract.ps1
│       │         # Validates: Get-CheckMetadata present + schema complete
│       │         # Validates: Invoke-Check present
│       │         # Detects: direct write calls in check module → hard fail
│       │         # Detects: global variable usage → hard fail
│       │         # Checks MUST be side-effect free: no mutation, no global state,
│       │         # no execution-order dependency
│       │
│       ├── sequencing/
│       │   ├── ActionGraphBuilder.ps1
│       │   │     # Builds directed dependency graph (DAG)
│       │   │     # Nodes = RemediationAction candidates
│       │   │     # Edges = dependencies (A must precede B)
│       │   │     # Detects circular dependencies → structured terminating error:
│       │   │     #   { type: Sequencing, code: CircularDependency, nodes: [...] }
│       │   │
│       │   ├── DependencyRulesEngine.ps1
│       │   │     # Loads rules from rules/ library
│       │   │     # Applies rules per action: annotates dependencies, blocks, conflicts
│       │   │     # Fact sources: Finding evidence[] (primary), Test-Environment (secondary)
│       │   │     #   NOT live Graph calls during sequencing — keeps engine deterministic
│       │   │     # Unknown/missing fact → evaluate as false (UNSATISFIED)
│       │   │     #   → may trigger Block depending on rule type
│       │   │     # Rule precedence: Block → Dependency → Conflict → Advisory
│       │   │     # ConflictsWith resolution: higher priority wins;
│       │   │     #   equal priority → both blocked
│       │   │     # Logs rulesApplied[] per action
│       │   │
│       │   ├── Planner.ps1
│       │   │     # Topological sort on DAG → deterministic ordered plan
│       │   │     # Assigns phase + order to each action
│       │   │     # Execution phases:
│       │   │     #   Phase 1: Safety Prep (break-glass, exclusions)
│       │   │     #   Phase 2: Identity Controls (CA, MFA)
│       │   │     #   Phase 3: Privilege Controls (PIM)
│       │   │     #   Phase 4: Device/Data (Compliance, DLP)
│       │   │     #   Phase 5: Enforcement (blocking, tightening)
│       │   │     # Outputs SequencePlan: phases[], summary{total,blocked,highRisk}
│       │   │     # Computes planHash (sha256) — written to plan + manifest
│       │   │     # Embeds rulesVersion
│       │   │     # MUST be deterministic: same input → identical plan every run
│       │   │
│       │   ├── Executor.ps1   [Premium only]
│       │   │     # Drift guard: recompute planHash at start;
│       │   │     #   if != stored planHash → FAIL (PlanIntegrityViolation)
│       │   │     # Walks plan in topological order
│       │   │     # Per action: Test-WriteAllowed → ShouldProcess → Remediator
│       │   │     # Blocked actions: skip, log, continue
│       │   │     # Critical failure (halt run):
│       │   │     #   GraphGateway write failure | tenant pin mismatch |
│       │   │     #   dependency integrity violation
│       │   │     # Non-critical failure (block action, continue):
│       │   │     #   single action failure
│       │   │     # No parallel writes (v1)
│       │   │
│       │   └── rules/
│       │       ├── CA.rules.ps1         # CA-DEP-001, CA-BLOCK-001, CA-DEP-002, CA-CONFLICT-001
│       │       ├── PIM.rules.ps1        # PIM-DEP-001, PIM-BLOCK-001, PIM-DEP-002, PIM-DEP-003
│       │       ├── LegacyAuth.rules.ps1 # LA-DEP-001, LA-ADV-001
│       │       ├── DLP.rules.ps1        # DLP-DEP-001, DLP-DEP-002
│       │       └── CrossCheck.rules.ps1 # CC-001 (CA+PIM), CC-002 (Device+CA),
│       │                                # CC-003 (DLP+CA), CC-004 (lockout protection)
│       │
│       └── checks/
│             # Check contract (every module must implement):
│             #
│             # Get-CheckMetadata → @{
│             #   id, title, category, severity, riskScoreBaseline,
│             #   secureScoreVisibility, description,
│             #   requiredPermissions[], supportsRemediation,
│             #   edition[], assessAuthMethods[]
│             # }
│             #
│             # Invoke-Check -GraphGateway -Config → Finding[]
│             #   (side-effect free: no mutation, no global state, no order dependency)
│             #
│             # Invoke-Remediation -GraphGateway -Finding -PSCmdlet → RemediationAction[]
│             #   (optional; Remediator enforces edition + gate before calling)
│             #   (uses $PSCmdlet.ShouldProcess before every write)
│             #
│             ├── Check-ConditionalAccess.ps1   # CA-001 | Critical | riskScore≥90
│             │     # Evaluates: legacy auth block, MFA coverage (all users + admins),
│             │     #   admin protection, break-glass presence, device compliance
│             │     #   enforcement, location controls, risk-based policies (P2 signal),
│             │     #   policy state (disabled/report-only/sprawl)
│             │     # Remediation (Premium): deploy in report-only first, then enforce
│             │     #   after dependency gates pass
│             │
│             ├── Check-PIM.ps1                 # PIM-001 | Critical | riskScore≥90
│             │     # Evaluates: standing active roles, eligible/active ratio,
│             │     #   high-risk role exposure (GA/PRA/SA), missing JIT model,
│             │     #   MFA on activation, approval workflow, activation duration,
│             │     #   justification requirement, access reviews, audit visibility
│             │     # Remediation (Premium): convert active→eligible ONLY,
│             │     #   configure role settings; NO role removal
│             │
│             ├── Check-EmailAuthentication.ps1 # MAIL-001 | High
│             │     # Evaluates: SPF present + valid, DKIM enabled + signing,
│             │     #   DMARC present + p=quarantine|reject (not p=none),
│             │     #   anti-phishing policy (not default preset),
│             │     #   Safe Links + Safe Attachments enabled
│             │     # Note: DNS changes are external — Lite generates change package
│             │     # Remediation (Premium): enable DKIM where platform-supported,
│             │     #   generate DNS change package + verification workflow
│             │
│             ├── Check-DLP.ps1                 # DLP-001 | High
│             │     # Evaluates: policies present across workloads, simulation mode,
│             │     #   coverage gaps, sensitivity label dependency
│             │     # Remediation (Premium): deploy baseline policies in audit→notify→enforce
│             │
│             ├── Check-GuestAccess.ps1         # GUEST-001 | High
│             │     # Evaluates: external collaboration settings, stale guests (12+ months),
│             │     #   no expiry policy, access to sensitive content
│             │     # Remediation (Premium): tighten collab settings, lifecycle controls,
│             │     #   blast-radius check before applying
│             │
│             ├── Check-DeviceCompliance.ps1    # DEV-001 | High
│             │     # Evaluates: compliance policy existence, coverage gaps
│             │     #   (enrolled but unevaluated), CA dependency alignment
│             │     # Remediation (Premium): baseline compliance settings,
│             │     #   coordinated with CA sequencing (Phase 4 after Phase 2)
│             │
│             ├── Check-LegacyAuthentication.ps1 # LA-001 | Critical
│             │     # Evaluates: legacy auth protocols active at tenant level,
│             │     #   clients/protocols still enabled (enables MFA bypass)
│             │     # Remediation (Premium): stage→validate→enforce pattern
│             │
│             ├── Check-SmtpAuth.ps1            # SMTP-001 | High
│             │     # Evaluates: SMTP AUTH enabled at tenant/mailbox level
│             │     # Remediation (Premium): default-deny + exception list,
│             │     #   per-object before/after state capture
│             │
│             ├── Check-SharePointSharing.ps1   # SP-001 | High
│             │     # Evaluates: anonymous link settings, expiry policy,
│             │     #   site-level overrides more permissive than tenant policy
│             │     # Remediation (Premium): sharing baseline, link type/expiry alignment
│             │
│             ├── Check-AuditLogging.ps1        # AUDIT-001 | Medium
│             │     # Evaluates: audit logging enabled, retention period vs licence tier
│             │     # Remediation (Premium): enable + align config + verification snapshot
│             │
│             ├── Check-SensitivityLabels.ps1   # LABEL-001 | High
│             │     # Evaluates: labels defined, labels published to users,
│             │     #   default labeling behaviour, DLP label dependency
│             │     # Remediation (Premium): publish curated label set (staged rollout)
│             │
│             ├── Check-DefenderOffice365.ps1   # DEF-001 | High
│             │     # Evaluates: anti-phishing preset (default vs standard/strict),
│             │     #   Safe Links + Safe Attachments policies
│             │     # Remediation (Premium): align to standard/strict preset (staged)
│             │
│             └── Check-CloudAppSecurity.ps1    # CASB-001 | Medium
│                   # Evaluates: CASB licensed + connected, session/access policies,
│                   #   governance absent vs discovery-only
│                   # Remediation (Premium): baseline alert policies, CA/MCAS alignment
│
├── config/
│   ├── assessment.config.psd1
│   │     # Edition [Lite|Premium], OutputPath, EnabledChecks,
│   │     # AuthMethod, ReportOptions
│   └── assessment.secrets.psd1   # GITIGNORED
│         # TenantId, AppId, CertThumbprint, ClientSecret
│
├── templates/
│   └── report.html.ps1           # Self-contained here-string, no external deps
│
├── tests/
│   ├── GraphGateway.Tests.ps1
│   ├── Auditor.Tests.ps1
│   ├── Remediator.Tests.ps1
│   ├── Reporter.Tests.ps1
│   ├── CheckContract.Tests.ps1   # All Check-* pass Test-CheckContract
│   └── sequencing/
│       ├── ActionGraphBuilder.Tests.ps1
│       ├── DependencyRulesEngine.Tests.ps1
│       ├── Planner.Tests.ps1
│       ├── SequencingIntegration.Tests.ps1
│       └── rules/
│           ├── CA.rules.Tests.ps1          # positive + negative + edge per rule
│           ├── PIM.rules.Tests.ps1
│           ├── LegacyAuth.rules.Tests.ps1
│           ├── DLP.rules.Tests.ps1
│           └── CrossCheck.rules.Tests.ps1
│
├── .github/
│   └── workflows/
│       └── ci.yml
│             # Invoke-ScriptAnalyzer -EnableExit (fail on Error + Warning)
│             # Invoke-Pester
│             # Test-ModuleManifest
│
├── Output/                       # GITIGNORED
│   └── <runId-timestamp>/
│       ├── run.manifest.json
│       ├── findings.json
│       ├── report.html
│       ├── remediation.actions.jsonl
│       ├── sequence-plan.json    # Premium
│       └── state/               # Premium
│           ├── before/<checkId>/<findingId>.json
│           └── after/<checkId>/<findingId>.json
│
├── docs/
│   ├── graph-permissions.md
│   ├── operational-mode-guarantee.md
│   └── superpowers/specs/
│       └── 2026-05-18-m365-security-assessment-design.md   # this file
│
└── .gitignore   # Output/, assessment.secrets.psd1
```

---

## 7. Edition Model

| Capability                  | Lite                            | Premium                            |
| --------------------------- | ------------------------------- | ---------------------------------- |
| Auth (Assess)               | Certificate or Secret           | Certificate or Secret              |
| Auth (Remediate)            | N/A                             | Delegated interactive only         |
| All 13 checks               | Yes                             | Yes                                |
| WhatIf action plan          | Yes (plan generated, no writes) | Yes                                |
| Write execution             | Never                           | Yes — all 4 gates must pass        |
| SequencingEngine            | Not initialized                 | Fully active                       |
| Before/after state capture  | No                              | Yes                                |
| `remediation.actions.jsonl` | WhatIf/Blocked entries only     | Full execution log                 |
| `sequence-plan.json`        | No                              | Yes (with planHash + rulesVersion) |
| `state/` snapshots          | No                              | Yes                                |

---

## 8. Safety Model

### 5.1 Fail-Closed System Invariant

Any violation of the following results in immediate termination, no partial write execution, and run status = `Failed` or `Partial` (never silent success):

- Tenant pin mismatch (either signal)
- Write gate failure (any of 4 conditions unmet)
- Auth model violation
- Graph permission validation failure
- Circular dependency in action graph
- Plan integrity violation (planHash drift)

### 5.2 Write Gate — Test-WriteAllowed (all 4 required simultaneously)

```
Mode        = Remediate
AuthMethod  = Delegated
-WhatIf     = not set
Edition     = Premium
```

### 5.3 GraphGateway Enforcement

- `OperationType = Read` → GET only
- `OperationType = Write` → POST, PATCH, PUT, DELETE
- Any write call from outside Remediator → terminating exception immediately
- Any non-GET from a check module → terminating exception immediately

### 5.4 Tenant Pinning

Two independent signals must both match `-TenantId`:

1. `tid` claim from JWT access token
2. tenantId from `GET /organization`

`mismatchReason` enum: `TokenTenantMismatch | OrganizationTenantMismatch | AuthorityTenantMismatch | RequestedTenantMissing | UnableToResolveTenant`

---

## 9. Auth Model

| Mode      | AuthMethod  | Type                                    | Writes              |
| --------- | ----------- | --------------------------------------- | ------------------- |
| Assess    | Certificate | App-only SP + cert                      | No                  |
| Assess    | Secret      | App-only SP + client secret             | No                  |
| Remediate | Delegated   | Interactive browser (MFA-capable admin) | Yes, if gate passes |

Initial dev/test uses both Certificate and Secret against a dev tenant. Production assess uses Certificate. Remediate always requires Delegated.

**Exchange auth constraint:** `ExchangeOnlineManagement` does not accept a client secret natively. When `AuthMethod=Secret`, any check with `dataSource=Exchange|Both` MUST return `status=NotAssessed` with reason `ExchangeAuthNotSupported`. Only `Certificate` and `Delegated` are valid for Exchange-backed checks.

---

## 10. Check Contract

Every `Check-*.ps1` must implement:

```powershell
function Get-CheckMetadata {
    @{
        id                    = 'XX-001'
        title                 = '...'
        category              = '...'
        severity              = 'Critical|High|Medium|Informational'
        riskScoreBaseline     = <int 0-100>
        secureScoreVisibility = 'Passes|NotFlagged|Partial'
        description           = '...'
        requiredPermissions   = @('...')        # Graph permissions
        requiredExchangeRoles = @('...')        # Exchange RBAC roles, if ExchangeGateway used
        dataSource            = 'Graph|Exchange|Both'   # declares which gateway(s) required
        supportsRemediation   = $true|$false
        edition               = @('Lite','Premium')
        assessAuthMethods     = @('Certificate','Secret','Delegated')
    }
}

function Invoke-Check { param($GraphGateway, $Config) }
# Returns: Finding[] via New-Finding
# MUST be side-effect free — no mutation, no global vars, no order dependency

function Invoke-Remediation { param($GraphGateway, $Finding, $PSCmdlet) }
# Optional. Only called by Remediator after gate + ShouldProcess.
# Returns: RemediationAction[] via New-RemediationAction
# Uses $PSCmdlet.ShouldProcess before every write (ConfirmImpact tuned per action)
```

Check modules that fail `Test-CheckContract` are not loaded — the run continues with that check marked `NotAssessed`.

---

## 11. Example End-to-End Flow

**Scenario:** Tenant has no break-glass accounts and no MFA CA policy.

```
1. ASSESS
   Check-ConditionalAccess.Invoke-Check runs (Read only, app-only auth)
     → FIND-CA-BREAKGLASS-001  | Critical | riskScore=92 | status=Fail
     → FIND-CA-MFA-001         | Critical | riskScore=90 | status=Fail

2. SEQUENCING (Premium, Mode=Remediate)
   ActionGraphBuilder: 2 candidate actions
     ACT-CA-EXCLUDE-BREAKGLASS
     ACT-CA-ENABLE-MFA

   DependencyRulesEngine applies:
     CA-DEP-001: ACT-CA-ENABLE-MFA depends on ACT-CA-EXCLUDE-BREAKGLASS
     CA-BLOCK-001: ACT-CA-ENABLE-MFA BLOCKED if BreakGlassAccountsPresent=false
       fact source: FIND-CA-BREAKGLASS-001.evidence.breakGlassFound = false
       → ACT-CA-ENABLE-MFA.status = Blocked / reason = "CA-BLOCK-001: BreakGlassAccountsPresent=false"

   Planner (topological sort):
     Phase 1: ACT-CA-EXCLUDE-BREAKGLASS  (order=1)
     Phase 2: ACT-CA-ENABLE-MFA          (order=1, status=Blocked)
   planHash = sha256:abc123...
   rulesVersion = 1.0.0

3. EXECUTION (Delegated auth, -WhatIf:$false)
   Executor drift guard: recompute planHash → matches → proceed

   Phase 1 / ACT-CA-EXCLUDE-BREAKGLASS:
     Test-WriteAllowed → PASS (all 4 gates)
     $PSCmdlet.ShouldProcess("CA", "Create break-glass exclusion group") → confirmed
     GET /groups → capture before state
     POST /groups → create exclusion group → HTTP 201
     GET /groups → capture after state
     JSONL entry: status=Success, executionMode=Execute, retries=0

   Phase 2 / ACT-CA-ENABLE-MFA:
     status=Blocked (CA-BLOCK-001) → skip, log JSONL entry: status=Blocked
     NOTE: remains blocked this run — operator must rerun after verifying break-glass

4. REPORT
   findings.json  → 2 findings (1 Fail, 1 Fail)
   report.html    → Executive: "2 critical identity gaps found"
                    Technical: CA domain, per-finding evidence + remediation guidance
   run.manifest.json → status=Partial (1 executed, 1 blocked)
   remediation.actions.jsonl → 2 entries (Success + Blocked)
```

---

## 12. Data Schemas

### 8.1 Finding (key fields)

```json
{
  "id": "FIND-CA-LEGACYAUTH-001",
  "runId": "2026-05-18T19:49:52Z-7f3c2b9a",
  "checkId": "CA-001",
  "title": "Legacy Authentication Not Blocked",
  "category": "Identity Security",
  "severity": "Critical",
  "riskScore": 95,
  "secureScoreVisibility": "Passes",
  "status": "Fail",
  "evidence": { "legacyAuthPolicyFound": false },
  "graphEndpoint": "/identity/conditionalAccess/policies",
  "timestampUtc": "2026-05-18T19:55:00Z",
  "supportsRemediation": true
}
```

**Risk score tiers (stable — same input must produce same score):**

| Severity      | riskScore range |
| ------------- | --------------- |
| Critical      | ≥ 90            |
| High          | 70 – 89         |
| Medium        | 40 – 69         |
| Informational | < 40            |

**Status enum:** `Pass | Fail | NotAssessed`

### 8.2 RemediationAction (key fields)

```json
{
  "schemaVersion": "1.0",
  "runContext": { "runId": "...", "sequence": 12, "timestampUtc": "..." },
  "tenant": { "tenantIdMasked": "aaaa-...-eeee", "tenantMatch": true },
  "check": { "checkId": "CA-001", "checkName": "Check-ConditionalAccess", "findingId": "FIND-CA-LEGACYAUTH-001" },
  "action": { "actionId": "ACT-CA-BLOCK-LEGACYAUTH", "operation": "POST", "resourceType": "ConditionalAccessPolicy", "resourceId": null, "target": "Block legacy authentication", "provider": "Graph" },
  "sequence": { "phase": 2, "order": 3, "dependencies": ["ACT-CA-EXCLUDE-BREAKGLASS"], "conflictsWith": [], "priority": 1 },
  "execution": {
    "whatIf": false, "confirmed": true, "confirmImpact": "High", "force": false,
    "writeAllowed": true, "executionMode": "Execute",
    "gates": { "modeRemediate": true, "delegatedAuth": true, "notWhatIf": true, "policyCheckPassed": true }
  },
  "request": {
    "endpoint": "/identity/conditionalAccess/policies", "method": "POST", "bodyHash": "sha256:...", "headers": { "clientRequestId": "req-..." },
    "cmdletName": null, "parameters": null, "writeCmdletName": null, "writeParameters": null
  },
  // For Graph actions: endpoint + method + bodyHash used. cmdlet fields = null.
  // For Exchange actions: cmdletName + parameters (read) + writeCmdletName + writeParameters (write) used. endpoint/method/bodyHash = null.
  "rulesApplied": [{ "ruleId": "CA-DEP-002", "outcome": "DependencyAdded" }],
  "state": {
    "beforeRef": "state://before/CA-001/FIND-CA-LEGACYAUTH-001.json",
    "afterRef": "state://after/CA-001/FIND-CA-LEGACYAUTH-001.json",
    "diffSummary": "policy created: BlockLegacyAuth"
  },
  "result": { "status": "Success", "reason": null, "httpStatusCode": 201, "retries": 0, "retryDelaysMs": [], "durationMs": 340 },
  "error": null
}
```

**RemediationAction status enum:** `Success | Blocked | Failed | Skipped`

### 8.3 run.manifest.json (key fields)

```json
{
  "schemaVersion": "1.0",
  "tool": { "name": "m365-security-assessment-tool", "moduleVersion": "...", "git": { "commit": "...", "branch": "...", "isDirty": false } },
  "run": { "runId": "...", "startedAtUtc": "...", "endedAtUtc": "...", "mode": "Remediate", "whatIf": false, "enabledChecks": [...] },
  "tenantPinning": { "requestedTenantIdMasked": "...", "resolvedTenantIdFromToken": "...", "resolvedTenantIdFromOrganization": "...", "match": true, "failClosedOnMismatch": true },
  "auth": { "authMethod": "Delegated", "authType": "Delegated", "appIdMasked": "...", "delegated": { "accountUpn": "...", "mfaCapable": true }, "runtimeGrants": { "scopes": [...] } },
  "environment": { "powerShell": { "version": "7.4.0", "edition": "Core" }, "os": { "platform": "Windows" } },
  "execution": {
    "status": "Success",
    "checks": { "discovered": 13, "attempted": 13, "succeeded": 13, "failed": 0, "skipped": 0 },
    "findings": { "total": 27, "critical": 3, "high": 9, "medium": 10, "informational": 5 },
    "remediation": { "plannedActions": 14, "executedActions": 11, "blockedActions": 3 }
  },
  "sequencing": { "planHash": "sha256:...", "rulesVersion": "1.0.0", "phases": 5, "blockedActions": 3, "executedActions": 11 },
  "artifacts": [
    { "name": "findings.json", "sha256": "..." },
    { "name": "report.html", "sha256": "..." },
    { "name": "remediation.actions.jsonl", "sha256": "..." }
  ]
}
```

**Run status enum:** `Success | Partial | Failed`

**Partial** = some checks failed OR some actions failed OR some checks skipped due to dependency failure.

---

## 13. Dependency Rule Library

### 9.1 Rule Schema

```json
{
  "ruleId": "CA-DEP-001",
  "appliesToAction": "ACT-CA-ENABLE-MFA",
  "type": "Dependency | Block | Conflict | Advisory",
  "condition": { "fact": "BreakGlassAccountsPresent", "operator": "Equals", "value": true },
  "effect": { "dependency": "ACT-CA-EXCLUDE-BREAKGLASS", "blockIfUnsatisfied": true, "reason": "Break-glass accounts must be excluded before enabling MFA policy" },
  "priority": 1,
  "category": "Identity",
  "version": "1.0.0"
}
```

**Fact sources:** Finding `evidence[]` (primary) or `Test-Environment` output (secondary). Rules engine MUST NOT make live Graph calls during sequencing.

**Unknown fact handling:** undefined or missing fact → evaluate as `false` (UNSATISFIED) → may trigger Block.

**Rule precedence:** Block → Dependency → Conflict → Advisory

**ConflictsWith resolution:** higher `priority` wins. Equal priority → both blocked.

### 9.2 v1 Rule Sets

**CA.rules.ps1**

- `CA-DEP-001`: ACT-CA-ENABLE-MFA depends on ACT-CA-EXCLUDE-BREAKGLASS
- `CA-BLOCK-001`: Block MFA creation if BreakGlassAccountsPresent = false
- `CA-DEP-002`: ACT-CA-BLOCK-LEGACYAUTH must precede ACT-CA-ENFORCE-MFA
- `CA-CONFLICT-001`: ACT-CA-BLOCK-ALL conflicts with ACT-CA-REQUIRE-MFA

**PIM.rules.ps1**

- `PIM-DEP-001`: ACT-PIM-CONVERT-ACTIVE-TO-ELIGIBLE depends on PIMEnabled = true
- `PIM-BLOCK-001`: Block all PIM remediation if PIMEnabled = false
- `PIM-DEP-002`: ACT-PIM-CONVERT-ACTIVE must precede ACT-PIM-CONFIGURE-ROLE-SETTINGS
- `PIM-DEP-003`: Tier0 roles require ApprovalWorkflowConfigured = true

**LegacyAuth.rules.ps1**

- `LA-DEP-001`: ACT-LA-BLOCK-PROTOCOLS depends on CAFrameworkPresent = true
- `LA-ADV-001`: Advisory — operator SHOULD validate sign-in logs before blocking (non-blocking)

**DLP.rules.ps1**

- `DLP-DEP-001`: ACT-DLP-ENABLE-POLICY depends on AuditLoggingEnabled = true
- `DLP-DEP-002`: ACT-DLP-ENABLE depends on SensitivityLabelsDefined = true

**CrossCheck.rules.ps1** (highest-value IP)

- `CC-001`: ACT-CA-ENFORCE-MFA requires PIM-HighRiskRolesSecured = true
- `CC-002`: ACT-CA-REQUIRE-COMPLIANT-DEVICE depends on DeviceCompliancePoliciesExist = true
- `CC-003`: ACT-DLP-ENFORCE MUST follow ACT-CA-IDENTITY-BASELINE (Phase 4 after Phase 2)
- `CC-004`: ACT-CA-BLOCK-ALL-EXTERNAL blocked if EmergencyAccessTested = false

---

## 14. Sequencing Engine

### 10.1 Design Principles

1. **Fail-safe**: no action executes unless dependencies satisfied
2. **Deterministic**: same findings → identical plan every run
3. **Dependency-first**: ordering governed by explicit prerequisites, not script order
4. **Plan → Evaluate → Execute**: strict phase separation
5. **Observable**: every block/allow decision logged with reason

### 10.2 Execution Phases

| Phase | Category           | Examples                               |
| ----- | ------------------ | -------------------------------------- |
| 1     | Safety Prep        | Break-glass accounts, exclusion groups |
| 2     | Identity Controls  | CA policies, MFA enforcement           |
| 3     | Privilege Controls | PIM role conversion, role settings     |
| 4     | Device/Data        | Compliance policies, DLP, labels       |
| 5     | Enforcement        | Legacy auth block, SMTP auth disable   |

### 10.3 Engine Disable Condition

```
If Mode != Remediate OR Edition != Premium:
    SequencingEngine is NOT initialized
    Planner runs in simulation-only mode (WhatIf plan only)
```

### 10.4 Plan Integrity (Drift Guard)

At execution start, Executor recomputes `planHash` from current plan state. If it does not match the stored `planHash` → `FAIL` with `PlanIntegrityViolation`. No execution proceeds.

### 10.5 Critical vs Non-Critical Failures

| Type         | Examples                                                                        | Behavior                         |
| ------------ | ------------------------------------------------------------------------------- | -------------------------------- |
| Critical     | GraphGateway write failure, tenant pin mismatch, dependency integrity violation | Halt entire run immediately      |
| Non-critical | Single action failure                                                           | Block that action, log, continue |

### 10.6 Sequencing Test Requirements

| Layer        | Focus                                                              |
| ------------ | ------------------------------------------------------------------ |
| Unit         | Rule evaluation, gate validation, state transitions                |
| Graph        | DAG construction, cycle detection, topological sort correctness    |
| Integration  | Findings→Plan pipeline, cross-check interactions                   |
| Execution    | Write gating, fail-closed behavior, mixed blocked/executable plans |
| Edge/Failure | Circular deps, missing prerequisites, conflicting actions          |
| Determinism  | Same input → identical plan, stable phase grouping                 |
| Performance  | 100–1000+ actions, dense dependency graphs                         |

**Minimum acceptance criteria:**

- No action executes without dependency satisfaction
- All plans honor dependency order
- All decisions (execute/block) explainable and logged
- System safe under all failure conditions
- Plans deterministic and reproducible
- planHash validates correctly at execution start

---

## 15. HTML Report Structure

**Section 1 — Executive Summary** (plain language, partner/director audience)

- Overall posture verdict
- Critical finding count and top risks
- Remediation priority summary

**Section 2 — Technical Findings** (IT team audience, grouped by domain)

- Per finding: severity badge, SecureScoreVisibility badge, title, evidence, remediation guidance
- Sorted: Critical → High → Medium → Informational
- Each finding cross-references check ID and Graph endpoint used

**Report metadata header (all artifacts):** version, git commit, RunId, masked TenantId, run timestamp, mode, auth method.

---

## 16. Operational Mode Guarantee

| Mode               | Auth                             | Writes                     | Scope                                              |
| ------------------ | -------------------------------- | -------------------------- | -------------------------------------------------- |
| Assess             | Certificate or Secret (app-only) | Never                      | Read-only Graph calls                              |
| Assess + WhatIf    | Same                             | Never                      | Generates action plan, no execution                |
| Remediate + WhatIf | Delegated                        | Never                      | Full plan generated, all actions logged as Blocked |
| Remediate          | Delegated                        | Only when all 4 gates pass | Gated, audited, interactive                        |

Fail-closed on tenant mismatch: no operation proceeds if either tenant signal mismatches `-TenantId`, regardless of mode.

---

## 17. Graph API Verification Requirement

For every `Invoke-GraphRequest` call in every check and remediation module, the following MUST be verified before implementation is considered complete:

1. **Permission name** — MUST exist in the Microsoft Graph permissions reference and be the least-privilege permission sufficient for the call
2. **Graph endpoint URI** — MUST be verified against the current Microsoft Graph v1.0 or beta API reference; beta endpoints MUST be flagged explicitly
3. **PowerShell SDK cmdlet** — MUST be verified to exist in Microsoft.Graph PowerShell SDK v2.x (not v1.x)
4. **Sub-module** — MUST confirm the cmdlet is exported from the specific `Microsoft.Graph.*` sub-module declared in prerequisites; the sub-module MUST be listed in `assessment.config.psd1` as a required dependency

Where the PowerShell SDK cmdlet does not exist or is insufficient, the implementation MUST use `Invoke-GraphRequest` (REST) directly and document the reason.

### 17.1 Verification Table (MUST be completed before each check is merged)

| Check                      | Call Purpose             | Permission                               | Endpoint                                                 | SDK Cmdlet                                             | Sub-Module                                     | REST fallback?           |
| -------------------------- | ------------------------ | ---------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------ | ---------------------------------------------- | ------------------------ |
| Check-ConditionalAccess    | List CA policies         | `Policy.Read.All`                        | `GET /identity/conditionalAccess/policies`               | `Get-MgIdentityConditionalAccessPolicy`                | `Microsoft.Graph.Identity.SignIns`             | No                       |
| Check-ConditionalAccess    | List named locations     | `Policy.Read.All`                        | `GET /identity/conditionalAccess/namedLocations`         | `Get-MgIdentityConditionalAccessNamedLocation`         | `Microsoft.Graph.Identity.SignIns`             | No                       |
| Check-PIM                  | List role assignments    | `RoleManagement.Read.Directory`          | `GET /roleManagement/directory/roleAssignments`          | `Get-MgRoleManagementDirectoryRoleAssignment`          | `Microsoft.Graph.Identity.Governance`          | No                       |
| Check-PIM                  | List eligible schedules  | `RoleManagement.Read.Directory`          | `GET /roleManagement/directory/roleEligibilitySchedules` | `Get-MgRoleManagementDirectoryRoleEligibilitySchedule` | `Microsoft.Graph.Identity.Governance`          | No                       |
| Check-PIM                  | List role mgmt policies  | `RoleManagement.Read.Directory`          | `GET /roleManagement/directory/roleManagementPolicies`   | `Get-MgPolicyRoleManagementPolicy`                     | `Microsoft.Graph.Identity.Governance`          | No                       |
| Check-EmailAuthentication  | List accepted domains    | `Organization.Read.All`                  | `GET /domains`                                           | `Get-MgDomain`                                         | `Microsoft.Graph.Identity.DirectoryManagement` | No                       |
| Check-LegacyAuthentication | Get auth methods policy  | `Policy.Read.All`                        | `GET /policies/authenticationMethodsPolicy`              | `Get-MgPolicyAuthenticationMethodPolicy`               | `Microsoft.Graph.Identity.SignIns`             | No                       |
| Check-SmtpAuth             | Get org SMTP settings    | `Organization.Read.All`                  | `GET /organization`                                      | `Get-MgOrganization`                                   | `Microsoft.Graph.Identity.DirectoryManagement` | No                       |
| Check-DLP                  | List compliance policies | `InformationProtectionPolicy.Read.All`   | Exchange/Compliance endpoint                             | N/A — Exchange PS required                             | N/A                                            | Yes — Exchange Online PS |
| Check-AuditLogging         | Get audit log settings   | `AuditLog.Read.All`                      | `GET /security/auditLog`                                 | `Get-MgAuditLogSignIn` (proxy)                         | `Microsoft.Graph.Reports`                      | Verify                   |
| Check-SharePointSharing    | Get SP tenant settings   | `Sites.Read.All`                         | SharePoint Admin endpoint                                | N/A — SPO PS required                                  | N/A                                            | Yes — SPO PS             |
| Check-SensitivityLabels    | List labels              | `InformationProtectionPolicy.Read.All`   | `GET /informationProtection/policy/labels`               | `Get-MgInformationProtectionPolicyLabel`               | `Microsoft.Graph.Security`                     | No                       |
| Check-DefenderOffice365    | Get anti-phish policies  | `SecurityEvents.Read.All`                | Exchange/Defender endpoint                               | N/A — Exchange PS required                             | N/A                                            | Yes — Exchange Online PS |
| Check-GuestAccess          | Get auth policy          | `Policy.Read.All`                        | `GET /policies/authorizationPolicy`                      | `Get-MgPolicyAuthorizationPolicy`                      | `Microsoft.Graph.Identity.SignIns`             | No                       |
| Check-DeviceCompliance     | List compliance policies | `DeviceManagementConfiguration.Read.All` | `GET /deviceManagement/deviceCompliancePolicies`         | `Get-MgDeviceManagementDeviceCompliancePolicy`         | `Microsoft.Graph.DeviceManagement`             | No                       |
| Check-CloudAppSecurity     | Get MCAS config          | `CloudApp.Read.All`                      | `GET /security/cloudAppSecurityProfiles`                 | Verify in SDK v2.x                                     | `Microsoft.Graph.Security`                     | Verify                   |

> **Note:** Rows marked "Yes — Exchange Online PS" MUST use `ExchangeGateway.ps1` via `Invoke-ExchangeRequest`, NOT `GraphGateway`. These checks MUST declare `dataSource = 'Exchange'` or `'Both'` in `Get-CheckMetadata` and list required Exchange RBAC roles in `requiredExchangeRoles`. `Test-Environment` MUST verify `ExchangeOnlineManagement` module is installed before these checks run. `ExchangeGateway` enforces the same write-gate invariant as `GraphGateway` — no Exchange write cmdlets are permitted outside `Remediator` + `Test-WriteAllowed`.

> **Note:** All SDK cmdlet names and sub-modules in this table MUST be re-verified against the live `Microsoft.Graph` v2.x module at implementation time. This table is a starting reference, not a guarantee. Use `Get-Command -Module Microsoft.Graph.*` to confirm.

---

## 18. v1 Scope Discipline

Rev0.85 recommendation: build CA, PIM, and LegacyAuth checks first to validate the full detection → sequencing → remediation → reporting pipeline end-to-end before adding remaining 10 checks.

**Not in scope for v1:**

- Remediation delivery to clients (separate engagement)
- Attack simulation
- Per-file or per-site content audits
- Deep DLP logic review
- Microsoft Sentinel architecture assessment
- Parallel write execution (v1 is sequential)
- Multi-tenant portfolio runs (single tenant per invocation)
