# M365 Security Assessment Tool

PowerShell-based security assessment and remediation tool for Microsoft 365 tenants.

## Tech Stack

- PowerShell 7.2+
- Pester (unit/integration tests)
- Microsoft.Graph SDK v2 (app-only and delegated)
- ExchangeOnlineManagement (Exchange/Defender checks)

## Architecture

3-plane model:

```
Detection (checks/)  →  Intelligence (sequencing/)  →  Execution (remediator)
```

- **Detection**: `src/Private/checks/Check-*.ps1` — read-only, side-effect free, returns findings
- **Intelligence**: `src/Private/sequencing/` — dependency rules, DAG builder, planner, executor
- **Execution**: `src/Private/Remediator.ps1` — applies changes, gated by write policy

## Key Safety Rules

1. **Fail-closed**: any ambiguity, mismatch, or missing data → deny, not allow
2. **Write gate**: all 4 conditions must be true simultaneously:
   - `Mode = Remediate`
   - `AuthMethod = Delegated`
   - `WhatIf = $false`
   - `Edition = Premium`
3. **Tenant pinning**: `Test-TenantPin` runs before any audit or execution; mismatch = immediate stop
4. **Checks are read-only**: no mutation, no global state, no order dependency
5. **Secret auth + Exchange**: unsupported — checks return `NotAssessed` with `ExchangeAuthNotSupported`
6. **No role removal**: PIM remediation converts active → eligible only; never removes roles

## Auth Methods

| Method | Use Case | Notes |
|--------|----------|-------|
| `Certificate` | App-only, cert-based | Preferred for CI/CD |
| `Secret` | App-only, client secret | No Exchange support |
| `Delegated` | Interactive/user context | Required for Remediate mode |

## Dev Tenant

- **TenantId**: `3177c971-05c9-4b7b-93a1-0edf6fd7237d`
- **App Registration**: `m365-security-assessment-tool-dev`
- **ClientId**: `71dfad0e-2667-4318-9682-9c35683a9500`
- **Credentials**: stored in `config/assessment.secrets.psd1` (gitignored — never commit)

Azure CLI login:
```
az login --tenant 3177c971-05c9-4b7b-93a1-0edf6fd7237d --use-device-code --allow-no-subscriptions
```

## Testing

Run all tests (293 passing):
```powershell
pwsh -NonInteractive -Command "Invoke-Pester -Path tests -Output Detailed"
```

Live run against dev tenant:
```powershell
pwsh -NonInteractive -File Test-LiveRun.ps1
```

`Test-LiveRun.ps1` is gitignored. Runs `Assess` mode with `WhatIf=$true` using Secret auth.

## Development Workflow

1. External AI review of changes
2. Phase 1B: Pester suite must pass (>= current count, no regressions)
3. Live execution: `Test-LiveRun.ps1` against dev tenant
4. Commit and push

**Version discipline**: always increment script/schema version numbers; never reuse filenames for review packages.

## Repo

https://github.com/albertjee/m365-security-assessment-tool
