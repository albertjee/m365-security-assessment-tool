# M365 Security Assessment Tool — Implementation Plan Index

**Spec:** `docs/superpowers/specs/2026-05-18-m365-security-assessment-design.md`

| File | Tasks | Coverage |
|---|---|---|
| [2026-05-18-m365-security-assessment.md](2026-05-18-m365-security-assessment.md) | 1–18 | Repo structure, Gateways, Policy layer, Models, First 3 checks, Auditor, Reporter, ActionGraphBuilder, Rules Library, DependencyRulesEngine |
| [tasks-19-24.md](tasks-19-24.md) | 19–24 | Planner, Executor, Remediator, CA/PIM/LegacyAuth Invoke-Remediation |
| [tasks-25-30.md](tasks-25-30.md) | 25–30 | Invoke-M365Assessment pipeline wiring (Assess + Remediate modes), DLP+CrossCheck rules, Sequencing integration tests |
| [tasks-31-34.md](tasks-31-34.md) | 31–34 | Check-EmailAuthentication, Check-DLP, Check-GuestAccess, Check-DeviceCompliance |
| [tasks-35-38.md](tasks-35-38.md) | 35–38 | Check-SmtpAuth, Check-SharePointSharing (SPO extension), Check-AuditLogging, Check-SensitivityLabels, Check-DefenderOffice365, Check-CloudAppSecurity + full suite validation |

## v1 Build Order

```
Tasks 1–6   → infrastructure foundation
Tasks 7–9   → models + contract
Tasks 10–12 → first 3 checks (CA, PIM, LegacyAuth)
Task  13    → Auditor
Tasks 14–15 → Reporter
Tasks 16–18 → Sequencing engine core
Tasks 19–21 → Planner + Executor + Remediator
Tasks 22–24 → Invoke-Remediation for first 3 checks
Tasks 25–26 → Pipeline wiring (Assess + Remediate end-to-end)
Tasks 27–28 → DLP + CrossCheck rules + sequencing integration tests
Tasks 31–34 → EmailAuth, DLP, GuestAccess, DeviceCompliance
Tasks 35–38 → SmtpAuth, SharePoint, AuditLogging, SensitivityLabels, Defender, CASB + suite sweep
```
