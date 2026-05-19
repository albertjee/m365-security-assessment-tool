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

        # 1. Contract validation (AST-only, no execution)
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

        # 5. Run check in child scope — New-Finding resolves from parent scope
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
