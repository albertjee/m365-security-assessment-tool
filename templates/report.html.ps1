Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ReportHtmlTemplate {
    param(
        [Parameter(Mandatory)] $Findings,
        [Parameter(Mandatory)] $Metadata
    )

    $severityOrder = @{ Critical=0; High=1; Medium=2; Informational=3 }
    $sorted = $Findings | Sort-Object { $severityOrder[$_.severity] }

    $critCount = @($Findings | Where-Object { $_.severity -eq 'Critical' -and $_.status -eq 'Fail' }).Count
    $highCount = @($Findings | Where-Object { $_.severity -eq 'High'     -and $_.status -eq 'Fail' }).Count
    $totalFail = @($Findings | Where-Object { $_.status -eq 'Fail' }).Count

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
        $sev      = $f.severity
        $sColor   = $badgeColor[$sev]
        $stColor  = $badgeColor[$f.status]
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
