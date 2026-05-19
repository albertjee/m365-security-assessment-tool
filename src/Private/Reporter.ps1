Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Sha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $FilePath)
    $sha    = [System.Security.Cryptography.SHA256]::Create()
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

function Write-HtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Findings,
        [Parameter(Mandatory)] [hashtable] $Metadata,
        [Parameter(Mandatory)] [string] $OutputFolder
    )
    $html = Get-ReportHtmlTemplate -Findings $Findings -Metadata $Metadata
    $path = Join-Path $OutputFolder 'report.html'
    $html | Set-Content -Path $path -Encoding UTF8
    return $path
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
