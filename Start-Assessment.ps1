Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#Requires -Version 7.2

function Start-AssessmentPipeline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable] $Params
    )

    $mode          = $Params.Mode
    $authMethod    = $Params.AuthMethod
    $tenantId      = $Params.TenantId
    $appId         = $Params.AppId
    $edition       = $Params.Edition
    $includeChecks = $Params.IncludeChecks
    $outputPath    = $Params.OutputPath
    $whatIf        = $Params.WhatIf
    $force         = $Params.Force

    $runId      = "$([System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH-mm-ssZ'))-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    $outputRoot = if ($outputPath) { $outputPath } else { Join-Path (Split-Path $PSScriptRoot -Parent) 'Output' }
    $runFolder  = Join-Path $outputRoot $runId
    [System.IO.Directory]::CreateDirectory($runFolder) | Out-Null

    $moduleRoot = $PSScriptRoot

    $config  = [PSCustomObject]@{
        edition       = $edition
        includeChecks = $includeChecks
        runId         = $runId
        mode          = $mode
        authMethod    = $authMethod
    }

    $findings = @(Invoke-Audit -ChecksPath (Join-Path $moduleRoot 'src/Private/checks') -Config $config)

    Write-FindingsJson -Findings $findings -OutputFolder $runFolder | Out-Null

    if ($edition -eq 'Premium' -and $mode -eq 'Remediate' -and -not $whatIf) {
        $rulesPath  = Join-Path $moduleRoot 'src/Private/sequencing/rules'
        $allRules   = Get-AllRules -RulesPath $rulesPath

        $actions    = @($findings | Where-Object { $_.supportsRemediation -and $_.status -eq 'Fail' } | ForEach-Object {
            [PSCustomObject]@{
                action       = [PSCustomObject]@{ actionId="ACT-$($_.checkId)-REMEDIATE"; provider='Graph'; operation='PATCH'; resourceType='policy'; resourceId=$_.id; target=$tenantId }
                sequence     = [PSCustomObject]@{ dependencies=@(); conflictsWith=@(); priority=1; safetyLevel='High'; category=$_.category; phase=2 }
                result       = [PSCustomObject]@{ status=$null; reason=$null }
                rulesApplied = @()
            }
        })

        if ($actions.Count -gt 0) {
            $annotated = Invoke-DependencyRules -Actions $actions -Rules $allRules -Findings $findings
            $plan      = New-SequencePlan -Actions $annotated -RulesVersion '1.0.0'

            $context = [PSCustomObject]@{
                Mode       = $mode
                AuthMethod = $authMethod
                WhatIf     = $whatIf
                Edition    = $edition
            }

            $log = Invoke-Executor -Plan $plan -Actions $annotated -Context $context -GraphGateway $null
            Write-SequencePlanJson -Plan $plan -OutputFolder $runFolder | Out-Null

            $jsonlPath = Join-Path $runFolder 'remediation.actions.jsonl'
            foreach ($entry in $log) {
                ($entry | ConvertTo-Json -Compress -Depth 5) | Add-Content -Path $jsonlPath -Encoding UTF8
            }
        }
    }

    $gitCommit = try {
        $out = & git rev-parse --short HEAD 2>&1
        if ($LASTEXITCODE -eq 0 -and $out) { "$out".Trim() } else { 'unknown' }
    } catch { 'unknown' }

    $manifest = [PSCustomObject]@{
        runId      = $runId
        tenantId   = ($tenantId -replace '(?<=.{4}).(?=.{4})', '*')
        appId      = $appId
        mode       = $mode
        edition    = $edition
        authMethod = $authMethod
        timestamp  = [System.DateTime]::UtcNow.ToString('o')
        status     = 'Complete'
        findings   = @($findings).Count
        gitCommit  = $gitCommit
    }
    Write-RunManifest -Manifest $manifest -OutputFolder $runFolder | Out-Null

    Write-HtmlReport -Findings $findings -Meta $manifest -OutputFolder $runFolder | Out-Null

    return [PSCustomObject]@{
        RunId      = $runId
        OutputPath = $runFolder
        Findings   = $findings
        Status     = 'Complete'
    }
}
