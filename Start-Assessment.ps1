Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#Requires -Version 7.2

function Start-AssessmentPipeline {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][hashtable] $Params
    )

    # 1) Normalize inputs — use index notation for optional keys (safe under strict mode)
    $mode          = $Params['Mode']
    $authMethod    = $Params['AuthMethod']
    $tenantId      = $Params['TenantId']
    $appId         = $Params['AppId']
    $edition       = $Params['Edition']
    $includeChecks = @($Params['IncludeChecks'])
    $outputPath    = $Params['OutputPath']
    $whatIf        = [bool]$Params['WhatIf']
    $force         = [bool]$Params['Force']

    $certThumb    = $Params['CertificateThumbprint']
    $certObj      = $Params['Certificate']
    $certPath     = $Params['CertificateFilePath']
    $certPass     = $Params['CertificatePassword']
    $clientSecret = $Params['ClientSecret']
    $upn          = $Params['UserPrincipalName']
    $org          = $Params['Organization']
    $showBanner   = $Params['ShowBanner']

    if (-not $mode)       { throw "Params.Mode is required (Assess|Remediate)." }
    if (-not $authMethod) { throw "Params.AuthMethod is required (Certificate|Secret|Delegated)." }
    if (-not $tenantId)   { throw "Params.TenantId is required." }
    if (-not $appId)      { throw "Params.AppId is required." }
    if (-not $edition)    { $edition = 'Lite' }

    # 2) RunId + output folder
    $runId      = "$([System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH-mm-ssZ'))-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    $moduleRoot = $PSScriptRoot
    $outputRoot = if ($outputPath) { $outputPath } else { Join-Path (Split-Path $moduleRoot -Parent) 'Output' }
    $runFolder  = Join-Path $outputRoot $runId
    [System.IO.Directory]::CreateDirectory($runFolder) | Out-Null

    $checksPath = Join-Path $moduleRoot 'src/Private/checks'
    $rulePath   = Join-Path $moduleRoot 'src/Private/sequencing/rules'

    # 3) Detect RequireExchange by inspecting check metadata dataSource
    $requireExchange = $false
    try {
        if (($includeChecks.Count -eq 0) -and ($authMethod -ne 'Secret')) {
            $requireExchange = $true
        } else {
            $checkFiles = Get-ChildItem -Path $checksPath -Filter 'Check-*.ps1' -File -ErrorAction Stop
            foreach ($f in $checkFiles) {
                $meta = & { . $f.FullName; Get-CheckMetadata }
                if ($includeChecks.Count -gt 0 -and $meta.id -notin $includeChecks) { continue }
                if ($meta.dataSource -in @('Exchange', 'Both') -and $authMethod -ne 'Secret') {
                    $requireExchange = $true
                    break
                }
            }
        }
    } catch {
        if ($authMethod -ne 'Secret') { $requireExchange = $true }
    }

    # 4) Preflight environment check
    $envResult = Test-Environment -AuthMethod $authMethod -RequireExchange $requireExchange
    if (-not $envResult.IsValid) {
        throw "Environment check failed: $($envResult.Failures -join '; ')"
    }

    # 5) Build and connect GraphGateway
    $gwParams = @{
        TenantId   = $tenantId
        AppId      = $appId
        AuthMethod = $authMethod
        RunId      = $runId
        RunFolder  = $runFolder
    }
    if ($certThumb)    { $gwParams.CertificateThumbprint = $certThumb }
    if ($certObj)      { $gwParams.Certificate           = $certObj }
    if ($certPath)     { $gwParams.CertificateFilePath   = $certPath }
    if ($certPass)     { $gwParams.CertificatePassword   = $certPass }
    if ($clientSecret) { $gwParams.ClientSecret          = $clientSecret }
    if ($upn)          { $gwParams.UserPrincipalName     = $upn }

    $graphGateway = New-GraphGateway @gwParams
    Connect-GraphGateway -GraphGateway $graphGateway | Out-Null

    # 5b) Optionally build and connect ExchangeGateway
    $exchangeGateway = $null
    if ($requireExchange -and $org) {
        $exParams = @{
            TenantId     = $tenantId
            AppId        = $appId
            AuthMethod   = $authMethod
            Organization = $org
            RunId        = $runId
            RunFolder    = $runFolder
        }
        if ($certThumb)  { $exParams.CertificateThumbprint = $certThumb }
        if ($certObj)    { $exParams.Certificate           = $certObj }
        if ($certPath)   { $exParams.CertificateFilePath   = $certPath }
        if ($certPass)   { $exParams.CertificatePassword   = $certPass }
        if ($upn)        { $exParams.UserPrincipalName     = $upn }
        if ($showBanner) { $exParams.ShowBanner            = $showBanner }

        $exchangeGateway = New-ExchangeGateway @exParams
        Connect-ExchangeGateway -ExchangeGateway $exchangeGateway | Out-Null
    }

    try {
        # 6) Tenant pinning — fail closed on mismatch
        $pin = Test-TenantPin -RequestedTenantId $tenantId -GraphGateway $graphGateway
        if (-not $pin.Match) {
            throw "Tenant pin mismatch ($($pin.MismatchReason)). Requested=$tenantId"
        }

        # 7) Permission validation against current session
        $requiredPerms = [System.Collections.Generic.HashSet[string]]::new()
        $checkFiles    = Get-ChildItem -Path $checksPath -Filter 'Check-*.ps1' -File -ErrorAction Stop
        foreach ($f in $checkFiles) {
            $meta = & { . $f.FullName; Get-CheckMetadata }
            if ($includeChecks.Count -gt 0 -and $meta.id -notin $includeChecks) { continue }
            foreach ($p in @($meta.requiredPermissions)) {
                if ($p) { [void]$requiredPerms.Add($p) }
            }
        }
        $ctx           = Get-MgContext
        $grantedScopes = @($ctx.Scopes)
        $permCheck     = Test-GraphPermissions -RequiredPermissions @($requiredPerms) -GrantedScopes $grantedScopes
        if (-not $permCheck.IsValid) {
            throw "Missing required Graph permissions: $($permCheck.Missing -join ', ')"
        }

        # 8) Build Config for audit
        $config = @{
            Edition         = $edition
            EnabledChecks   = $includeChecks
            RunId           = $runId
            Mode            = $mode
            AuthMethod      = $authMethod
            ExchangeGateway = $exchangeGateway
        }

        # 9) Run audit with correct signature
        $findings = @(Invoke-Audit `
            -GraphGateway    $graphGateway `
            -ExchangeGateway $exchangeGateway `
            -Config          $config `
            -ChecksPath      $checksPath `
            -RunId           $runId
        )

        $findingsPath = Write-FindingsJson -Findings $findings -OutputFolder $runFolder

        # 10) Sequencing — Premium+Remediate, always generate plan regardless of WhatIf
        $sequencePlanPath = $null
        $jsonlPath        = $null
        $execLog          = @()

        if ($edition -eq 'Premium' -and $mode -eq 'Remediate') {
            $allRules = Get-AllRules -RulesPath $rulePath

            $actions = @(
                $findings |
                Where-Object { $_.supportsRemediation -and $_.status -eq 'Fail' } |
                ForEach-Object {
                    [PSCustomObject]@{
                        action       = [PSCustomObject]@{
                            actionId     = "ACT-$($_.checkId)-REMEDIATE"
                            provider     = 'Graph'
                            operation    = 'PATCH'
                            resourceType = 'policy'
                            resourceId   = $_.id
                            target       = $tenantId
                        }
                        sequence     = [PSCustomObject]@{
                            dependencies  = @()
                            conflictsWith = @()
                            priority      = 1
                            safetyLevel   = 'High'
                            category      = $_.category
                            phase         = 2
                        }
                        result       = [PSCustomObject]@{ status = $null; reason = $null }
                        rulesApplied = @()
                        request      = [PSCustomObject]@{
                            endpoint = "/placeholder/$($_.id)"
                            method   = 'PATCH'
                            body     = @{}
                        }
                        check        = [PSCustomObject]@{ checkId = $_.checkId; findingId = $_.id }
                    }
                }
            )

            if ($actions.Count -gt 0) {
                $annotated        = Invoke-DependencyRules -Actions $actions -Rules $allRules -Findings $findings
                $plan             = New-SequencePlan -Actions $annotated -RulesVersion '1.0.0'
                $sequencePlanPath = Write-SequencePlanJson -SequencePlan $plan -OutputFolder $runFolder

                $context = [PSCustomObject]@{
                    Mode       = $mode
                    AuthMethod = $authMethod
                    WhatIf     = $whatIf
                    Edition    = $edition
                }

                $execLog = Invoke-Executor `
                    -Plan         $plan `
                    -Actions      $annotated `
                    -Context      $context `
                    -GraphGateway $graphGateway `
                    -Findings     $findings `
                    -TenantId     $tenantId

                $jsonlPath = Join-Path $runFolder 'remediation.actions.jsonl'
                foreach ($entry in @($execLog)) {
                    ($entry | ConvertTo-Json -Compress -Depth 10) | Add-Content -Path $jsonlPath -Encoding UTF8
                }
            }
        }

        # 11) Manifest and HTML report
        $gitCommit = try {
            $out = & git rev-parse --short HEAD 2>&1
            if ($LASTEXITCODE -eq 0 -and $out) { "$out".Trim() } else { 'unknown' }
        } catch { 'unknown' }

        $status      = 'Complete'
        $notAssessed = @($findings | Where-Object { $_.status -eq 'NotAssessed' }).Count
        if ($notAssessed -gt 0) { $status = 'Partial' }

        $maskedTenant = ($tenantId -replace '(?<=.{4}).(?=.{4})', '*')

        $manifest = @{
            schemaVersion = '1.0'
            run           = @{
                runId        = $runId
                mode         = $mode
                edition      = $edition
                authMethod   = $authMethod
                whatIf       = $whatIf
                timestampUtc = [System.DateTime]::UtcNow.ToString('o')
            }
            tenantPinning = @{
                requestedTenantIdMasked = $maskedTenant
                match                   = $true
            }
            execution     = @{
                status   = $status
                findings = @{
                    total         = @($findings).Count
                    critical      = @($findings | Where-Object { $_.severity -eq 'Critical' }).Count
                    high          = @($findings | Where-Object { $_.severity -eq 'High' }).Count
                    medium        = @($findings | Where-Object { $_.severity -eq 'Medium' }).Count
                    informational = @($findings | Where-Object { $_.severity -eq 'Informational' }).Count
                }
            }
            git           = @{ commit = $gitCommit }
            artifacts     = @(
                @{ name = 'findings.json'; path = $findingsPath }
            )
        }

        if ($sequencePlanPath) {
            $manifest.artifacts += @{ name = 'sequence-plan.json'; path = $sequencePlanPath }
        }
        if ($jsonlPath -and (Test-Path $jsonlPath)) {
            $manifest.artifacts += @{ name = 'remediation.actions.jsonl'; path = $jsonlPath }
        }

        $manifestPath = Write-RunManifest -Manifest $manifest -OutputFolder $runFolder -ComputeArtifactHashes

        $htmlPath = Write-HtmlReport -Findings $findings -Metadata @{
            RunId          = $runId
            Mode           = $mode
            AuthMethod     = $authMethod
            TenantIdMasked = $maskedTenant
            Timestamp      = [System.DateTime]::UtcNow.ToString('o')
            ModuleVersion  = '0.1.0'
            GitCommit      = $gitCommit
            Status         = $status
        } -OutputFolder $runFolder

        return [PSCustomObject]@{
            RunId        = $runId
            OutputFolder = $runFolder
            Findings     = $findings
            Status       = $status
            ManifestPath = $manifestPath
            ReportPath   = $htmlPath
        }
    }
    finally {
        try { Disconnect-GraphGateway -GraphGateway $graphGateway } catch {}
        if ($exchangeGateway) {
            try { Disconnect-ExchangeGateway -ExchangeGateway $exchangeGateway } catch {}
        }
    }
}
