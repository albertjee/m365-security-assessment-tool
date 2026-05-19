BeforeAll {
    . "$PSScriptRoot/../src/Private/models/Finding.schema.ps1"
    . "$PSScriptRoot/../src/Private/models/RemediationAction.schema.ps1"
    . "$PSScriptRoot/../src/Private/Reporter.ps1"

    $script:tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "metis-reporter-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $script:tmpDir -Force | Out-Null

    $script:sampleFinding = New-Finding -CheckId 'CA-001' -RunId 'run-001' `
        -Title 'Legacy Auth' -Category 'Identity' -Severity 'Critical' -RiskScore 95 `
        -SecureScoreVisibility 'Passes' -Status 'Fail' -GraphEndpoint '/test' -SupportsRemediation $true

    $script:sampleManifest = @{
        schemaVersion = '1.0'
        run           = @{ runId='run-001'; mode='Assess'; whatIf=$false }
        tenantPinning = @{ match=$true }
        auth          = @{ authMethod='Certificate' }
        execution     = @{ status='Success'; findings=@{ total=1; critical=1 } }
    }
}

AfterAll { Remove-Item $script:tmpDir -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'Write-FindingsJson' {
    It 'writes valid JSON array to findings.json' {
        $path = Write-FindingsJson -Findings @($script:sampleFinding) -OutputFolder $script:tmpDir
        $path | Should -Exist
        $json = Get-Content $path -Raw | ConvertFrom-Json
        $json.Count | Should -Be 1
        $json[0].checkId | Should -Be 'CA-001'
    }
}

Describe 'Write-RunManifest' {
    It 'writes run.manifest.json with required top-level keys' {
        $path = Write-RunManifest -Manifest $script:sampleManifest -OutputFolder $script:tmpDir
        $path | Should -Exist
        $json = Get-Content $path -Raw | ConvertFrom-Json
        $json.schemaVersion | Should -Be '1.0'
        $json.run.runId     | Should -Be 'run-001'
    }

    It 'manifest includes artifact sha256 entries for findings.json' {
        $findingsPath = Write-FindingsJson -Findings @($script:sampleFinding) -OutputFolder $script:tmpDir
        $manifest = $script:sampleManifest.Clone()
        $manifest['artifacts'] = @(
            @{ name='findings.json'; path=$findingsPath }
        )
        $path = Write-RunManifest -Manifest $manifest -OutputFolder $script:tmpDir -ComputeArtifactHashes
        $json = Get-Content $path -Raw | ConvertFrom-Json
        $json.artifacts[0].sha256 | Should -Match '^sha256:'
    }
}

Describe 'Append-RemediationActionLog' {
    It 'appends NDJSON entries — does not overwrite' {
        $logPath = Join-Path $script:tmpDir 'remediation.actions.jsonl'
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
        $f = Join-Path $script:tmpDir 'hashtest.txt'
        Set-Content -Path $f -Value 'hello'
        $hash = Get-Sha256 -FilePath $f
        $hash | Should -Match '^sha256:[a-f0-9]{64}$'
    }
}
