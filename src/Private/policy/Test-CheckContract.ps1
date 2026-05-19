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
    '\b(Set|New|Remove|Enable|Disable)-(Mg|Az|AzureAD|EXO|SPO|MSol)\w+\b'
)

function Test-CheckContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $ModulePath)

    $violations = [System.Collections.Generic.List[string]]::new()
    $content    = Get-Content -Path $ModulePath -Raw -ErrorAction Stop
    $ast     = [System.Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$null, [ref]$null)
    $fnNames = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $false) | ForEach-Object { $_.Name })

    if ('Get-CheckMetadata' -notin $fnNames) {
        $violations.Add('Get-CheckMetadata function not found')
    }
    if ('Invoke-Check' -notin $fnNames) {
        $violations.Add('Invoke-Check function not found')
    }

    if ('Get-CheckMetadata' -in $fnNames) {
        try {
            $sb        = [scriptblock]::Create($content)
            $tmpModule = New-Module -Name "__ContractCheck_$(New-Guid)" -ScriptBlock $sb
            $meta      = & $tmpModule { Get-CheckMetadata }
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
