Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-RemediationAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $RunId,
        [Parameter(Mandatory)][string]   $CheckId,
        [Parameter(Mandatory)][string]   $CheckName,
        [Parameter(Mandatory)][string]   $FindingId,
        [Parameter(Mandatory)][string]   $ActionId,
        [Parameter(Mandatory)][string]   $Operation,
        [Parameter(Mandatory)][string]   $ResourceType,
        [Parameter()][string]            $ResourceId    = $null,
        [Parameter(Mandatory)][string]   $Target,
        [Parameter(Mandatory)][ValidateSet('Graph','Exchange')] [string] $Provider,
        [Parameter(Mandatory)][int]      $Phase,
        [Parameter(Mandatory)][int]      $Order,
        [Parameter()][string[]]          $Dependencies  = @(),
        [Parameter()][string[]]          $ConflictsWith = @(),
        [Parameter(Mandatory)][int]      $Priority,
        [Parameter()][string]            $SafetyLevel   = 'High',
        [Parameter()][string]            $Category      = $null,
        [Parameter(Mandatory)][string]   $TenantIdMasked,
        [Parameter()][string]            $Endpoint      = $null,
        [Parameter()][string]            $HttpMethod     = $null,
        [Parameter()][object]            $Body           = $null,
        [Parameter()][string]            $CmdletName        = $null,
        [Parameter()][hashtable]         $Parameters        = $null,
        [Parameter()][string]            $WriteCmdletName   = $null,
        [Parameter()][hashtable]         $WriteParameters   = $null
    )

    if ($Provider -eq 'Graph') {
        if (-not $Endpoint -or -not $HttpMethod) {
            throw "Graph RemediationAction requires -Endpoint and -HttpMethod"
        }
    }
    if ($Provider -eq 'Exchange') {
        if (-not $CmdletName) {
            throw "Exchange RemediationAction requires -CmdletName"
        }
    }

    $bodyHash = $null
    if ($Body) {
        $bodyJson = $Body | ConvertTo-Json -Depth 20 -Compress
        $bytes    = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)
        $sha      = [System.Security.Cryptography.SHA256]::Create()
        $bodyHash = 'sha256:' + ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').ToLower()
    }

    [PSCustomObject]@{
        schemaVersion = '1.0'
        runContext    = [PSCustomObject]@{
            runId        = $RunId
            sequence     = $null
            timestampUtc = [System.DateTime]::UtcNow.ToString('o')
        }
        tenant = [PSCustomObject]@{
            tenantIdMasked = $TenantIdMasked
            tenantMatch    = $true
        }
        check = [PSCustomObject]@{
            checkId   = $CheckId
            checkName = $CheckName
            findingId = $FindingId
        }
        action = [PSCustomObject]@{
            actionId     = $ActionId
            operation    = $Operation
            resourceType = $ResourceType
            resourceId   = $ResourceId
            target       = $Target
            provider     = $Provider
        }
        sequence = [PSCustomObject]@{
            phase         = $Phase
            order         = $Order
            dependencies  = $Dependencies
            conflictsWith = $ConflictsWith
            priority      = $Priority
            safetyLevel   = $SafetyLevel
            category      = $Category
        }
        execution = [PSCustomObject]@{
            whatIf        = $false
            confirmed     = $false
            confirmImpact = 'High'
            force         = $false
            writeAllowed  = $false
            executionMode = $null
            gates         = [PSCustomObject]@{
                modeRemediate     = $false
                delegatedAuth     = $false
                notWhatIf         = $false
                policyCheckPassed = $false
            }
        }
        request = [PSCustomObject]@{
            endpoint        = $Endpoint
            method          = $HttpMethod
            bodyHash        = $bodyHash
            headers         = [PSCustomObject]@{ clientRequestId = $null }
            cmdletName      = $CmdletName
            parameters      = $Parameters
            writeCmdletName = $WriteCmdletName
            writeParameters = $WriteParameters
        }
        rulesApplied = @()
        state = [PSCustomObject]@{
            beforeRef   = $null
            afterRef    = $null
            diffSummary = $null
        }
        result = [PSCustomObject]@{
            status        = $null
            reason        = $null
            httpStatusCode = $null
            retries       = 0
            retryDelaysMs = @()
            durationMs    = 0
        }
        error = $null
    }
}
