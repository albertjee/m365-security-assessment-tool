Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Remediator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Action,
        [Parameter(Mandatory)] $GraphGateway,
        $ExchangeGateway = $null,
        [string] $RunFolder = $null
    )

    $actionId  = $Action.action.actionId
    $provider  = $Action.action.provider
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        if ($provider -eq 'Exchange') {
            if (-not $ExchangeGateway) {
                throw "ExchangeGateway is required for Exchange provider action '$actionId'"
            }
            $readParams  = if ($Action.request.PSObject.Properties['parameters'] -and $null -ne $Action.request.parameters) {
                               $Action.request.parameters
                           } else { @{} }
            $writeParams = if ($Action.request.PSObject.Properties['writeParameters'] -and $null -ne $Action.request.writeParameters) {
                               $Action.request.writeParameters
                           } else { @{} }
            $writeCmdlet = $Action.request.writeCmdletName

            $null = Invoke-ExchangeRequest -CmdletName $writeCmdlet -Parameters $writeParams `
                        -OperationType 'Write' -Caller 'Remediator'

        } elseif ($provider -eq 'Graph') {
            $endpoint = $Action.request.endpoint
            $method   = $Action.request.method
            $body     = if ($Action.request.PSObject.Properties['body'] -and $null -ne $Action.request.body) {
                            $Action.request.body
                        } else { $null }

            $beforeProp = $Action.request.PSObject.Properties['beforeEndpoint']
            if ($beforeProp -and $beforeProp.Value) {
                $null = Invoke-GraphRequest -GraphGateway $GraphGateway `
                            -Uri $beforeProp.Value -Method 'GET' `
                            -OperationType 'Read' -Caller 'Remediator'
            }

            if ($body) {
                $null = Invoke-GraphRequest -GraphGateway $GraphGateway `
                            -Uri $endpoint -Method $method -Body $body `
                            -OperationType 'Write' -Caller 'Remediator'
            } else {
                $null = Invoke-GraphRequest -GraphGateway $GraphGateway `
                            -Uri $endpoint -Method $method `
                            -OperationType 'Write' -Caller 'Remediator'
            }

            $afterProp = $Action.request.PSObject.Properties['afterEndpoint']
            if ($afterProp -and $afterProp.Value) {
                $null = Invoke-GraphRequest -GraphGateway $GraphGateway `
                            -Uri $afterProp.Value -Method 'GET' `
                            -OperationType 'Read' -Caller 'Remediator'
            }

        } else {
            throw "Unknown provider '$provider' for action '$actionId'"
        }

        $stopwatch.Stop()
        $result = [PSCustomObject]@{
            actionId   = $actionId
            status     = 'Success'
            error      = $null
            durationMs = $stopwatch.ElapsedMilliseconds
        }
    } catch {
        $stopwatch.Stop()
        $result = [PSCustomObject]@{
            actionId   = $actionId
            status     = 'Failed'
            error      = $_.Exception.Message
            durationMs = $stopwatch.ElapsedMilliseconds
        }
    }

    if ($RunFolder) {
        $jsonlPath = Join-Path $RunFolder 'remediation.actions.jsonl'
        ($result | ConvertTo-Json -Compress -Depth 5) | Add-Content -Path $jsonlPath -Encoding UTF8
    }

    return $result
}
