Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Remediator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Action,
        [Parameter(Mandatory)] $GraphGateway,
        $ExchangeGateway = $null
    )

    $actionId  = $Action.action.actionId
    $provider  = $Action.action.provider
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        if ($provider -eq 'Exchange') {
            if (-not $ExchangeGateway) {
                throw "ExchangeGateway is required for Exchange provider action '$actionId'"
            }
            $writeCmdlet = $Action.request.writeCmdletName
            $writeParams = if ($Action.request.writeParameters) { $Action.request.writeParameters } else { @{} }
            $null = Invoke-ExchangeRequest -CmdletName $writeCmdlet -Parameters $writeParams -OperationType 'Write'
        } elseif ($provider -eq 'Graph') {
            $endpoint = $Action.request.endpoint
            $method   = $Action.request.method
            $body     = if ($Action.request.PSObject.Properties['body'] -and $Action.request.body) { $Action.request.body } else { $null }
            if ($body) {
                $null = Invoke-GraphRequest -Uri $endpoint -Method $method -Body $body -OperationType 'Write'
            } else {
                $null = Invoke-GraphRequest -Uri $endpoint -Method $method -OperationType 'Write'
            }
        } else {
            throw "Unknown provider '$provider' for action '$actionId'"
        }

        $stopwatch.Stop()
        return [PSCustomObject]@{
            actionId   = $actionId
            status     = 'Success'
            error      = $null
            durationMs = $stopwatch.ElapsedMilliseconds
        }
    } catch {
        $stopwatch.Stop()
        return [PSCustomObject]@{
            actionId   = $actionId
            status     = 'Failed'
            error      = $_.Exception.Message
            durationMs = $stopwatch.ElapsedMilliseconds
        }
    }
}
