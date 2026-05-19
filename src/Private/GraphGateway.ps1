Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-GraphGateway {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $TenantId,
        [Parameter(Mandatory)][string] $AppId,
        [Parameter(Mandatory)][ValidateSet('Certificate','Secret','Delegated')] [string] $AuthMethod,
        [Parameter()][string] $CertificateThumbprint,
        [Parameter()][System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter()][string] $CertificateFilePath,
        [Parameter()][securestring] $CertificatePassword,
        [Parameter()][string] $ClientSecret,
        [Parameter()][string] $UserPrincipalName,
        [Parameter(Mandatory)][string] $RunId,
        [Parameter(Mandatory)][string] $RunFolder
    )
    [PSCustomObject]@{
        PSTypeName            = 'Metis.GraphGateway'
        TenantId              = $TenantId
        AppId                 = $AppId
        AuthMethod            = $AuthMethod
        CertificateThumbprint = $CertificateThumbprint
        Certificate           = $Certificate
        CertificateFilePath   = $CertificateFilePath
        CertificatePassword   = $CertificatePassword
        ClientSecret          = $ClientSecret
        UserPrincipalName     = $UserPrincipalName
        RunId                 = $RunId
        RunFolder             = $RunFolder
        Connected             = $false
        AccessToken           = $null
    }
}

function Connect-GraphGateway {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $GraphGateway)

    if ($GraphGateway.Connected) { return $GraphGateway }

    $connectParams = @{
        TenantId    = $GraphGateway.TenantId
        ClientId    = $GraphGateway.AppId
        NoWelcome   = $true
        ErrorAction = 'Stop'
    }

    switch ($GraphGateway.AuthMethod) {
        'Certificate' {
            if ($GraphGateway.CertificateThumbprint) {
                $connectParams['CertificateThumbprint'] = $GraphGateway.CertificateThumbprint
            } elseif ($GraphGateway.Certificate) {
                $connectParams['Certificate'] = $GraphGateway.Certificate
            } elseif ($GraphGateway.CertificateFilePath) {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    $GraphGateway.CertificateFilePath,
                    $GraphGateway.CertificatePassword
                )
                $connectParams['Certificate'] = $cert
            } else {
                throw "Certificate auth requires CertificateThumbprint OR Certificate OR CertificateFilePath."
            }
            Connect-MgGraph @connectParams | Out-Null
        }
        'Secret' {
            $secret = $GraphGateway.ClientSecret
            if (-not $secret) { throw "AuthMethod=Secret requires ClientSecret." }
            $connectParams['ClientSecretCredential'] = [System.Net.NetworkCredential]::new('', $secret).SecurePassword
            Connect-MgGraph @connectParams | Out-Null
        }
        'Delegated' {
            Connect-MgGraph @connectParams | Out-Null
        }
        default { throw "Unsupported AuthMethod: $($GraphGateway.AuthMethod)" }
    }

    $GraphGateway.Connected   = $true
    $GraphGateway.AccessToken = (Get-MgContext).AccessToken
    return $GraphGateway
}

function Disconnect-GraphGateway {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $GraphGateway)
    if (-not $GraphGateway.Connected) { return }
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    $GraphGateway.Connected   = $false
    $GraphGateway.AccessToken = $null
}

function Invoke-GraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $GraphGateway,
        [Parameter(Mandatory)][string] $Uri,
        [Parameter(Mandatory)][string] $Method,
        [Parameter()][object] $Body,
        [Parameter(Mandatory)][ValidateSet('Read','Write')] [string] $OperationType,
        [Parameter()][string] $Caller = 'Unknown',
        [Parameter()][ValidateRange(0,10)][int] $MaxRetries = 3
    )

    $isGet = $Method -eq 'GET'

    if ($OperationType -eq 'Read' -and -not $isGet) {
        throw "GraphGateway contract violation: OperationType=Read requires GET. Got '$Method'."
    }

    if (-not $isGet) {
        if (-not ($Caller -eq 'Remediator' -and $OperationType -eq 'Write')) {
            throw "Graph write denied: Caller=$Caller OperationType=$OperationType Method=$Method URI=$Uri"
        }
    }

    Connect-GraphGateway -GraphGateway $GraphGateway | Out-Null

    $clientRequestId = [Guid]::NewGuid().ToString()
    $headers = @{ 'x-ms-client-request-id' = $clientRequestId }

    $retryDelaysMs = @()
    $attempt = 0
    $allValues = [System.Collections.Generic.List[object]]::new()
    $response = $null

    $currentUri = $Uri
    while ($currentUri) {
        $attempt++
        try {
            $invokeParams = @{
                Uri         = $currentUri
                Method      = $Method
                Headers     = $headers
                ErrorAction = 'Stop'
            }
            if ($Body -and -not $isGet) {
                $invokeParams['Body']        = ($Body | ConvertTo-Json -Depth 20 -Compress)
                $invokeParams['ContentType'] = 'application/json'
            }

            $response = Invoke-MgGraphRequest @invokeParams
            $attempt  = 0
            $retryDelaysMs = @()
        } catch {
            $msg        = $_.Exception.Message
            $statusCode = $null
            if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
            $isTransient = ($statusCode -in @(429,500,502,503,504)) -or ($msg -match '(?i)throttl|timeout|server busy|try again')

            if (-not $isTransient -or $attempt -gt $MaxRetries) { throw }

            $delay = [int]([math]::Pow(2, $attempt - 1) * 1000)
            $retryDelaysMs += $delay
            Start-Sleep -Milliseconds $delay
            continue
        }

        if ($response.value) {
            foreach ($v in $response.value) { $allValues.Add($v) | Out-Null }
        }

        $currentUri = if ($response -is [hashtable]) { $response['@odata.nextLink'] } `
                      elseif ($response) { $response.PSObject.Properties['@odata.nextLink']?.Value } `
                      else { $null }
        if (-not $currentUri) { break }
    }

    $result = if ($allValues.Count -gt 0) { @{ value = $allValues.ToArray() } } else { $response }

    return [PSCustomObject]@{
        Result          = $result
        ClientRequestId = $clientRequestId
        HttpStatusCode  = $null
        Retries         = $retryDelaysMs.Count
        RetryDelaysMs   = $retryDelaysMs
    }
}
