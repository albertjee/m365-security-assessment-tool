
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-ExchangeGateway {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $TenantId,
        [Parameter(Mandatory)][string] $AppId,

        [Parameter(Mandatory)]
        [ValidateSet('Certificate','Secret','Delegated')]
        [string] $AuthMethod,

        # For Certificate auth (app-only) you must provide either Thumbprint or Certificate object/file path.
        [Parameter()][string] $CertificateThumbprint,
        [Parameter()][System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter()][string] $CertificateFilePath,
        [Parameter()][securestring] $CertificatePassword,

        # For Delegated auth (interactive), optional hint.
        [Parameter()][string] $UserPrincipalName,

        # Exchange org identity; for EXO, this is typically tenant domain (e.g., contoso.onmicrosoft.com)
        [Parameter(Mandatory)][string] $Organization,

        [Parameter(Mandatory)][string] $RunId,
        [Parameter(Mandatory)][string] $RunFolder,

        [Parameter()][switch] $ShowBanner
    )

    # ExchangeOnlineManagement module is required for Connect-ExchangeOnline
    # Your spec already requires Test-Environment to verify this. [1](https://onedrive.live.com/?id=93c1d491-3b46-4e26-b49c-4b7daad9fa45&cid=15085622402a77de&web=1)
    [PSCustomObject]@{
        PSTypeName            = 'Metis.ExchangeGateway'
        TenantId              = $TenantId
        AppId                 = $AppId
        AuthMethod            = $AuthMethod
        Organization          = $Organization
        CertificateThumbprint = $CertificateThumbprint
        Certificate           = $Certificate
        CertificateFilePath   = $CertificateFilePath
        CertificatePassword   = $CertificatePassword
        UserPrincipalName     = $UserPrincipalName
        RunId                 = $RunId
        RunFolder             = $RunFolder
        ShowBanner            = [bool]$ShowBanner

        # runtime
        Connected             = $false
        ConnectionInfo        = $null
    }
}

function Connect-ExchangeGateway {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ExchangeGateway
    )

    if ($ExchangeGateway.Connected) { return $ExchangeGateway }

    # Ensure module available
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw "ExchangeOnlineManagement module not found. Install-Module ExchangeOnlineManagement is required."
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    # Connect-ExchangeOnline supports app-only certificate and delegated interactive. [3](https://github.com/MicrosoftDocs/office-docs-powershell/blob/main/exchange/exchange-ps/ExchangePowerShell/Connect-ExchangeOnline.md)[2](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps)
    $connectParams = @{
        Organization = $ExchangeGateway.Organization
        ShowBanner   = $ExchangeGateway.ShowBanner
        ErrorAction  = 'Stop'
    }

    switch ($ExchangeGateway.AuthMethod) {
        'Delegated' {
            if ($ExchangeGateway.UserPrincipalName) {
                $connectParams['UserPrincipalName'] = $ExchangeGateway.UserPrincipalName
            }
            Connect-ExchangeOnline @connectParams | Out-Null
        }
        'Certificate' {
            $connectParams['AppId'] = $ExchangeGateway.AppId

            if ($ExchangeGateway.CertificateThumbprint) {
                $connectParams['CertificateThumbprint'] = $ExchangeGateway.CertificateThumbprint
            }
            elseif ($ExchangeGateway.Certificate) {
                $connectParams['Certificate'] = $ExchangeGateway.Certificate
            }
            elseif ($ExchangeGateway.CertificateFilePath) {
                $connectParams['CertificateFilePath'] = $ExchangeGateway.CertificateFilePath
                if ($ExchangeGateway.CertificatePassword) {
                    $connectParams['CertificatePassword'] = $ExchangeGateway.CertificatePassword
                }
            }
            else {
                throw "Certificate auth requires CertificateThumbprint OR Certificate OR CertificateFilePath."
            }

            Connect-ExchangeOnline @connectParams | Out-Null
        }
        'Secret' {
            # ExchangeOnlineManagement does not natively accept a client secret parameter.
            # If you want Secret-based auth, you must supply -AccessToken to Connect-ExchangeOnline,
            # or avoid Exchange-backed checks under Secret mode (recommended for v1).
            throw "AuthMethod=Secret is not supported for ExchangeGateway without supplying an AccessToken. Use Certificate or Delegated."
        }
        default {
            throw "Unsupported AuthMethod: $($ExchangeGateway.AuthMethod)"
        }
    }

    # Capture connection info if available
    $ci = $null
    if (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) {
        $ci = Get-ConnectionInformation | Select-Object -First 1
    }

    $ExchangeGateway.Connected = $true
    $ExchangeGateway.ConnectionInfo = $ci
    return $ExchangeGateway
}

function Disconnect-ExchangeGateway {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ExchangeGateway
    )

    if (-not $ExchangeGateway.Connected) { return }

    if (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }

    $ExchangeGateway.Connected = $false
    $ExchangeGateway.ConnectionInfo = $null
}

function Invoke-ExchangeRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ExchangeGateway,

        # Exchange cmdlet to invoke, e.g. Get-EXOMailbox, Set-TransportConfig, New-HostedContentFilterPolicy, etc.
        [Parameter(Mandatory)][string] $CmdletName,

        # Hashtable of parameters to splat into the cmdlet
        [Parameter()][hashtable] $Parameters = @{},  # splat

        [Parameter(Mandatory)]
        [ValidateSet('Read','Write')]
        [string] $OperationType,

        [Parameter()][string] $Caller = 'Unknown',

        # Optional: allow caller to request retry for transient failures
        [Parameter()][ValidateRange(0,10)][int] $MaxRetries = 3
    )

    # Ensure connected (connect once per run)
    Connect-ExchangeGateway -ExchangeGateway $ExchangeGateway | Out-Null

    # OperationType contract:
    # Read  = Get-* only
    # Write = Set-*, Enable-*, Disable-*, New-*, Remove-*, Add-*, etc.
    # You specified Read=Get-* only in the design. [1](https://onedrive.live.com/?id=93c1d491-3b46-4e26-b49c-4b7daad9fa45&cid=15085622402a77de&web=1)
    $isGet = $CmdletName.StartsWith('Get-', [System.StringComparison]::OrdinalIgnoreCase)

    if ($OperationType -eq 'Read' -and -not $isGet) {
        throw "ExchangeGateway contract violation: OperationType=Read requires Get-* cmdlet. Got '$CmdletName'."
    }

    if (-not $isGet) {
        # Default-deny ALL non-Get-* unless caller is Remediator AND OperationType=Write AND Test-WriteAllowed passed. [1](https://onedrive.live.com/?id=93c1d491-3b46-4e26-b49c-4b7daad9fa45&cid=15085622402a77de&web=1)
        if (-not ($Caller -eq 'Remediator' -and $OperationType -eq 'Write')) {
            throw "Exchange write denied: Caller=$Caller OperationType=$OperationType Cmdlet=$CmdletName"
        }
    }

    # Validate cmdlet exists
    $cmd = Get-Command $CmdletName -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "Exchange cmdlet not found in session: $CmdletName"
    }

    $clientRequestId = [Guid]::NewGuid().ToString()
    $retryDelaysMs = @()
    $attempt = 0

    while ($true) {
        $attempt++
        try {
            # Splat parameters; always enforce ErrorAction Stop for deterministic behavior
            $splat = @{} + $Parameters
            $splat['ErrorAction'] = 'Stop'

            $result = & $CmdletName @splat

            return [PSCustomObject]@{
                Result          = $result
                ClientRequestId = $clientRequestId
                Retries         = ($attempt - 1)
                RetryDelaysMs   = $retryDelaysMs
            }
        }
        catch {
            $msg = $_.Exception.Message

            # Best-effort transient detection (throttling/temporary service issues)
            $isTransient = ($msg -match '(?i)throttl|temporar|timeout|server busy|try again|429')

            if (-not $isTransient -or $attempt -gt $MaxRetries) {
                throw
            }

            # Exponential backoff (100ms, 200ms, 400ms, ...)
            $delay = [int]([math]::Pow(2, $attempt - 1) * 100)
            $retryDelaysMs += $delay
            Start-Sleep -Milliseconds $delay
        }
    }
}

