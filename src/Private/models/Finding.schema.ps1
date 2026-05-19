Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ValidSeverities = @('Critical','High','Medium','Informational')
$script:ValidStatuses   = @('Pass','Fail','NotAssessed')
$script:ValidSSV        = @('Passes','NotFlagged','Partial')

function New-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $CheckId,
        [Parameter(Mandatory)][string]   $RunId,
        [Parameter(Mandatory)][string]   $Title,
        [Parameter(Mandatory)][string]   $Category,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Informational')] [string] $Severity,
        [Parameter(Mandatory)][ValidateRange(0,100)] [int] $RiskScore,
        [Parameter(Mandatory)][ValidateSet('Passes','NotFlagged','Partial')] [string] $SecureScoreVisibility,
        [Parameter(Mandatory)][ValidateSet('Pass','Fail','NotAssessed')] [string] $Status,
        [Parameter()][hashtable] $Evidence = @{},
        [Parameter(Mandatory)][string]   $GraphEndpoint,
        [Parameter(Mandatory)][bool]     $SupportsRemediation,
        [Parameter()][string]            $ErrorMessage = $null
    )

    if ($null -eq $Evidence) { $Evidence = @{} }
    $shortId = [System.Guid]::NewGuid().ToString('N').Substring(0,8).ToUpper()

    $obj = [PSCustomObject]@{
        id                    = "FIND-$CheckId-$shortId"
        runId                 = $RunId
        checkId               = $CheckId
        title                 = $Title
        category              = $Category
        severity              = $Severity
        riskScore             = $RiskScore
        secureScoreVisibility = $SecureScoreVisibility
        status                = $Status
        evidence              = $Evidence
        graphEndpoint         = $GraphEndpoint
        timestampUtc          = [System.DateTime]::UtcNow.ToString('o')
        supportsRemediation   = $SupportsRemediation
        error                 = if ($ErrorMessage) { [PSCustomObject]@{ message = $ErrorMessage } } else { $null }
    }
    return $obj
}

function Assert-FindingValid {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Finding)

    $required = @('id','runId','checkId','title','category','severity','riskScore',
                  'secureScoreVisibility','status','graphEndpoint','timestampUtc','supportsRemediation')
    foreach ($field in $required) {
        $val = $Finding.PSObject.Properties[$field]
        if ($null -eq $val -or $null -eq $val.Value) {
            throw "Finding missing required field: $field"
        }
    }
    if ($Finding.severity -notin $script:ValidSeverities) {
        throw "Finding.severity invalid: $($Finding.severity)"
    }
    if ($Finding.status -notin $script:ValidStatuses) {
        throw "Finding.status invalid: $($Finding.status)"
    }
    if ($Finding.secureScoreVisibility -notin $script:ValidSSV) {
        throw "Finding.secureScoreVisibility invalid: $($Finding.secureScoreVisibility)"
    }
    if ($Finding.riskScore -lt 0 -or $Finding.riskScore -gt 100) {
        throw "Finding.riskScore out of range 0-100: $($Finding.riskScore)"
    }
}
