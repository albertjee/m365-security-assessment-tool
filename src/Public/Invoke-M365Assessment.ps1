Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-M365Assessment {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Assess','Remediate')]
        [string] $Mode,

        [Parameter(Mandatory)]
        [ValidateSet('Certificate','Secret','Delegated')]
        [string] $AuthMethod,

        [Parameter(Mandatory)]
        [string] $TenantId,

        [Parameter(Mandatory)]
        [string] $AppId,

        [Parameter()]
        [ValidateSet('Lite','Premium')]
        [string] $Edition = 'Lite',

        [Parameter()]
        [string[]] $IncludeChecks = @(),

        [Parameter()]
        [string] $OutputPath = $null,

        [Parameter()]
        [switch] $Force
    )

    $pipelineParams = @{
        Mode          = $Mode
        AuthMethod    = $AuthMethod
        TenantId      = $TenantId
        AppId         = $AppId
        Edition       = $Edition
        IncludeChecks = $IncludeChecks
        OutputPath    = $OutputPath
        WhatIf        = [bool]$WhatIfPreference
        Force         = $Force.IsPresent
    }

    Start-AssessmentPipeline -Params $pipelineParams
}
