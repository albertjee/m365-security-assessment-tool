Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-WriteAllowed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Assess','Remediate')] [string] $Mode,
        [Parameter(Mandatory)][ValidateSet('Certificate','Secret','Delegated')] [string] $AuthMethod,
        [Parameter(Mandatory)][bool] $WhatIf,
        [Parameter(Mandatory)][ValidateSet('Lite','Premium')] [string] $Edition
    )
    return ($Mode -eq 'Remediate') -and
           ($AuthMethod -eq 'Delegated') -and
           (-not $WhatIf) -and
           ($Edition -eq 'Premium')
}
