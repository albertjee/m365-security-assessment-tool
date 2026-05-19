Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$privatePath = Join-Path $PSScriptRoot 'src\Private'
$publicPath  = Join-Path $PSScriptRoot 'src\Public'

# Dot-source all Private files except checks/ — Auditor loads checks in isolation
Get-ChildItem -Path $privatePath -Recurse -Filter '*.ps1' |
    Where-Object { $_.FullName -notmatch '\\checks\\' } |
    ForEach-Object { . $_.FullName }

Get-ChildItem -Path $publicPath -Recurse -Filter '*.ps1' | ForEach-Object { . $_.FullName }

. (Join-Path $PSScriptRoot 'templates\report.html.ps1')
