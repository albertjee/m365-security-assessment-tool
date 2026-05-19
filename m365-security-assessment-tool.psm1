Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$privatePath = Join-Path $PSScriptRoot 'src\Private'
$publicPath  = Join-Path $PSScriptRoot 'src\Public'

Get-ChildItem -Path $privatePath -Recurse -Filter '*.ps1' | ForEach-Object { . $_.FullName }
Get-ChildItem -Path $publicPath  -Recurse -Filter '*.ps1' | ForEach-Object { . $_.FullName }
