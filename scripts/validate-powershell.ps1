[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$parseErrors = @()
Get-ChildItem -LiteralPath $repoRoot -Recurse -File -Filter '*.ps1' |
    Where-Object { $_.FullName -notmatch '[\\/]node_modules[\\/]' } |
    ForEach-Object {
        $tokens = $null
        $fileErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $_.FullName,
            [ref]$tokens,
            [ref]$fileErrors
        )
        $parseErrors += $fileErrors
    }

if ($parseErrors.Count -gt 0) {
    $parseErrors | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output 'PowerShell syntax validation passed.'
