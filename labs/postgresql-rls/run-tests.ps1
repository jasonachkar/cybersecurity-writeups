[CmdletBinding()]
param(
    [switch]$Keep
)

$ErrorActionPreference = 'Stop'
$labRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker CLI is required.'
}
if (-not $env:POSTGRES_PASSWORD) {
    $env:POSTGRES_PASSWORD = [guid]::NewGuid().ToString('N')
}

try {
    docker compose --project-directory $labRoot up --detach --wait
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL container failed to become healthy.' }

    Get-Content -Raw -LiteralPath (Join-Path $labRoot 'tests/rls-tests.sql') |
        docker compose --project-directory $labRoot exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d tenant_lab -f /dev/stdin
    if ($LASTEXITCODE -ne 0) { throw 'RLS runtime tests failed.' }

    Get-Content -Raw -LiteralPath (Join-Path $labRoot 'tests/catalog-tests.sql') |
        docker compose --project-directory $labRoot exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d tenant_lab -f /dev/stdin
    if ($LASTEXITCODE -ne 0) { throw 'RLS catalog tests failed.' }
}
finally {
    if (-not $Keep) {
        docker compose --project-directory $labRoot down --volumes --remove-orphans
    }
}
