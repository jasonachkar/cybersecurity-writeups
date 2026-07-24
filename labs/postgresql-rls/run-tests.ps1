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

function Invoke-SqlTest {
    param(
        [Parameter(Mandatory)]
        [string]$RelativePath,
        [Parameter(Mandatory)]
        [string]$FailureMessage
    )

    Get-Content -Raw -LiteralPath (Join-Path $labRoot $RelativePath) |
        docker compose --project-directory $labRoot exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d tenant_lab -f /dev/stdin
    if ($LASTEXITCODE -ne 0) {
        throw $FailureMessage
    }
}

try {
    docker compose --project-directory $labRoot up --detach --wait
    if ($LASTEXITCODE -ne 0) {
        throw 'PostgreSQL container failed to become healthy.'
    }

    Invoke-SqlTest -RelativePath 'tests/rls-tests.sql' -FailureMessage 'RLS runtime tests failed.'
    Invoke-SqlTest -RelativePath 'tests/boundary-tests.sql' -FailureMessage 'RLS boundary tests failed.'
    Invoke-SqlTest -RelativePath 'tests/catalog-tests.sql' -FailureMessage 'RLS catalog tests failed.'
}
finally {
    if (-not $Keep) {
        docker compose --project-directory $labRoot down --volumes --remove-orphans
    }
}
