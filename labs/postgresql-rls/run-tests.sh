#!/usr/bin/env sh
set -eu

lab_root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
keep=false
if [ "${1:-}" = "--keep" ]; then
  keep=true
fi
: "${POSTGRES_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
export POSTGRES_PASSWORD
command -v docker >/dev/null 2>&1 || { echo 'Docker CLI is required.' >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo 'Node.js is required for the pooled-client integration test.' >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo 'npm is required for the pooled-client integration test.' >&2; exit 1; }


cleanup() {
  if [ "$keep" = false ]; then
    docker compose --project-directory "$lab_root" down --volumes --remove-orphans
  fi
}
trap cleanup EXIT INT TERM

run_sql_test() {
  test_file=$1
  docker compose --project-directory "$lab_root" exec -T postgres \
    psql -v ON_ERROR_STOP=1 -U postgres -d tenant_lab -f /dev/stdin \
    < "$lab_root/tests/$test_file"
}

npm --prefix "$lab_root" ci --ignore-scripts
docker compose --project-directory "$lab_root" up --detach --wait
run_sql_test rls-tests.sql
run_sql_test boundary-tests.sql
run_sql_test catalog-tests.sql
node "$lab_root/tests/pool-tests.js"
