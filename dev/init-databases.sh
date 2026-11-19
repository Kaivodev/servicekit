#!/bin/sh
# Used both by the official Postgres entrypoint and native/stack.py.
set -eu
export PGUSER="${PGUSER:-${POSTGRES_USER:-postgres}}" PGDATABASE="${PGDATABASE:-postgres}"
: "${STACK_ID:?missing private provisioning environment}"
# One session lock covers preflight and all DDL. psql reads secrets from its
# environment. Do not echo the expanded SQL or pass passwords as argv.
{
  cat <<'SQL'
\set ON_ERROR_STOP on
\set VERBOSITY terse
\getenv stack_id STACK_ID
SELECT pg_advisory_lock(72401212);
CREATE TEMP TABLE dev_roles(name text PRIMARY KEY, pass text);
CREATE TEMP TABLE dev_databases(name text PRIMARY KEY, owner_name text, app_name text);
SQL
  for svc in iam ledger payment reconciliation settlement backend; do
    upper=$(echo "$svc" | tr '[:lower:]' '[:upper:]')
    printf '\\getenv pw %s_DB_PASSWORD\n' "$upper"
    echo "INSERT INTO dev_roles VALUES ('$svc', :'pw');"
    case "$svc" in
      iam|ledger|payment|reconciliation)
        app="${svc}_app"
        printf '\\getenv pw %s_APP_PASSWORD\n' "$upper"
        echo "INSERT INTO dev_roles VALUES ('$app', :'pw');" ;;
      *) app="$svc" ;;
    esac
    echo "INSERT INTO dev_databases VALUES ('aipay_$svc', '$svc', '$app');"
  done
  cat <<'SQL'
SELECT EXISTS (SELECT FROM dev_roles t JOIN pg_roles r ON r.rolname=t.name
 WHERE shobj_description(r.oid,'pg_authid') IS DISTINCT FROM :'stack_id')
 OR EXISTS (SELECT FROM dev_databases t JOIN pg_database d ON d.datname=t.name
 LEFT JOIN pg_roles r ON r.oid=d.datdba
 WHERE r.rolname IS DISTINCT FROM t.owner_name OR shobj_description(r.oid,'pg_authid') IS DISTINCT FROM :'stack_id') AS collision \gset
\if :collision
DO $$ BEGIN RAISE EXCEPTION 'development role or database already belongs to another stack'; END $$;
\endif
BEGIN;
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L',t.name,t.pass) FROM dev_roles t
 WHERE NOT EXISTS (SELECT FROM pg_roles r WHERE r.rolname=t.name) \gexec
SELECT format('COMMENT ON ROLE %I IS %L',name,:'stack_id') FROM dev_roles \gexec
COMMIT;
SELECT format('CREATE DATABASE %I OWNER %I',name,owner_name) FROM dev_databases t
 WHERE NOT EXISTS (SELECT FROM pg_database d WHERE d.datname=t.name) \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC',name) FROM dev_databases \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I',name,app_name) FROM dev_databases \gexec
SQL
} | psql -X -w -q >/dev/null 2>&1 || {
  echo 'Database provisioning failed. Check admin connectivity/permissions and existing role/database ownership; retry with the same prepared state.' >&2
  exit 1
}
