#!/bin/sh
set -eu
# psql variables quote credentials as SQL literals; never interpolate into SQL.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 \
  --set iam_password="$IAM_DB_PASSWORD" --set payment_password="$PAYMENT_DB_PASSWORD" --set ledger_password="$LEDGER_DB_PASSWORD" \
  --set settlement_password="$SETTLEMENT_DB_PASSWORD" --set reconciliation_password="$RECONCILIATION_DB_PASSWORD" <<'SQL'
CREATE ROLE iam LOGIN PASSWORD :'iam_password';
CREATE ROLE payment LOGIN PASSWORD :'payment_password';
CREATE ROLE ledger LOGIN PASSWORD :'ledger_password';
CREATE ROLE settlement LOGIN PASSWORD :'settlement_password';
CREATE ROLE reconciliation LOGIN PASSWORD :'reconciliation_password';
CREATE DATABASE aipay_iam OWNER iam;
CREATE DATABASE aipay_payment OWNER payment;
CREATE DATABASE aipay_ledger OWNER ledger;
CREATE DATABASE aipay_settlement OWNER settlement;
CREATE DATABASE aipay_reconciliation OWNER reconciliation;
REVOKE CONNECT ON DATABASE aipay_iam FROM PUBLIC;
REVOKE CONNECT ON DATABASE aipay_payment FROM PUBLIC;
REVOKE CONNECT ON DATABASE aipay_ledger FROM PUBLIC;
REVOKE CONNECT ON DATABASE aipay_settlement FROM PUBLIC;
REVOKE CONNECT ON DATABASE aipay_reconciliation FROM PUBLIC;
GRANT CONNECT ON DATABASE aipay_iam TO iam;
GRANT CONNECT ON DATABASE aipay_payment TO payment;
GRANT CONNECT ON DATABASE aipay_ledger TO ledger;
GRANT CONNECT ON DATABASE aipay_settlement TO settlement;
GRANT CONNECT ON DATABASE aipay_reconciliation TO reconciliation;
SQL
