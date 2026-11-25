#!/bin/sh
# Only canned, public arguments are accepted. The simulated API response is
# inherited in memory. Nothing containing Secret data is written to a file.
set -eu
[ "$1 $2 $3 $4 $5" = "shell kaivo-k3s sudo k3s kubectl" ]
shift 5
[ "$1" = "-n" ] && [ "$3" = get ]
ns=$2
shift 3
case "$ns" in
  "${AIPAY_DEMO_NS_BUSINESS:-kaivo-business}") objects=$SEED_TEST_BUSINESS; market=payment-inputs ;;
  "${AIPAY_DEMO_NS_LEDGER:-kaivo-ledger}") objects=$SEED_TEST_LEDGER; market=ledger-inputs ;;
  "${AIPAY_DEMO_NS_RECONCILIATION:-kaivo-reconciliation}") objects=$SEED_TEST_RECON; market=reconciliation-inputs ;;
  "${AIPAY_DEMO_NS_SIM:-kaivo-sim}") objects=$SEED_TEST_SIM; market= ;;
  *) exit 23 ;;
esac
if [ "${SEED_TEST_FAILURE:-}" = "$ns" ]; then
  printf '%s' 'secret-in-kubectl-error' >&2
  exit 1
fi
selector=app.kubernetes.io/managed-by=kaivo-stagingseed
if [ "$1" = secret,configmap ] || [ "$1" = configmap ]; then
  if [ "$SEED_TEST_MODE" = market ]; then
    [ -n "$market" ] && [ "$*" = "configmap -l $selector -o json --field-selector metadata.name=$market" ] || exit 23
  else
    [ "$*" = "secret,configmap -l $selector -o json" ] || exit 23
  fi
  printf '%s\n' "$ns" >> "$SEED_TEST_CALLS"
  printf '%s' "$objects"
  exit 0
fi
while [ "$#" -gt 3 ]; do
  case "$1" in
    secret/backend-private|secret/iam-private|secret/payment-private|secret/ledger-private|secret/reconciliation-private|secret/upstream-sim-private|secret/collection-private|secret/demo-fixtures-private|secret/reconciliation-handoff|configmap/deposit-dataset|configmap/kaivo-signing-public|configmap/backend-inputs|configmap/iam-inputs|configmap/payment-inputs|configmap/notifier-inputs|configmap/ledger-inputs|configmap/reconciliation-inputs) ;;
    *) exit 23 ;;
  esac
  shift
done
[ "$*" = "--ignore-not-found -o name" ]
printf '%s' "${SEED_TEST_COLLISION:-}"
