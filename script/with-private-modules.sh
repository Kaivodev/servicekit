#!/bin/sh
# Use an environment-only read token without persisting it to Git configuration.
set -eu

if [ -z "${AIPAY_MODULES_TOKEN:-}" ]; then
  echo "Set AIPAY_MODULES_TOKEN with read-only Contents access to aipay-dev/observability." >&2
  exit 1
fi
if [ "$#" -eq 0 ]; then
  echo "Usage: with-private-modules.sh command [arguments...]" >&2
  exit 1
fi

umask 077
auth_dir=$(mktemp -d "${TMPDIR:-/tmp}/aipay-module-auth.XXXXXX")
trap 'rm -r -- "$auth_dir"' EXIT
trap 'exit 130' HUP INT TERM
cat > "$auth_dir/credential" <<'HELPER'
#!/bin/sh
[ "${1:-}" = get ] || exit 0
protocol= host= repo_path=
while IFS='=' read -r key value; do
  case "$key" in
    protocol) protocol=$value ;;
    host) host=$value ;;
    path) repo_path=$value ;;
  esac
done
[ "$protocol" = https ] && [ "$host" = github.com ] || exit 0
case "$repo_path" in
  aipay-dev/observability|aipay-dev/observability.git)
    printf 'username=x-access-token\npassword=%s\n' "$AIPAY_MODULES_TOKEN" ;;
esac
HELPER
chmod 700 "$auth_dir/credential"

config_count=${GIT_CONFIG_COUNT:-0}
case "$config_count" in ''|*[!0-9]*) echo "Invalid GIT_CONFIG_COUNT" >&2; exit 1 ;; esac
export "GIT_CONFIG_KEY_${config_count}=credential.helper" "GIT_CONFIG_VALUE_${config_count}="
config_count=$((config_count + 1))
export "GIT_CONFIG_KEY_${config_count}=credential.useHttpPath" "GIT_CONFIG_VALUE_${config_count}=true"
config_count=$((config_count + 1))
export "GIT_CONFIG_KEY_${config_count}=credential.helper" "GIT_CONFIG_VALUE_${config_count}=!\"$auth_dir/credential\""
export GIT_CONFIG_COUNT=$((config_count + 1))
export GIT_TERMINAL_PROMPT=0
export GOPRIVATE="${GOPRIVATE:+${GOPRIVATE},}github.com/aipay-dev/*"
"$@"
