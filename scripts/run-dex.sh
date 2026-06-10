#!/usr/bin/env bash
# Launch Dex (the OIDC provider) for the experiment.
#
#   ./scripts/run-dex.sh            # static passwords (default) -> dex/config.yaml
#   ./scripts/run-dex.sh static     # same as above, explicit
#   ./scripts/run-dex.sh ldap       # LDAP backend            -> dex/config-ldap.yaml
#
# Finds the dex binary on PATH or in ~/go/bin. See README.md "Prerequisites" for
# how to install Dex (it is NOT a plain `go install ...@latest`).
set -euo pipefail

mode="${1:-static}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$mode" in
  static) config="$repo_root/dex/config.yaml" ;;
  ldap)   config="$repo_root/dex/config-ldap.yaml" ;;
  -h|--help|help)
    sed -n '2,9p' "$0"
    exit 0
    ;;
  *)
    echo "usage: $0 [static|ldap]" >&2
    exit 2
    ;;
esac

if command -v dex >/dev/null 2>&1; then
  dex_bin="$(command -v dex)"
elif [ -x "$HOME/go/bin/dex" ]; then
  dex_bin="$HOME/go/bin/dex"
else
  echo "error: dex binary not found on PATH or in ~/go/bin." >&2
  echo "See README.md \"Prerequisites\" for how to build it." >&2
  exit 1
fi

echo "Starting Dex ($mode) with $config"
exec "$dex_bin" serve "$config"
