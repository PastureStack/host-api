#!/usr/bin/env bash
set -euo pipefail

platform_home=${PASTURESTACK_HOME:-${CATTLE_HOME:-/var/lib/pasturestack}}
source "${platform_home}/common/scripts.sh"

cd "$(dirname "$0")"
test -s bin/host-api
version=$(bin/host-api --version)
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "invalid host API version: $version" >&2
    exit 1
fi

install -d -m 0755 "${platform_home}/bin"
temporary="${platform_home}/bin/.host-api.new.$$"
cleanup() {
    rm -f -- "$temporary"
}
trap cleanup EXIT
install -m 0755 bin/host-api "$temporary"
mv -f -- "$temporary" "${platform_home}/bin/host-api"

pids=$(pidof host-api || true)
if [ -n "$pids" ]; then
    kill $pids
    sleep 1
fi

touch "${platform_home}/.pyagent-stamp"
