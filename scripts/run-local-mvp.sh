#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
package_name=ua.securechat.telegram

if [[ $# -gt 1 ]]; then
    printf 'Usage: ./scripts/run-local-mvp.sh [adb-serial]\n' >&2
    exit 2
fi

if [[ $# -eq 1 ]]; then
    serial=$1
else
    mapfile -t devices < <(adb devices | awk 'NR > 1 && $2 == "device" { print $1 }')
    if [[ ${#devices[@]} -ne 1 ]]; then
        printf 'Connect exactly one authorized Android device, or pass its serial explicitly.\n' >&2
        adb devices >&2
        exit 1
    fi
    serial=${devices[0]}
fi

"$project_dir/scripts/build-local-mvp.sh"
"$project_dir/scripts/install-local-mvp.sh" "$serial"
adb -s "$serial" shell monkey -p "$package_name" 1 >/dev/null
printf 'Telegram Fork-Secure is running on %s.\n' "$serial"
