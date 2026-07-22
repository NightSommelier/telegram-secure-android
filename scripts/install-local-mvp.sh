#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
serial=${1:?Usage: ./scripts/install-local-mvp.sh <adb-serial>}
apk="$project_dir/TMessagesProj_App/build/outputs/apk/afat/debug/app.apk"

test -f "$apk" || {
    printf 'APK is missing; run ./scripts/build-local-mvp.sh first.\n' >&2
    exit 1
}

adb -s "$serial" install -r "$apk"
