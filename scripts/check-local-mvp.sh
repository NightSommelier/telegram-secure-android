#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
sdk_dir=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}

if [[ -z "$sdk_dir" && -f "$project_dir/local.properties" ]]; then
    sdk_dir=$(sed -n 's/^sdk\.dir=//p' "$project_dir/local.properties" | head -n 1 | sed 's#\\:#:#g')
fi

missing=0
check() {
    if [[ "$1" ]]; then
        printf 'OK: %s\n' "$2"
    else
        printf 'MISSING: %s\n' "$2"
        missing=1
    fi
}

java_major=""
if command -v java >/dev/null 2>&1; then
    java_major=$(java -version 2>&1 | sed -n 's/.*version "\([0-9][0-9]*\).*/\1/p' | head -n 1)
fi
check "$(test "$java_major" = 17 && printf yes)" "Java 17 on PATH"
check "$(command -v adb)" "adb on PATH"
check "${sdk_dir:+yes}" "Android SDK path (ANDROID_SDK_ROOT, ANDROID_HOME, or local.properties)"

if [[ -n "$sdk_dir" ]]; then
    check "$(test -d "$sdk_dir/platforms/android-35" && printf yes)" "Android platform 35"
    check "$(test -x "$sdk_dir/build-tools/35.0.0/aapt2" && printf yes)" "Android build-tools 35.0.0"
    check "$(test -d "$sdk_dir/ndk/27.2.12479018" && printf yes)" "NDK 27.2.12479018"
    cmake_dir=$(sed -n 's/^cmake\.dir=//p' "$project_dir/local.properties" 2>/dev/null | tail -n 1 | sed 's#\\:#:#g')
    check "$(test -d "$sdk_dir/cmake/3.22.1" || test -d "${cmake_dir:-/nonexistent}" && printf yes)" "CMake 3.22.1"
fi

check "$(test -f "$project_dir/local.properties" && rg -q '^TELEGRAM_API_ID=[1-9][0-9]*$' "$project_dir/local.properties" && printf yes)" "TELEGRAM_API_ID in local.properties"
check "$(test -f "$project_dir/local.properties" && rg -q '^TELEGRAM_API_HASH=[0-9A-Fa-f]{32}$' "$project_dir/local.properties" && printf yes)" "TELEGRAM_API_HASH in local.properties"

if (( missing )); then
    exit 1
fi
