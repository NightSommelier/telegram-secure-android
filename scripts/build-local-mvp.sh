#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
java_home=${JAVA_HOME:-}
if [[ -z "$java_home" || ! -x "$java_home/bin/java" ]]; then
    if [[ -x /nix/store/x92dxglx7ziz2sc3wfvcyl6v2n34w4c4-openjdk-21.0.12.1+1/bin/java ]]; then
        java_home=/nix/store/x92dxglx7ziz2sc3wfvcyl6v2n34w4c4-openjdk-21.0.12.1+1
    elif [[ -x /nix/store/r5yyzs1n6hrs3n6kjmxlf8dwynbif5mq-openjdk-21.0.12.1+1/bin/java ]]; then
        java_home=/nix/store/r5yyzs1n6hrs3n6kjmxlf8dwynbif5mq-openjdk-21.0.12.1+1
    fi
fi
android_sdk=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}
if [[ -z "$android_sdk" && -f "$project_dir/local.properties" ]]; then
    android_sdk=$(sed -n 's/^sdk\.dir=//p' "$project_dir/local.properties" | head -n 1 | sed 's#\\:#:#g')
fi
gradle_bin="$project_dir/gradlew"

test -x "$java_home/bin/java"
test -x "$gradle_bin"

export JAVA_HOME="$java_home"
export ANDROID_HOME="$android_sdk"
export ANDROID_SDK_ROOT="$android_sdk"
export ANDROID_AAPT2_OVERRIDE="$android_sdk/build-tools/35.0.0/aapt2"
export PATH="$JAVA_HOME/bin:$PATH"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-/tmp/telegram-fork-secure-gradle}"

cd "$project_dir"
./scripts/check-local-mvp.sh

apk="$project_dir/TMessagesProj_App/build/outputs/apk/afat/debug/app.apk"
rm -f "$apk"
"$gradle_bin" :TMessagesProj_App:assembleAfatDebug --no-daemon --console=plain \
  -PLOCAL_MVP_ABI=arm64-v8a \
  -PLOCAL_MVP_RELEASE_SIGNING=true \
  "-Pandroid.aapt2FromMavenOverride=$ANDROID_AAPT2_OVERRIDE"
test -f "$apk"
printf 'APK ready: %s\n' "$apk"
