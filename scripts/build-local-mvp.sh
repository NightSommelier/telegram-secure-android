#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
java_home=/nix/store/v3n6jl0sxn64g97c5kxzriwj4fv6qnjh-openjdk-21.0.12+2
android_sdk=/nix/store/9w9ynwf0j4f2z18i3x5dwic9d73qv3n4-androidsdk/libexec/android-sdk
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
