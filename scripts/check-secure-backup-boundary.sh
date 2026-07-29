#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$project_dir/TMessagesProj/src/main/AndroidManifest.xml"
agent="$project_dir/TMessagesProj/src/main/java/org/telegram/messenger/BackupAgent.java"

fail() {
    printf 'SECURE BACKUP BOUNDARY FAILED: %s\n' "$1" >&2
    exit 1
}

rg -q 'android:backupAgent="\.BackupAgent"' "$manifest" \
    || fail "the manifest no longer uses the reviewed custom BackupAgent"

helper_count=$(rg -c 'new [A-Za-z]+BackupHelper\(' "$agent" || true)
[[ "$helper_count" = 1 ]] \
    || fail "BackupAgent must construct exactly one explicit helper"

rg -q 'new SharedPreferencesBackupHelper\(this, "saved_tokens", "saved_tokens_login"\)' "$agent" \
    || fail "BackupAgent preference allowlist changed"

add_count=$(rg -c 'addHelper\(' "$agent" || true)
[[ "$add_count" = 1 ]] \
    || fail "BackupAgent must register exactly one helper"

if rg -q \
        'telegram_secure_overlay_state|telegram_secure_chat_state|fork-secure|SecureOverlay' \
        "$agent"; then
    fail "Fork-Secure state appeared in Android BackupAgent"
fi

printf 'OK: Android BackupAgent excludes Fork-Secure state\n'
