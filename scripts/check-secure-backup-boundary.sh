#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$project_dir/TMessagesProj/src/main/AndroidManifest.xml"
agent="$project_dir/TMessagesProj/src/main/java/org/telegram/messenger/BackupAgent.java"
full_backup="$project_dir/TMessagesProj/src/main/res/xml/full_backup_content.xml"
extraction_rules="$project_dir/TMessagesProj/src/main/res/xml/data_extraction_rules.xml"

fail() {
    printf 'SECURE BACKUP BOUNDARY FAILED: %s\n' "$1" >&2
    exit 1
}

rg -q 'android:backupAgent="\.BackupAgent"' "$manifest" \
    || fail "the manifest no longer uses the reviewed custom BackupAgent"
rg -q 'android:fullBackupContent="@xml/full_backup_content"' "$manifest" \
    || fail "the manifest no longer configures full_backup_content"
rg -q 'android:dataExtractionRules="@xml/data_extraction_rules"' "$manifest" \
    || fail "the manifest no longer configures data_extraction_rules"

helper_count=$(rg -c 'new [A-Za-z]+BackupHelper\(' "$agent" || true)
[[ "$helper_count" = 1 ]] \
    || fail "BackupAgent must construct exactly one explicit helper"

rg -q 'new SharedPreferencesBackupHelper\(this, "saved_tokens", "saved_tokens_login"\)' "$agent" \
    || fail "BackupAgent preference allowlist changed"

add_count=$(rg -c 'addHelper\(' "$agent" || true)
[[ "$add_count" = 1 ]] \
    || fail "BackupAgent must register exactly one helper"

if rg -q \
        'telegram_secure_overlay_state|telegram_secure_chat_state|telegram_secure_overlay_v2|fork-secure|fork_secure|SecureOverlay' \
        "$agent"; then
    fail "Fork-Secure state appeared in Android BackupAgent"
fi

for required_exclude in \
        'path="telegram_secure_overlay_state_v1\.xml"' \
        'path="fork_secure_content_settings\.xml"' \
        'path="fork_secure_saved_messages\.xml"' \
        'path="telegram_secure_overlay_v2\.db"' \
        'path="telegram_secure_overlay_v2\.db-wal"' \
        'path="telegram_secure_overlay_v2\.db-shm"' \
        'path="telegram_secure_overlay_v2\.db-journal"'; do
    rg -q "$required_exclude" "$full_backup" \
        || fail "full_backup_content.xml missing exclusion $required_exclude"
    matches=$(rg -c "$required_exclude" "$extraction_rules" || true)
    [[ "$matches" -ge 2 ]] \
        || fail "data_extraction_rules.xml missing cloud-backup/device-transfer exclusion $required_exclude"
done

printf 'OK: Android BackupAgent and backup XML rules exclude Fork-Secure state\n'
