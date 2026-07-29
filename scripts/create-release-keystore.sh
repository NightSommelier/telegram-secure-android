#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
keystore_dir="$project_dir/keystore"
keystore_file="$keystore_dir/telegram-fork-secure-release.p12"
properties_file="$project_dir/signing.properties"
key_alias=telegram_fork_secure

if [[ -e "$keystore_file" || -e "$properties_file" ]]; then
    printf 'Release signing files already exist; refusing to overwrite them.\n' >&2
    exit 1
fi

command -v keytool >/dev/null || {
    printf 'keytool is required (install or expose JDK 21 first).\n' >&2
    exit 1
}

read -r -s -p 'New keystore password (at least 12 characters): ' password
printf '\n'
if [[ ${#password} -lt 12 ]]; then
    printf 'Password must contain at least 12 characters.\n' >&2
    exit 1
fi
read -r -s -p 'Repeat password: ' password_again
printf '\n'
if [[ "$password" != "$password_again" ]]; then
    printf 'Passwords do not match.\n' >&2
    exit 1
fi
unset password_again

umask 077
mkdir -p "$keystore_dir"
keytool -genkeypair \
    -storetype PKCS12 \
    -keystore "$keystore_file" \
    -storepass "$password" \
    -keypass "$password" \
    -alias "$key_alias" \
    -keyalg RSA \
    -keysize 4096 \
    -validity 10000 \
    -dname 'CN=Telegram Fork-Secure, OU=Local MVP, O=SecureChat, C=UA'

printf 'RELEASE_STORE_FILE=keystore/telegram-fork-secure-release.p12\nRELEASE_STORE_PASSWORD=%s\nRELEASE_KEY_ALIAS=%s\nRELEASE_KEY_PASSWORD=%s\n' \
    "$password" "$key_alias" "$password" > "$properties_file"
unset password
printf 'Created local release keystore and signing.properties. Back up keystore/ securely before publishing any update.\n'
