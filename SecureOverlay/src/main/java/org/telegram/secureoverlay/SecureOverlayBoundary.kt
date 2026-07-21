package org.telegram.secureoverlay

/**
 * Deliberately transport-free boundary for the Telegram Secure overlay.
 *
 * This module is a structural placeholder only. It owns no keys, parses no
 * carriers and must not be connected to Telegram message sending/receiving
 * until docs/secure-overlay-protocol-v1.md has passed independent review.
 */
object SecureOverlayBoundary {
    const val PROTOCOL_REVIEW_REQUIRED = true
}

/** States the Telegram UI integration must render explicitly once approved. */
enum class SecureConversationState {
    Normal,
    CapabilityRequested,
    CapabilityConfirmed,
    IdentityPending,
    Verified,
    SessionEstablishing,
    SecureActive,
    KeyChanged,
    DeviceChanged,
    SessionInvalid,
    UnsupportedVersion,
    AuthenticationFailed,
    StorageFailed,
    KeystoreFailed,
}
