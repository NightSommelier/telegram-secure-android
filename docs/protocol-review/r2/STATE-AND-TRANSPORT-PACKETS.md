# External decision packets

## Telegram boundary packet — IR3

**Owner:** Telegram integration owner (unassigned)
**Status:** OPEN

Acceptance requires two isolated test accounts and recorded TDLib evidence
for: account-scoped data directories; authenticated inbound account/chat/sender
and durable message/update identifiers; update ordering/deduplication; logout
deletion; and each ambiguous-submit path yielding `SEND_OUTCOME_UNKNOWN`.
The owner must state whether Telegram policy/API permits the reserved carrier
and provide versioned API evidence. No feasibility result is inferred here.

## Secure/fallback UX packet — IR6

**Owners:** Product owner and legal owner (both unassigned)
**Status:** OPEN

Acceptance requires written approval of the carrier marker, visible rejected
carrier state, blocking warnings, no-plaintext-fallback behavior, explicit
leave-secure action, draft discard copy, accessibility treatment, notification
copy, and screenshots of the accepted flows. The packet must name supported
jurisdictions/policy constraints and link usability testing.

## Keystore/storage packet

**Owner:** Android security owner (unassigned)
**Status:** OPEN

Acceptance requires physical-device results covering hardware availability,
authentication timeout, biometric/PIN changes, key invalidation, restore,
reinstall, corruption, rollback, process death at each transaction boundary,
and reset-marker persistence. It must choose an authenticated transactional
store and document its migration/backup policy.
