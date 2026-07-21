# Blocking review issues

None may be decided implicitly during implementation.

1. Name and pin the maintained Signal Double Ratchet implementation, Android binding, license, CVE owner, known-answer evidence and adapter audit scope.
2. Independently review handshake construction, CFS encoding, the 256-message bound, nonce source, session expiry and labels.
3. Confirm Telegram can provide authenticated inbound peer/chat provenance and a durable-send boundary without changing TDLib or MTProto semantics.
4. Define Keystore hardware/authentication policy and invalidation, reinstall, rollback and corruption matrix.
5. Add the full bundle/control-signature, four-DH handshake/transcript/confirmation and complete-envelope vectors listed in `FIXTURE-COVERAGE.md`, then verify every vector with two independently written consumers before claiming interoperability.
6. Obtain legal/product approval for the reserved carrier marker and visible secure/fallback behavior.
