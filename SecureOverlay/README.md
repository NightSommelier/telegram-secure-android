# SecureOverlay

This Android library is the isolated boundary for Telegram Secure functionality.

It intentionally has no dependency on `TMessagesProj`, TDLib/MTProto code, Telegram message transport, crypto libraries or key material. It currently exposes only the UI/security state contract.

Before the module receives carrier parsing, identity/session code or an upstream message integration adapter, the review package at `../docs/protocol-review/` (including its written decision) and `docs/secure-overlay-protocol-v1.md` must complete independent cryptographic review, and the acceptance gates in `FORK.md` must be satisfied.
