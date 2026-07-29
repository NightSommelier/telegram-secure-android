# SecureOverlay

This Android library is the isolated boundary for Telegram Secure functionality.

It intentionally has no dependency on `TMessagesProj`, TDLib/MTProto code or
Telegram message transport. It uses Signal's `libsignal` Android artifact only
inside this module; application code must reach it through the narrow adapter
that will be added here.

The library is AGPLv3. Anyone who receives a build containing it must also be
given the corresponding source code and license notices. This project is a
private-group MVP, not a public product release.
