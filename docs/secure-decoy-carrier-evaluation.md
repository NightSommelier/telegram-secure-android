# Fork-Secure text-like carrier evaluation

**Status:** design candidate only. The canonical `TGS1:` carrier remains the
default until this mode passes interoperability, corruption, and UX review.

KryptEY demonstrates a “fairytale mode” that compresses its message envelope,
maps every four bits to one of sixteen zero-width Unicode characters, and
appends that payload to visible cover text. Its documentation also reports that
Telegram HTML clipboard conversion can corrupt this form. Fork-Secure can avoid
the clipboard boundary by reading Telegram’s original message string directly,
but it cannot assume that every Telegram operation preserves invisible Unicode.

## Proposed boundary

- Keep the existing authenticated libsignal payload unchanged.
- Treat text-like encoding only as an outer transport representation.
- Use an explicit, canonical version marker; do not scan arbitrary prose for
  accidental zero-width sequences.
- Authenticate the complete carrier mode and visible cover text, so attackers
  cannot replace the decoy sentence without detection.
- Reject truncation, normalization, duplicated markers, unsupported code
  points, excessive expansion, and trailing invisible data.
- A recognized malformed carrier must display a protected-message error and
  must never fall back to visible cover text as the sender’s plaintext.
- Normal `TGS1:` remains available for recovery and interoperability.

## Required Telegram tests

Test send, receive, edit, reply preview, forward, scheduled send, notification,
reaction refresh, search/indexing, copy, export, and official-client display.
Include NFC/NFKC normalization, entity parsing, link previews, server-side
truncation, and clients that remove or reorder zero-width characters.

This mode cannot hide Telegram metadata or reliably defeat traffic analysis.
Visible decoy text may also mislead users of unsupported clients, so the mode
must be opt-in per chat and clearly identified inside Fork-Secure.

Reference: [KryptEY](https://github.com/amnesica/KryptEY), particularly its
documented raw and fairytale message encodings.
