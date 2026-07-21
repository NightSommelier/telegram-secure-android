# Fixture coverage matrix

This matrix prevents the current small fixture set from being mistaken for interoperability approval. `Present` means a machine-readable input/expected-outcome fixture exists; `Required before approval` means a reviewer must either add it or explicitly accept the reason it is absent.

| Requirement | Current evidence | Required before approval |
|---|---|---|
| CFS canonical identity core | Present | Valid signature over full bundle and rotation case |
| Ed25519 primitive | RFC 8032 vector | Bundle and control-message signature vectors |
| Capability valid/expired flow | Present | Full request/response CFS and signed response |
| X25519 | No dedicated vector | Four-DH handshake vector with public/private inputs |
| Transcript / HKDF / confirmations | Synthetic KDF vector | Full init/response CFS, transcript and both confirmations |
| XChaCha20-Poly1305 | Present | Complete TGSE CFS, computed AD and decrypt success case |
| Replay / order / AEAD failure | Negative outcomes present | Ratchet-library adapter fixtures after backend selection |
| Storage / Keystore | Negative outcomes present | Transaction/crash/rollback integration fixtures after storage design |

The missing items are deliberate approval blockers, not permission to invent values in an implementation. They are tracked in `OPEN-ISSUES.md`.
