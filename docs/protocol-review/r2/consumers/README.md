# Test-only consumers

The Go and Kotlin consumers were written separately and only parse/verify CFS,
Ed25519 signatures, X25519/HKDF/confirmations, CFS envelope AD, and the
XChaCha20-Poly1305 fixture. They contain no Android, Telegram, key-storage,
production handshake, or ratchet implementation.

Run Go from `go/` with `go test ./...`. Compile Kotlin with JDK 17 as stated
in its source header. The Kotlin source uses only JDK APIs; a JDK 17/Nix
environment is required for the requested Gradle validation.
