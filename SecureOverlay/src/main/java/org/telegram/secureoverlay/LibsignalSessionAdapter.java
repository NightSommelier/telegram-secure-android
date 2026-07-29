package org.telegram.secureoverlay;

import org.signal.libsignal.protocol.SessionBuilder;
import org.signal.libsignal.protocol.SessionCipher;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.message.CiphertextMessage;
import org.signal.libsignal.protocol.message.PreKeySignalMessage;
import org.signal.libsignal.protocol.message.SignalMessage;
import org.signal.libsignal.protocol.state.PreKeyBundle;
import org.signal.libsignal.protocol.state.SignalProtocolStore;

/**
 * Narrow, transport-free boundary around libsignal's 1:1 session API.
 *
 * <p>This class deliberately neither parses Telegram carriers nor persists
 * state. Callers must supply a durable {@link SignalProtocolStore} before a
 * secure chat can use it. Unknown or malformed message types fail closed; no
 * plaintext fallback is available from this API.</p>
 */
public final class LibsignalSessionAdapter {
    public static final int MESSAGE_TYPE_PRE_KEY = CiphertextMessage.PREKEY_TYPE;
    public static final int MESSAGE_TYPE_WHISPER = CiphertextMessage.WHISPER_TYPE;

    private final SignalProtocolStore store;
    private final SignalProtocolAddress localAddress;

    public LibsignalSessionAdapter(SignalProtocolStore store, SignalProtocolAddress localAddress) {
        this.store = store;
        this.localAddress = localAddress;
    }

    public void establish(SignalProtocolAddress remoteAddress, PreKeyBundle remoteBundle)
            throws Exception {
        new SessionBuilder(store, remoteAddress).process(remoteBundle);
    }

    public EncryptedMessage encrypt(SignalProtocolAddress remoteAddress, byte[] plaintext)
            throws Exception {
        CiphertextMessage ciphertext = new SessionCipher(store, remoteAddress)
                .encrypt(plaintext);
        int type = ciphertext.getType();
        if (type != MESSAGE_TYPE_PRE_KEY && type != MESSAGE_TYPE_WHISPER) {
            throw new IllegalStateException("libsignal returned unsupported ciphertext type: " + type);
        }
        return new EncryptedMessage(type, ciphertext.serialize());
    }

    public byte[] decrypt(SignalProtocolAddress remoteAddress, EncryptedMessage encrypted)
            throws Exception {
        SessionCipher cipher = new SessionCipher(store, remoteAddress);
        if (encrypted.type == MESSAGE_TYPE_PRE_KEY) {
            return cipher.decrypt(new PreKeySignalMessage(encrypted.serialized));
        }
        if (encrypted.type == MESSAGE_TYPE_WHISPER) {
            return cipher.decrypt(new SignalMessage(encrypted.serialized));
        }
        throw new IllegalArgumentException("unsupported secure ciphertext type");
    }

    public static final class EncryptedMessage {
        public final int type;
        public final byte[] serialized;

        public EncryptedMessage(int type, byte[] serialized) {
            if (serialized == null || serialized.length == 0) {
                throw new IllegalArgumentException("secure ciphertext must not be empty");
            }
            this.type = type;
            this.serialized = serialized.clone();
        }
    }
}
