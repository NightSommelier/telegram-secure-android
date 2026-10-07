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
    public static final int MESSAGE_TYPE_SENDERKEY = CiphertextMessage.SENDERKEY_TYPE;

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

    public byte[] createGroupDistributionMessage(java.util.UUID distributionId) {
        org.signal.libsignal.protocol.groups.GroupSessionBuilder builder =
                new org.signal.libsignal.protocol.groups.GroupSessionBuilder(store);
        return builder.create(localAddress, distributionId).serialize();
    }

    public void processGroupDistributionMessage(
            SignalProtocolAddress senderAddress, byte[] serializedDistributionMessage)
            throws Exception {
        org.signal.libsignal.protocol.groups.GroupSessionBuilder builder =
                new org.signal.libsignal.protocol.groups.GroupSessionBuilder(store);
        builder.process(
                senderAddress,
                new org.signal.libsignal.protocol.message.SenderKeyDistributionMessage(
                        serializedDistributionMessage));
    }

    public EncryptedMessage encryptGroup(java.util.UUID distributionId, byte[] plaintext)
            throws Exception {
        if (store.loadSenderKey(localAddress, distributionId) == null) {
            org.signal.libsignal.protocol.groups.GroupSessionBuilder builder =
                    new org.signal.libsignal.protocol.groups.GroupSessionBuilder(store);
            builder.create(localAddress, distributionId);
        }
        org.signal.libsignal.protocol.groups.GroupCipher groupCipher =
                new org.signal.libsignal.protocol.groups.GroupCipher(store, localAddress);
        CiphertextMessage ciphertext = groupCipher.encrypt(distributionId, plaintext);
        return new EncryptedMessage(MESSAGE_TYPE_SENDERKEY, ciphertext.serialize());
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
        if (encrypted.type == MESSAGE_TYPE_SENDERKEY) {
            org.signal.libsignal.protocol.groups.GroupCipher groupCipher =
                    new org.signal.libsignal.protocol.groups.GroupCipher(store, remoteAddress);
            return groupCipher.decrypt(encrypted.serialized);
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
