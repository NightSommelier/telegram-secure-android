package org.telegram.secureoverlay;

import android.content.Context;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Crash-resumable identity-only backup lifecycle.
 *
 * <p>A prepared import does not alter protocol state. Committing atomically replaces the local
 * identity and registration records together with a {@code COMMITTING} marker, then clears all
 * chat gates and creates fresh prekeys and recovery metadata. Startup may safely repeat the latter
 * steps until the marker is removed.</p>
 */
public final class SecureIdentityBackupManager {
    private static final String MARKER = "identity-recovery-import-v1/marker";
    private static final String STAGED = "identity-recovery-import-v1/staged";
    private static final byte MARKER_VERSION = 1;
    private static final byte PREPARED = 1;
    private static final byte COMMITTING = 2;
    private static final byte[] STAGE_MAGIC = new byte[] {'F', 'S', 'I', 'S'};
    private static final int STAGE_VERSION = 1;
    private static final int MAX_STAGE_BYTES = 8192;
    private static final Object LOCK = new Object();

    private SecureIdentityBackupManager() {
    }

    public static final class PreparedImport {
        public final UUID archiveId;
        public final long ownerUserId;
        public final long archivedGeneration;
        public final long restoredGeneration;
        public final long exportedAtUnixSeconds;
        public final String fingerprint;
        public final boolean replacesExistingState;

        PreparedImport(
                SecureIdentityBackupCodec.Payload payload,
                SecureRecoveryGenerationStore.Record recovery,
                boolean replacesExistingState) {
            archiveId = payload.archiveId;
            ownerUserId = payload.ownerUserId;
            archivedGeneration = payload.generation;
            restoredGeneration = recovery.generation;
            exportedAtUnixSeconds = payload.exportedAtUnixSeconds;
            fingerprint = fingerprint(payload.serializedIdentity);
            this.replacesExistingState = replacesExistingState;
        }
    }

    public static final class IdentityInfo {
        public final long generation;
        public final String fingerprint;

        IdentityInfo(long generation, String fingerprint) {
            this.generation = generation;
            this.fingerprint = fingerprint;
        }
    }

    public static IdentityInfo getIdentityInfo(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        Context appContext = context.getApplicationContext();
        synchronized (LOCK) {
            resumeInterruptedImport(appContext);
            SecureChatState chatState = new SecureChatState(appContext);
            SecureRecoveryGenerationStore.Record recovery =
                    new SecureRecoveryGenerationStore(appContext).ensureLocalIdentity(
                            generationForEpoch(chatState.getIdentityEpoch()));
            byte[] serializedIdentity = new KeystoreSignalProtocolStore(appContext)
                    .getIdentityKeyPair()
                    .serialize();
            try {
                return new IdentityInfo(
                        recovery.generation, fingerprint(serializedIdentity));
            } finally {
                Arrays.fill(serializedIdentity, (byte) 0);
            }
        }
    }

    public static byte[] exportArchive(
            Context context, long ownerUserId, char[] password) {
        if (context == null || ownerUserId <= 0) {
            throw new IllegalArgumentException("backup export requires a Telegram owner");
        }
        Context appContext = context.getApplicationContext();
        synchronized (LOCK) {
            resumeInterruptedImport(appContext);
            ensureNoPreparedImport(appContext);
            SecureChatState chatState = new SecureChatState(appContext);
            SecureRecoveryGenerationStore recovery =
                    new SecureRecoveryGenerationStore(appContext);
            SecureRecoveryGenerationStore.Record local = recovery.ensureLocalIdentity(
                    generationForEpoch(chatState.getIdentityEpoch()));
            KeystoreSignalProtocolStore protocol =
                    new KeystoreSignalProtocolStore(appContext);
            SecureIdentityBackupCodec.Payload payload =
                    new SecureIdentityBackupCodec.Payload(
                            nonZeroUuid(),
                            ownerUserId,
                            local.generation,
                            Math.max(1, System.currentTimeMillis() / 1000L),
                            protocol.getLocalRegistrationId(),
                            protocol.getIdentityKeyPair().serialize());
            return SecureIdentityBackupCodec.encrypt(payload, password);
        }
    }

    public static PreparedImport prepareImport(
            Context context,
            long expectedOwnerUserId,
            byte[] archive,
            char[] password) {
        if (context == null || expectedOwnerUserId <= 0) {
            throw new IllegalArgumentException("backup import requires a Telegram owner");
        }
        Context appContext = context.getApplicationContext();
        synchronized (LOCK) {
            resumeInterruptedImport(appContext);
            ensureNoPreparedImport(appContext);
            SecureChatState chatState = new SecureChatState(appContext);
            boolean replacesExistingState =
                    hasExistingSecureState(appContext, chatState);
            SecureIdentityBackupCodec.Payload payload =
                    SecureIdentityBackupCodec.decrypt(archive, password);
            if (payload.ownerUserId != expectedOwnerUserId) {
                throw new SecurityException(
                        "identity backup belongs to a different Telegram account");
            }
            SecureRecoveryGenerationStore recoveryStore =
                    new SecureRecoveryGenerationStore(appContext);
            SecureRecoveryGenerationStore.Record current =
                    recoveryStore.getLocalIdentity();
            long restoredGeneration = increment(payload.generation);
            if (current != null) {
                restoredGeneration = Math.max(restoredGeneration, increment(current.generation));
            }
            SecureRecoveryGenerationStore.Record restoredRecovery =
                    new SecureRecoveryGenerationStore.Record(
                            restoredGeneration, nonZeroUuid());
            byte[] stage = encodeStage(payload, restoredRecovery);
            try {
                Map<String, byte[]> values = new LinkedHashMap<>();
                values.put(STAGED, stage);
                values.put(MARKER, marker(PREPARED));
                new KeystoreEncryptedBlobStore(appContext).putAll(values);
            } catch (KeystoreEncryptedBlobStore.StateStoreException error) {
                throw new IllegalStateException("cannot stage identity backup import", error);
            } finally {
                Arrays.fill(stage, (byte) 0);
            }
            return new PreparedImport(
                    payload, restoredRecovery, replacesExistingState);
        }
    }

    public static PreparedImport getPreparedImport(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        Context appContext = context.getApplicationContext();
        synchronized (LOCK) {
            ImportStage stage = readStage(appContext, PREPARED);
            return stage == null
                    ? null
                    : new PreparedImport(
                            stage.payload,
                            stage.recovery,
                            hasExistingSecureState(
                                    appContext, new SecureChatState(appContext)));
        }
    }

    public static void cancelPreparedImport(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        Context appContext = context.getApplicationContext();
        synchronized (LOCK) {
            byte phase = readMarker(appContext);
            if (phase == COMMITTING) {
                throw new IllegalStateException("identity recovery is already committing");
            }
            try {
                new KeystoreEncryptedBlobStore(appContext).deleteAll(MARKER, STAGED);
            } catch (KeystoreEncryptedBlobStore.StateStoreException error) {
                throw new IllegalStateException("cannot cancel staged identity recovery", error);
            }
        }
    }

    public static PreparedImport commitPreparedImport(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        Context appContext = context.getApplicationContext();
        synchronized (LOCK) {
            ImportStage stage = requireStage(appContext, PREPARED);
            boolean replacedExistingState = hasExistingSecureState(
                    appContext, new SecureChatState(appContext));
            Map<String, byte[]> transaction = new LinkedHashMap<>();
            transaction.put(MARKER, marker(COMMITTING));
            KeystoreSignalProtocolStore.replaceIdentityForRecovery(
                    appContext,
                    stage.payload.serializedIdentity,
                    stage.payload.registrationId,
                    transaction);
            completeCommittingImport(appContext, stage);
            return new PreparedImport(
                    stage.payload, stage.recovery, replacedExistingState);
        }
    }

    /**
     * Completes a crash-interrupted committing import. A merely prepared import is left untouched
     * until the user confirms or cancels it.
     */
    public static boolean resumeInterruptedImport(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        Context appContext = context.getApplicationContext();
        synchronized (LOCK) {
            byte phase = readMarker(appContext);
            if (phase == 0 || phase == PREPARED) {
                return false;
            }
            ImportStage stage = requireStage(appContext, COMMITTING);
            completeCommittingImport(appContext, stage);
            return true;
        }
    }

    private static void completeCommittingImport(
            Context context, ImportStage stage) {
        new SecureChatState(context)
                .resetForRecoveredIdentity(stage.recovery.generation);
        new SecureRecoveryGenerationStore(context)
                .replaceLocalAfterRecovery(stage.recovery);
        new KeystoreSignalProtocolStore(context).ensureLocalPreKeyMaterial();
        try {
            new KeystoreEncryptedBlobStore(context).deleteAll(MARKER, STAGED);
        } catch (KeystoreEncryptedBlobStore.StateStoreException error) {
            throw new IllegalStateException("cannot finish identity backup recovery", error);
        }
    }

    private static void ensureNoPreparedImport(Context context) {
        if (readMarker(context) != 0) {
            throw new IllegalStateException("an identity backup import is already staged");
        }
    }

    private static boolean hasExistingSecureState(
            Context context, SecureChatState chatState) {
        return chatState.hasAnySecureConversationState()
                || KeystoreSignalProtocolStore.hasRemoteProtocolState(context);
    }

    private static ImportStage requireStage(Context context, byte expectedPhase) {
        ImportStage stage = readStage(context, expectedPhase);
        if (stage == null) {
            throw new IllegalStateException("identity backup import is not in the expected phase");
        }
        return stage;
    }

    private static ImportStage readStage(Context context, byte expectedPhase) {
        byte phase = readMarker(context);
        if (phase == 0) {
            return null;
        }
        if (phase != expectedPhase) {
            throw new IllegalStateException("identity recovery marker phase mismatch");
        }
        try {
            byte[] encoded = new KeystoreEncryptedBlobStore(context).get(STAGED);
            if (encoded == null) {
                throw new IllegalStateException("identity recovery staging record is missing");
            }
            try {
                return decodeStage(encoded);
            } finally {
                Arrays.fill(encoded, (byte) 0);
            }
        } catch (KeystoreEncryptedBlobStore.StateStoreException error) {
            throw new IllegalStateException("cannot read staged identity recovery", error);
        }
    }

    private static byte readMarker(Context context) {
        try {
            byte[] encoded = new KeystoreEncryptedBlobStore(context).get(MARKER);
            if (encoded == null) {
                return 0;
            }
            try {
                if (encoded.length != 2
                        || encoded[0] != MARKER_VERSION
                        || (encoded[1] != PREPARED && encoded[1] != COMMITTING)) {
                    throw new IllegalStateException("invalid identity recovery marker");
                }
                return encoded[1];
            } finally {
                Arrays.fill(encoded, (byte) 0);
            }
        } catch (KeystoreEncryptedBlobStore.StateStoreException error) {
            throw new IllegalStateException("cannot read identity recovery marker", error);
        }
    }

    private static byte[] marker(byte phase) {
        return new byte[] {MARKER_VERSION, phase};
    }

    private static byte[] encodeStage(
            SecureIdentityBackupCodec.Payload payload,
            SecureRecoveryGenerationStore.Record recovery) {
        byte[] plaintext = SecureIdentityBackupCodec.encodePlaintext(payload);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(STAGE_MAGIC);
            output.writeShort(STAGE_VERSION);
            output.writeLong(recovery.generation);
            output.writeLong(recovery.recoveryId.getMostSignificantBits());
            output.writeLong(recovery.recoveryId.getLeastSignificantBits());
            output.writeInt(plaintext.length);
            output.write(plaintext);
            output.flush();
            byte[] encoded = bytes.toByteArray();
            if (encoded.length > MAX_STAGE_BYTES) {
                throw new IllegalArgumentException("identity recovery staging record is too large");
            }
            return encoded;
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static ImportStage decodeStage(byte[] encoded) {
        if (encoded == null || encoded.length < 4 + 2 + 8 + 16 + 4
                || encoded.length > MAX_STAGE_BYTES) {
            throw new IllegalArgumentException("invalid identity recovery staging length");
        }
        try {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded));
            byte[] magic = new byte[STAGE_MAGIC.length];
            input.readFully(magic);
            if (!Arrays.equals(magic, STAGE_MAGIC)
                    || input.readUnsignedShort() != STAGE_VERSION) {
                throw new IllegalArgumentException("unsupported identity recovery staging record");
            }
            long generation = input.readLong();
            UUID recoveryId = new UUID(input.readLong(), input.readLong());
            int plaintextLength = input.readInt();
            if (plaintextLength <= 0 || plaintextLength > 4096
                    || plaintextLength != input.available()) {
                throw new IllegalArgumentException("invalid staged identity payload length");
            }
            byte[] plaintext = new byte[plaintextLength];
            input.readFully(plaintext);
            try {
                return new ImportStage(
                        SecureIdentityBackupCodec.decodePlaintext(plaintext),
                        new SecureRecoveryGenerationStore.Record(generation, recoveryId));
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        } catch (java.io.EOFException error) {
            throw new IllegalArgumentException("truncated identity recovery staging record", error);
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static String fingerprint(byte[] serializedIdentity) {
        try {
            byte[] publicKey = new org.signal.libsignal.protocol.IdentityKeyPair(
                    serializedIdentity).getPublicKey().serialize();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey);
            StringBuilder compact = new StringBuilder(48);
            for (int i = 0; i < 24; i++) {
                compact.append(Character.forDigit((digest[i] >>> 4) & 0x0f, 16));
                compact.append(Character.forDigit(digest[i] & 0x0f, 16));
            }
            StringBuilder grouped = new StringBuilder(59);
            for (int i = 0; i < compact.length(); i += 4) {
                if (grouped.length() > 0) {
                    grouped.append(' ');
                }
                grouped.append(compact, i, i + 4);
            }
            return grouped.toString();
        } catch (Exception error) {
            throw new IllegalArgumentException("invalid recovered identity", error);
        }
    }

    private static long generationForEpoch(long epoch) {
        if (epoch < 0 || epoch == Long.MAX_VALUE) {
            throw new IllegalStateException("invalid secure identity epoch");
        }
        return epoch + 1;
    }

    private static long increment(long generation) {
        if (generation <= 0 || generation == Long.MAX_VALUE) {
            throw new IllegalArgumentException("identity recovery generation is exhausted");
        }
        return generation + 1;
    }

    private static UUID nonZeroUuid() {
        UUID value;
        do {
            value = UUID.randomUUID();
        } while (value.getMostSignificantBits() == 0 && value.getLeastSignificantBits() == 0);
        return value;
    }

    private static final class ImportStage {
        final SecureIdentityBackupCodec.Payload payload;
        final SecureRecoveryGenerationStore.Record recovery;

        ImportStage(
                SecureIdentityBackupCodec.Payload payload,
                SecureRecoveryGenerationStore.Record recovery) {
            this.payload = payload;
            this.recovery = recovery;
        }
    }
}
