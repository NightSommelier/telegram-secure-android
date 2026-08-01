package org.telegram.secureoverlay;

import android.content.Context;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

import org.signal.libsignal.protocol.IdentityKeyPair;

/**
 * Exports and restores identity plus historical display records without restoring live ratchets.
 */
public final class SecureHistoryBackupManager {
    private static final String MARKER = "history-recovery-v1/committing";
    private static final int MARKER_VERSION = 1;
    private static final int MAX_MARKER_BYTES = 20_000 * 12 + 32;
    private static final String[] PROTOCOL_ROOTS = {
            "identity",
            "registration",
            "prekey",
            "signed",
            "kyber",
            "index",
            "kyber-used",
            "session",
            "sender",
            "recovery-generation-v1"
    };
    private static final String[] HISTORY_PREFIXES = {
            SecureLocalTextStore.OUTGOING_PREFIX,
            SecureLocalTextStore.INCOMING_PREFIX,
            SecureLocalContentStore.OUTGOING_PREFIX,
            SecureLocalContentStore.INCOMING_PREFIX
    };
    private static final int[] HISTORY_KINDS = {
            SecureHistoryBackupCodec.KIND_OUTGOING_TEXT,
            SecureHistoryBackupCodec.KIND_INCOMING_TEXT,
            SecureHistoryBackupCodec.KIND_OUTGOING_CONTENT,
            SecureHistoryBackupCodec.KIND_INCOMING_CONTENT
    };
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Object LOCK = new Object();

    private SecureHistoryBackupManager() {
    }

    public static final class RestoreResult {
        public final long restoredGeneration;
        public final int restoredMessages;
        public final int pausedChats;
        public final String fingerprint;

        RestoreResult(
                long restoredGeneration,
                int restoredMessages,
                int pausedChats,
                String fingerprint) {
            this.restoredGeneration = restoredGeneration;
            this.restoredMessages = restoredMessages;
            this.pausedChats = pausedChats;
            this.fingerprint = fingerprint;
        }
    }

    public static byte[] exportArchive(
            Context context,
            int account,
            long ownerUserId,
            char[] password) {
        if (context == null || account < 0 || ownerUserId <= 0) {
            throw new IllegalArgumentException(
                    "secure history export requires an account owner");
        }
        Context appContext = context.getApplicationContext();
        synchronized (LOCK) {
            resumeInterruptedRestore(appContext);
            if (SecureIdentityBackupManager.getPreparedImport(appContext) != null) {
                throw new IllegalStateException(
                        "identity recovery is already prepared");
            }
            SecureChatState chatState = new SecureChatState(appContext);
            SecureRecoveryGenerationStore.Record recovery =
                    new SecureRecoveryGenerationStore(appContext).ensureLocalIdentity(
                            generationForEpoch(chatState.getIdentityEpoch()));
            KeystoreSignalProtocolStore protocol =
                    new KeystoreSignalProtocolStore(appContext);
            List<SecureHistoryBackupCodec.CacheRecord> records =
                    snapshotHistory(appContext, account);
            List<SecureHistoryBackupCodec.PeerRecord> peers =
                    mergeHistoryPeers(chatState.getRecoveryPeers(account), records);
            SecureHistoryBackupCodec.Payload payload =
                    new SecureHistoryBackupCodec.Payload(
                            nonZeroUuid(),
                            ownerUserId,
                            recovery.generation,
                            Math.max(1, System.currentTimeMillis() / 1000L),
                            protocol.getLocalRegistrationId(),
                            protocol.getIdentityKeyPair().serialize(),
                            records,
                            peers);
            return SecureHistoryBackupCodec.encrypt(payload, password);
        }
    }

    /**
     * Validates and restores a history archive. The caller must obtain explicit user confirmation
     * before invoking this method.
     */
    public static RestoreResult restoreArchive(
            Context context,
            int targetAccount,
            long ownerUserId,
            byte[] archive,
            char[] password) {
        if (context == null || targetAccount < 0 || ownerUserId <= 0) {
            throw new IllegalArgumentException(
                    "secure history restore requires an account owner");
        }
        Context appContext = context.getApplicationContext();
        synchronized (LOCK) {
            resumeInterruptedRestore(appContext);
            SecureHistoryBackupCodec.Payload payload =
                    SecureHistoryBackupCodec.decrypt(archive, password);
            if (payload.ownerUserId != ownerUserId) {
                throw new SecurityException(
                        "secure history backup belongs to a different Telegram account");
            }
            SecureChatState chatState = new SecureChatState(appContext);
            KeystoreEncryptedBlobStore blobs =
                    new KeystoreEncryptedBlobStore(appContext);
            if (chatState.hasAnySecureConversationState()
                    || KeystoreSignalProtocolStore.hasRemoteProtocolState(appContext)
                    || hasLocalHistory(blobs)
                    || SecureIdentityBackupManager.getPreparedImport(appContext) != null) {
                throw new IllegalStateException(
                        "secure history restore requires an unused secure installation");
            }
            SecureRecoveryGenerationStore recoveryStore =
                    new SecureRecoveryGenerationStore(appContext);
            SecureRecoveryGenerationStore.Record current =
                    recoveryStore.ensureLocalIdentity(
                            generationForEpoch(chatState.getIdentityEpoch()));
            long restoredGeneration =
                    nextGeneration(payload.generation, current.generation);
            SecureRecoveryGenerationStore.Record restoredRecovery =
                    new SecureRecoveryGenerationStore.Record(
                            restoredGeneration, nonZeroUuid());
            Map<String, byte[]> replacements = new LinkedHashMap<>();
            replacements.put("identity", payload.serializedIdentity);
            replacements.put(
                    "registration",
                    ByteBuffer.allocate(4).putInt(payload.registrationId).array());
            replacements.put(
                    "recovery-generation-v1/local",
                    SecureRecoveryGenerationStore.encodeRecord(restoredRecovery));
            for (SecureHistoryBackupCodec.CacheRecord record : payload.cacheRecords) {
                if (record.kind != SecureHistoryBackupCodec.KIND_SAVED_MESSAGES_KEY) {
                    replacements.put(historyName(targetAccount, record), record.value);
                }
            }
            replacements.put(
                    MARKER,
                    encodeMarker(
                            targetAccount,
                            restoredGeneration,
                            payload.cacheRecords.size(),
                            payload.peers,
                            payload.serializedIdentity));
            try {
                blobs.replaceSelected(
                        replacements,
                        PROTOCOL_ROOTS,
                        HISTORY_PREFIXES,
                        MARKER);
            } catch (KeystoreEncryptedBlobStore.StateStoreException error) {
                throw new IllegalStateException(
                        "cannot commit secure history records", error);
            }
            for (SecureHistoryBackupCodec.CacheRecord record : payload.cacheRecords) {
                if (record.kind == SecureHistoryBackupCodec.KIND_SAVED_MESSAGES_KEY) {
                    try {
                        new SecureSavedMessagesKeyStore(appContext).restoreEncoded(
                                targetAccount, record.value);
                    } catch (KeystoreEncryptedBlobStore.StateStoreException error) {
                        throw new IllegalStateException(
                                "cannot restore Saved Messages key", error);
                    }
                }
            }
            return finishInterruptedRestore(appContext);
        }
    }

    /** Completes an already-committed restore marker after a process or device restart. */
    public static void resumeInterruptedRestore(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        synchronized (LOCK) {
            KeystoreEncryptedBlobStore blobs =
                    new KeystoreEncryptedBlobStore(context.getApplicationContext());
            try {
                if (blobs.get(MARKER) != null) {
                    finishInterruptedRestore(context.getApplicationContext());
                }
            } catch (KeystoreEncryptedBlobStore.StateStoreException error) {
                throw new IllegalStateException(
                        "cannot resume secure history recovery", error);
            }
        }
    }

    private static RestoreResult finishInterruptedRestore(Context context) {
        KeystoreEncryptedBlobStore blobs = new KeystoreEncryptedBlobStore(context);
        try {
            byte[] encoded = blobs.get(MARKER);
            if (encoded == null) {
                throw new IllegalStateException(
                        "secure history recovery marker is missing");
            }
            RestoreMarker marker = decodeMarker(encoded);
            new SecureChatState(context).restorePausedPeers(
                    marker.account, marker.generation, marker.peers);
            new KeystoreSignalProtocolStore(context).ensureLocalPreKeyMaterial();
            blobs.delete(MARKER);
            return new RestoreResult(
                    marker.generation,
                    marker.restoredMessages,
                    marker.peers.size(),
                    marker.fingerprint);
        } catch (KeystoreEncryptedBlobStore.StateStoreException error) {
            throw new IllegalStateException(
                    "cannot finish secure history recovery", error);
        }
    }

    private static List<SecureHistoryBackupCodec.CacheRecord> snapshotHistory(
            Context context, int account) {
        String[] scopedPrefixes = new String[HISTORY_PREFIXES.length];
        for (int i = 0; i < HISTORY_PREFIXES.length; i++) {
            scopedPrefixes[i] = HISTORY_PREFIXES[i] + account + '.';
        }
        Map<String, byte[]> snapshot;
        try {
            snapshot = new KeystoreEncryptedBlobStore(context)
                    .snapshotPrefixes(scopedPrefixes);
        } catch (KeystoreEncryptedBlobStore.StateStoreException error) {
            throw new IllegalStateException(
                    "cannot snapshot secure history", error);
        }
        List<SecureHistoryBackupCodec.CacheRecord> records =
                new ArrayList<>(snapshot.size());
        try {
            SecureSavedMessagesKeyStore.KeyMaterial savedKey =
                    new SecureSavedMessagesKeyStore(context).getOrCreate(account);
            records.add(new SecureHistoryBackupCodec.CacheRecord(
                    SecureHistoryBackupCodec.KIND_SAVED_MESSAGES_KEY,
                    Long.MAX_VALUE,
                    new byte[32],
                    SecureSavedMessagesKeyStore.encodeForBackup(savedKey)));
        } catch (KeystoreEncryptedBlobStore.StateStoreException error) {
            throw new IllegalStateException("cannot snapshot Saved Messages key", error);
        }
        for (Map.Entry<String, byte[]> entry : snapshot.entrySet()) {
            int kind = 0;
            String scopedPrefix = null;
            for (int i = 0; i < scopedPrefixes.length; i++) {
                if (entry.getKey().startsWith(scopedPrefixes[i])) {
                    kind = HISTORY_KINDS[i];
                    scopedPrefix = scopedPrefixes[i];
                    break;
                }
            }
            if (scopedPrefix == null) {
                throw new IllegalStateException(
                        "unexpected secure history record");
            }
            String suffix = entry.getKey().substring(scopedPrefix.length());
            int separator = suffix.indexOf('.');
            if (separator <= 0 || separator == suffix.length() - 1) {
                throw new IllegalStateException(
                        "invalid secure history record name");
            }
            long peerUserId;
            try {
                peerUserId = Long.parseLong(suffix.substring(0, separator));
            } catch (NumberFormatException error) {
                throw new IllegalStateException(
                        "invalid secure history peer", error);
            }
            byte[] digest = decodeHex(suffix.substring(separator + 1));
            records.add(new SecureHistoryBackupCodec.CacheRecord(
                    kind, peerUserId, digest, entry.getValue()));
        }
        return records;
    }

    private static List<SecureHistoryBackupCodec.PeerRecord> mergeHistoryPeers(
            List<SecureHistoryBackupCodec.PeerRecord> statePeers,
            List<SecureHistoryBackupCodec.CacheRecord> records) {
        TreeMap<Long, Integer> peers = new TreeMap<>();
        for (SecureHistoryBackupCodec.PeerRecord peer : statePeers) {
            peers.put(peer.peerUserId, peer.lastPairingMessageId);
        }
        for (SecureHistoryBackupCodec.CacheRecord record : records) {
            if (record.kind != SecureHistoryBackupCodec.KIND_SAVED_MESSAGES_KEY) {
                peers.putIfAbsent(record.peerUserId, 0);
            }
        }
        List<SecureHistoryBackupCodec.PeerRecord> merged =
                new ArrayList<>(peers.size());
        for (Map.Entry<Long, Integer> peer : peers.entrySet()) {
            merged.add(new SecureHistoryBackupCodec.PeerRecord(
                    peer.getKey(), peer.getValue()));
        }
        return merged;
    }

    private static String historyName(
            int account, SecureHistoryBackupCodec.CacheRecord record) {
        return HISTORY_PREFIXES[record.kind - 1]
                + account
                + '.'
                + record.peerUserId
                + '.'
                + hex(record.carrierDigest);
    }

    private static boolean hasLocalHistory(KeystoreEncryptedBlobStore blobs) {
        return blobs.hasNameStartingWith(HISTORY_PREFIXES);
    }

    private static byte[] encodeMarker(
            int account,
            long generation,
            int restoredMessages,
            List<SecureHistoryBackupCodec.PeerRecord> peers,
            byte[] serializedIdentity) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.writeByte(MARKER_VERSION);
            output.writeInt(account);
            output.writeLong(generation);
            output.writeInt(restoredMessages);
            output.writeInt(peers.size());
            for (SecureHistoryBackupCodec.PeerRecord peer : peers) {
                output.writeLong(peer.peerUserId);
                output.writeInt(peer.lastPairingMessageId);
            }
            output.write(fingerprintBytes(serializedIdentity));
            output.flush();
            byte[] marker = bytes.toByteArray();
            if (marker.length > MAX_MARKER_BYTES) {
                throw new IllegalArgumentException(
                        "secure history recovery marker is too large");
            }
            return marker;
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static RestoreMarker decodeMarker(byte[] encoded) {
        if (encoded == null || encoded.length < 1 + 4 + 8 + 4 + 4 + 32
                || encoded.length > MAX_MARKER_BYTES) {
            throw new IllegalArgumentException(
                    "invalid secure history recovery marker");
        }
        try {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded));
            if (input.readUnsignedByte() != MARKER_VERSION) {
                throw new IllegalArgumentException(
                        "unsupported secure history recovery marker");
            }
            int account = input.readInt();
            long generation = input.readLong();
            int restoredMessages = input.readInt();
            int peerCount = input.readInt();
            if (account < 0
                    || generation <= 0
                    || restoredMessages < 0
                    || peerCount < 0
                    || peerCount > 20_000) {
                throw new IllegalArgumentException(
                        "invalid secure history recovery marker fields");
            }
            List<SecureHistoryBackupCodec.PeerRecord> peers =
                    new ArrayList<>(peerCount);
            long previousPeer = 0;
            for (int i = 0; i < peerCount; i++) {
                SecureHistoryBackupCodec.PeerRecord peer =
                        new SecureHistoryBackupCodec.PeerRecord(
                                input.readLong(), input.readInt());
                if (peer.peerUserId <= previousPeer) {
                    throw new IllegalArgumentException(
                            "non-canonical secure history recovery peers");
                }
                peers.add(peer);
                previousPeer = peer.peerUserId;
            }
            byte[] fingerprint = new byte[32];
            input.readFully(fingerprint);
            if (input.available() != 0) {
                throw new IllegalArgumentException(
                        "secure history recovery marker has trailing bytes");
            }
            return new RestoreMarker(
                    account,
                    generation,
                    restoredMessages,
                    peers,
                    formatFingerprint(fingerprint));
        } catch (java.io.EOFException error) {
            throw new IllegalArgumentException(
                    "truncated secure history recovery marker", error);
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static long generationForEpoch(long identityEpoch) {
        if (identityEpoch < 0 || identityEpoch == Long.MAX_VALUE) {
            throw new IllegalStateException("invalid secure identity epoch");
        }
        return identityEpoch + 1;
    }

    private static long nextGeneration(long archived, long current) {
        long maximum = Math.max(archived, current);
        if (maximum == Long.MAX_VALUE) {
            throw new IllegalArgumentException(
                    "secure recovery generation is exhausted");
        }
        return maximum + 1;
    }

    private static UUID nonZeroUuid() {
        byte[] random = new byte[16];
        UUID value;
        do {
            RANDOM.nextBytes(random);
            ByteBuffer input = ByteBuffer.wrap(random);
            value = new UUID(input.getLong(), input.getLong());
        } while (value.getMostSignificantBits() == 0
                && value.getLeastSignificantBits() == 0);
        Arrays.fill(random, (byte) 0);
        return value;
    }

    private static byte[] fingerprintBytes(byte[] serializedIdentity) {
        try {
            IdentityKeyPair identity = new IdentityKeyPair(serializedIdentity);
            return MessageDigest.getInstance("SHA-256")
                    .digest(identity.getPublicKey().serialize());
        } catch (Exception error) {
            throw new IllegalArgumentException(
                    "invalid secure history identity", error);
        }
    }

    private static String formatFingerprint(byte[] digest) {
        if (digest == null || digest.length < 24) {
            throw new IllegalArgumentException("invalid secure history fingerprint");
        }
        String raw = hex(Arrays.copyOf(digest, 24));
        StringBuilder formatted = new StringBuilder(raw.length() + 11);
        for (int i = 0; i < raw.length(); i += 4) {
            if (i > 0) {
                formatted.append(' ');
            }
            formatted.append(raw, i, Math.min(raw.length(), i + 4));
        }
        return formatted.toString();
    }

    private static String hex(byte[] data) {
        StringBuilder output = new StringBuilder(data.length * 2);
        for (byte value : data) {
            output.append(Character.forDigit((value >>> 4) & 0x0f, 16));
            output.append(Character.forDigit(value & 0x0f, 16));
        }
        return output.toString();
    }

    private static byte[] decodeHex(String value) {
        if (value == null || value.length() != 64) {
            throw new IllegalStateException(
                    "invalid secure history carrier digest");
        }
        byte[] result = new byte[32];
        for (int i = 0; i < result.length; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalStateException(
                        "invalid secure history carrier digest");
            }
            result[i] = (byte) ((high << 4) | low);
        }
        return result;
    }

    private static final class RestoreMarker {
        final int account;
        final long generation;
        final int restoredMessages;
        final List<SecureHistoryBackupCodec.PeerRecord> peers;
        final String fingerprint;

        RestoreMarker(
                int account,
                long generation,
                int restoredMessages,
                List<SecureHistoryBackupCodec.PeerRecord> peers,
                String fingerprint) {
            this.account = account;
            this.generation = generation;
            this.restoredMessages = restoredMessages;
            this.peers = peers;
            this.fingerprint = fingerprint;
        }
    }
}
