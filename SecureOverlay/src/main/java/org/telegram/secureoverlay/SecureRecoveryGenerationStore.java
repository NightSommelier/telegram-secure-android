package org.telegram.secureoverlay;

import android.content.Context;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.UUID;

/**
 * Keystore-encrypted recovery-generation records for the local identity and verified peers.
 *
 * <p>This store does not import an identity archive or alter libsignal sessions. It provides the
 * monotonic state and fail-closed rollback/clone decisions that a reviewed recovery protocol can
 * bind into future pairing objects.</p>
 */
public final class SecureRecoveryGenerationStore {
    private static final String DEFAULT_ROOT = "recovery-generation-v1";
    private static final String LOCAL = "local";
    private static final String PEER_PREFIX = "peer/";
    private static final int FORMAT_VERSION = 1;
    private static final int RECORD_BYTES = 1 + 8 + 16;
    private static final Object LOCK = new Object();
    private static final SecureRandom RANDOM = new SecureRandom();

    public enum Decision {
        FIRST_SEEN,
        SAME_RECOVERY,
        ADVANCE_REQUIRES_VERIFICATION,
        REJECT_ROLLBACK,
        REJECT_CLONE
    }

    public static final class Record {
        public final long generation;
        public final UUID recoveryId;

        public Record(long generation, UUID recoveryId) {
            if (generation <= 0) {
                throw new IllegalArgumentException("recovery generation must be positive");
            }
            if (recoveryId == null
                    || (recoveryId.getMostSignificantBits() == 0
                    && recoveryId.getLeastSignificantBits() == 0)) {
                throw new IllegalArgumentException("recovery id must be non-zero");
            }
            this.generation = generation;
            this.recoveryId = recoveryId;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof Record)) {
                return false;
            }
            Record record = (Record) other;
            return generation == record.generation && recoveryId.equals(record.recoveryId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(generation, recoveryId);
        }
    }

    private final KeystoreEncryptedBlobStore blobs;
    private final String root;

    public SecureRecoveryGenerationStore(Context context) {
        this(context, DEFAULT_ROOT);
    }

    SecureRecoveryGenerationStore(Context context, String root) {
        if (context == null || root == null || root.isEmpty() || root.length() > 80) {
            throw new IllegalArgumentException("invalid recovery store");
        }
        blobs = new KeystoreEncryptedBlobStore(context.getApplicationContext());
        this.root = root;
    }

    /**
     * Creates the local record if absent and catches it up to an already-known lifecycle epoch.
     * Re-reading the same or an older epoch never changes the recovery ID.
     */
    public Record ensureLocalIdentity(long minimumGeneration) {
        requireGeneration(minimumGeneration);
        synchronized (LOCK) {
            Record current = read(localName());
            if (current != null && current.generation >= minimumGeneration) {
                return current;
            }
            Record next = new Record(minimumGeneration, newRecoveryId());
            write(localName(), next);
            return next;
        }
    }

    /**
     * Advances the local identity after an explicit reset or successful archive recovery.
     */
    public Record advanceLocalIdentity(long minimumGeneration) {
        requireGeneration(minimumGeneration);
        synchronized (LOCK) {
            Record current = read(localName());
            long nextGeneration = minimumGeneration;
            if (current != null) {
                if (current.generation == Long.MAX_VALUE) {
                    throw new StateFailure("recovery generation exhausted", null);
                }
                nextGeneration = Math.max(minimumGeneration, current.generation + 1);
            }
            Record next = new Record(nextGeneration, newRecoveryId());
            write(localName(), next);
            return next;
        }
    }

    public Record getLocalIdentity() {
        synchronized (LOCK) {
            return read(localName());
        }
    }

    public Record getVerifiedPeer(int account, long peerUserId) {
        requirePeer(account, peerUserId);
        synchronized (LOCK) {
            return read(peerName(account, peerUserId));
        }
    }

    /**
     * Classifies an authenticated offer without changing trusted state.
     */
    public Decision classifyPeer(int account, long peerUserId, Record offered) {
        requirePeer(account, peerUserId);
        Objects.requireNonNull(offered, "offered recovery record");
        synchronized (LOCK) {
            return classify(read(peerName(account, peerUserId)), offered);
        }
    }

    /**
     * Persists only a record that the UI has explicitly verified.
     *
     * <p>Rollback and clone conflicts fail without state mutation. A higher generation is accepted
     * only through this explicit method, never during classification or message parsing.</p>
     */
    public void recordVerifiedPeer(int account, long peerUserId, Record offered) {
        requirePeer(account, peerUserId);
        Objects.requireNonNull(offered, "offered recovery record");
        synchronized (LOCK) {
            String name = peerName(account, peerUserId);
            Record current = read(name);
            Decision decision = classify(current, offered);
            if (decision == Decision.REJECT_ROLLBACK || decision == Decision.REJECT_CLONE) {
                throw new SecurityException("rejected peer recovery state: " + decision);
            }
            if (decision != Decision.SAME_RECOVERY) {
                write(name, offered);
            }
        }
    }

    static Decision classify(Record current, Record offered) {
        Objects.requireNonNull(offered, "offered recovery record");
        if (current == null) {
            return Decision.FIRST_SEEN;
        }
        if (offered.generation < current.generation) {
            return Decision.REJECT_ROLLBACK;
        }
        if (offered.generation > current.generation) {
            return Decision.ADVANCE_REQUIRES_VERIFICATION;
        }
        return current.recoveryId.equals(offered.recoveryId)
                ? Decision.SAME_RECOVERY
                : Decision.REJECT_CLONE;
    }

    static byte[] encodeRecord(Record record) {
        Objects.requireNonNull(record, "recovery record");
        return ByteBuffer.allocate(RECORD_BYTES)
                .put((byte) FORMAT_VERSION)
                .putLong(record.generation)
                .putLong(record.recoveryId.getMostSignificantBits())
                .putLong(record.recoveryId.getLeastSignificantBits())
                .array();
    }

    static Record decodeRecord(byte[] encoded) {
        if (encoded == null || encoded.length != RECORD_BYTES) {
            throw new IllegalArgumentException("invalid recovery record length");
        }
        ByteBuffer input = ByteBuffer.wrap(encoded);
        if ((input.get() & 0xff) != FORMAT_VERSION) {
            throw new IllegalArgumentException("unsupported recovery record version");
        }
        long generation = input.getLong();
        UUID recoveryId = new UUID(input.getLong(), input.getLong());
        return new Record(generation, recoveryId);
    }

    void clearForTests() {
        synchronized (LOCK) {
            try {
                blobs.deleteRoots(root);
            } catch (Exception e) {
                throw new StateFailure("cannot clear recovery test state", e);
            }
        }
    }

    private Record read(String name) {
        try {
            byte[] encoded = blobs.get(name);
            return encoded == null ? null : decodeRecord(encoded);
        } catch (Exception e) {
            throw failure("cannot read recovery state", e);
        }
    }

    private void write(String name, Record record) {
        try {
            blobs.put(name, encodeRecord(record));
        } catch (Exception e) {
            throw failure("cannot persist recovery state", e);
        }
    }

    private String localName() {
        return root + '/' + LOCAL;
    }

    private String peerName(int account, long peerUserId) {
        return root + '/' + PEER_PREFIX + account + '/' + peerUserId;
    }

    private static UUID newRecoveryId() {
        byte[] random = new byte[16];
        UUID id;
        do {
            RANDOM.nextBytes(random);
            ByteBuffer input = ByteBuffer.wrap(random);
            id = new UUID(input.getLong(), input.getLong());
        } while (id.getMostSignificantBits() == 0 && id.getLeastSignificantBits() == 0);
        return id;
    }

    private static void requireGeneration(long generation) {
        if (generation <= 0) {
            throw new IllegalArgumentException("recovery generation must be positive");
        }
    }

    private static void requirePeer(int account, long peerUserId) {
        if (account < 0 || peerUserId <= 0) {
            throw new IllegalArgumentException("recovery peer requires an account and user");
        }
    }

    private static StateFailure failure(String message, Exception error) {
        return error instanceof StateFailure
                ? (StateFailure) error
                : new StateFailure(message, error);
    }

    public static final class StateFailure extends RuntimeException {
        StateFailure(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
