package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureRecoveryGenerationStoreTest {
    @Test
    public void localGenerationIsMonotonicAndChangesRecoveryIdOnlyOnAdvance() {
        SecureRecoveryGenerationStore store = testStore();
        try {
            SecureRecoveryGenerationStore.Record first = store.ensureLocalIdentity(3);
            assertEquals(first, store.ensureLocalIdentity(1));
            assertEquals(first, store.ensureLocalIdentity(3));

            SecureRecoveryGenerationStore.Record next = store.advanceLocalIdentity(3);
            assertEquals(4, next.generation);
            assertNotEquals(first.recoveryId, next.recoveryId);

            SecureRecoveryGenerationStore.Record caughtUp =
                    store.advanceLocalIdentity(10);
            assertEquals(10, caughtUp.generation);
            assertNotEquals(next.recoveryId, caughtUp.recoveryId);
            assertEquals(caughtUp, store.getLocalIdentity());
        } finally {
            store.clearForTests();
        }
    }

    @Test
    public void rollbackAndCloneAreRejectedWithoutTrustedStateMutation() {
        SecureRecoveryGenerationStore store = testStore();
        long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        SecureRecoveryGenerationStore.Record accepted = record(5);
        try {
            assertNull(store.getVerifiedPeer(0, peer));
            assertEquals(
                    SecureRecoveryGenerationStore.Decision.FIRST_SEEN,
                    store.classifyPeer(0, peer, accepted));
            assertNull(store.getVerifiedPeer(0, peer));

            store.recordVerifiedPeer(0, peer, accepted);
            assertEquals(accepted, store.getVerifiedPeer(0, peer));
            assertEquals(
                    SecureRecoveryGenerationStore.Decision.SAME_RECOVERY,
                    store.classifyPeer(0, peer, accepted));

            SecureRecoveryGenerationStore.Record rollback =
                    new SecureRecoveryGenerationStore.Record(4, UUID.randomUUID());
            assertEquals(
                    SecureRecoveryGenerationStore.Decision.REJECT_ROLLBACK,
                    store.classifyPeer(0, peer, rollback));
            assertRejectedWithoutMutation(store, peer, rollback, accepted);

            SecureRecoveryGenerationStore.Record clone =
                    new SecureRecoveryGenerationStore.Record(5, UUID.randomUUID());
            assertEquals(
                    SecureRecoveryGenerationStore.Decision.REJECT_CLONE,
                    store.classifyPeer(0, peer, clone));
            assertRejectedWithoutMutation(store, peer, clone, accepted);

            SecureRecoveryGenerationStore.Record advanced =
                    new SecureRecoveryGenerationStore.Record(6, UUID.randomUUID());
            assertEquals(
                    SecureRecoveryGenerationStore.Decision.ADVANCE_REQUIRES_VERIFICATION,
                    store.classifyPeer(0, peer, advanced));
            assertEquals(accepted, store.getVerifiedPeer(0, peer));
            store.recordVerifiedPeer(0, peer, advanced);
            assertEquals(advanced, store.getVerifiedPeer(0, peer));
        } finally {
            store.clearForTests();
        }
    }

    @Test
    public void recordCodecRejectsMalformedAndNonCanonicalValues() {
        SecureRecoveryGenerationStore.Record record = record(9);
        byte[] encoded = SecureRecoveryGenerationStore.encodeRecord(record);
        assertEquals(record, SecureRecoveryGenerationStore.decodeRecord(encoded));
        assertArrayEquals(encoded, SecureRecoveryGenerationStore.encodeRecord(
                SecureRecoveryGenerationStore.decodeRecord(encoded)));

        assertMalformed(new byte[encoded.length - 1]);
        assertMalformed(new byte[encoded.length + 1]);

        byte[] wrongVersion = encoded.clone();
        wrongVersion[0] = 2;
        assertMalformed(wrongVersion);

        byte[] zeroGeneration = encoded.clone();
        for (int i = 1; i <= 8; i++) {
            zeroGeneration[i] = 0;
        }
        assertMalformed(zeroGeneration);

        byte[] zeroRecoveryId = encoded.clone();
        for (int i = 9; i < zeroRecoveryId.length; i++) {
            zeroRecoveryId[i] = 0;
        }
        assertMalformed(zeroRecoveryId);
    }

    private static void assertRejectedWithoutMutation(
            SecureRecoveryGenerationStore store,
            long peer,
            SecureRecoveryGenerationStore.Record offered,
            SecureRecoveryGenerationStore.Record expected) {
        try {
            store.recordVerifiedPeer(0, peer, offered);
            throw new AssertionError("conflicting recovery state was accepted");
        } catch (SecurityException expectedError) {
            assertEquals(expected, store.getVerifiedPeer(0, peer));
        }
    }

    private static void assertMalformed(byte[] encoded) {
        try {
            SecureRecoveryGenerationStore.decodeRecord(encoded);
            throw new AssertionError("malformed recovery record was accepted");
        } catch (IllegalArgumentException expected) {
            // Expected fail-closed parse.
        }
    }

    private static SecureRecoveryGenerationStore.Record record(long generation) {
        return new SecureRecoveryGenerationStore.Record(generation, UUID.randomUUID());
    }

    private static SecureRecoveryGenerationStore testStore() {
        Context context = ApplicationProvider.getApplicationContext();
        return new SecureRecoveryGenerationStore(
                context, "recovery-generation-test-" + UUID.randomUUID());
    }
}
