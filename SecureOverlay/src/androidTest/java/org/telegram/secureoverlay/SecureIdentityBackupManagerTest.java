package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureIdentityBackupManagerTest {
    private static final long OWNER = 910000001L;

    @Test
    public void identityOnlyArchiveRestoresGloballyWithFreshGeneration() {
        Context context = ApplicationProvider.getApplicationContext();
        char[] password = "test-only-backup-password".toCharArray();
        byte[] archive = null;
        try {
            SecureChatEngine.resetOwnIdentity(context);
            SecureIdentityBackupManager.IdentityInfo archived =
                    SecureIdentityBackupManager.getIdentityInfo(context);
            archive = SecureIdentityBackupManager.exportArchive(
                    context, OWNER, password);

            String replacement = SecureChatEngine.resetOwnIdentity(context);
            assertNotEquals(archived.fingerprint, replacement);

            SecureIdentityBackupManager.PreparedImport prepared =
                    SecureIdentityBackupManager.prepareImport(
                            context, OWNER, archive, password);
            assertEquals(archived.fingerprint, prepared.fingerprint);
            assertTrue(prepared.restoredGeneration > archived.generation);
            assertEquals(
                    replacement,
                    SecureIdentityBackupManager.getIdentityInfo(context).fingerprint);

            SecureIdentityBackupManager.PreparedImport restored =
                    SecureIdentityBackupManager.commitPreparedImport(context);
            SecureIdentityBackupManager.IdentityInfo current =
                    SecureIdentityBackupManager.getIdentityInfo(context);
            assertEquals(archived.fingerprint, restored.fingerprint);
            assertEquals(archived.fingerprint, current.fingerprint);
            assertEquals(restored.restoredGeneration, current.generation);
            assertNull(SecureIdentityBackupManager.getPreparedImport(context));

            long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
            SecureChatEngine engine = new SecureChatEngine(context, 0, peer);
            assertEquals(archived.fingerprint, engine.getOwnFingerprint());
            assertEquals(SecureChatEngine.Mode.OFF, engine.getMode());
            assertFalse(engine.isPaired());
        } finally {
            Arrays.fill(password, '\0');
            if (archive != null) {
                Arrays.fill(archive, (byte) 0);
            }
            cancelPrepared(context);
            SecureChatEngine.resetOwnIdentity(context);
        }
    }

    @Test
    public void cancelledAndRejectedImportsDoNotReplaceCurrentIdentity() {
        Context context = ApplicationProvider.getApplicationContext();
        char[] password = "test-only-backup-password".toCharArray();
        byte[] archive = null;
        try {
            SecureChatEngine.resetOwnIdentity(context);
            archive = SecureIdentityBackupManager.exportArchive(
                    context, OWNER, password);
            String current = SecureChatEngine.resetOwnIdentity(context);
            byte[] testedArchive = archive;

            expectFailure(() -> SecureIdentityBackupManager.prepareImport(
                    context, OWNER + 1, testedArchive, password));
            assertNull(SecureIdentityBackupManager.getPreparedImport(context));
            assertEquals(
                    current,
                    SecureIdentityBackupManager.getIdentityInfo(context).fingerprint);

            SecureIdentityBackupManager.prepareImport(
                    context, OWNER, archive, password);
            SecureIdentityBackupManager.cancelPreparedImport(context);
            assertNull(SecureIdentityBackupManager.getPreparedImport(context));
            assertEquals(
                    current,
                    SecureIdentityBackupManager.getIdentityInfo(context).fingerprint);

            long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
            SecureChatState state = new SecureChatState(context);
            state.markWaiting(0, peer);
            SecureIdentityBackupManager.prepareImport(
                    context, OWNER, testedArchive, password);
            assertTrue(state.isWaiting(0, peer));
            SecureIdentityBackupManager.cancelPreparedImport(context);
            assertNull(SecureIdentityBackupManager.getPreparedImport(context));
            assertEquals(
                    current,
                    SecureIdentityBackupManager.getIdentityInfo(context).fingerprint);
            assertTrue(state.isWaiting(0, peer));
        } finally {
            Arrays.fill(password, '\0');
            if (archive != null) {
                Arrays.fill(archive, (byte) 0);
            }
            cancelPrepared(context);
            SecureChatEngine.resetOwnIdentity(context);
        }
    }

    @Test
    public void confirmedImportReplacesTemporaryActiveState() {
        Context context = ApplicationProvider.getApplicationContext();
        char[] password = "test-only-backup-password".toCharArray();
        byte[] archive = null;
        try {
            SecureChatEngine.resetOwnIdentity(context);
            SecureIdentityBackupManager.IdentityInfo archived =
                    SecureIdentityBackupManager.getIdentityInfo(context);
            archive = SecureIdentityBackupManager.exportArchive(
                    context, OWNER, password);
            String replacement = SecureChatEngine.resetOwnIdentity(context);
            assertNotEquals(archived.fingerprint, replacement);

            long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
            SecureChatState state = new SecureChatState(context);
            state.markPaired(0, peer);

            SecureIdentityBackupManager.PreparedImport prepared =
                    SecureIdentityBackupManager.prepareImport(
                            context, OWNER, archive, password);
            assertEquals(archived.fingerprint, prepared.fingerprint);
            assertTrue(state.isPaired(0, peer));

            SecureIdentityBackupManager.commitPreparedImport(context);
            assertEquals(
                    archived.fingerprint,
                    SecureIdentityBackupManager.getIdentityInfo(context).fingerprint);
            assertFalse(new SecureChatState(context)
                    .hasAnySecureConversationState());
            assertFalse(KeystoreSignalProtocolStore
                    .hasRemoteProtocolState(context));
        } finally {
            Arrays.fill(password, '\0');
            if (archive != null) {
                Arrays.fill(archive, (byte) 0);
            }
            cancelPrepared(context);
            SecureChatEngine.resetOwnIdentity(context);
        }
    }

    private static void expectFailure(Runnable runnable) {
        try {
            runnable.run();
            fail("expected identity import failure");
        } catch (RuntimeException expected) {
            assertTrue(expected.getMessage() != null);
        }
    }

    private static void cancelPrepared(Context context) {
        try {
            SecureIdentityBackupManager.cancelPreparedImport(context);
        } catch (RuntimeException ignored) {
            // A test that failed before staging has nothing to cancel.
        }
    }
}
