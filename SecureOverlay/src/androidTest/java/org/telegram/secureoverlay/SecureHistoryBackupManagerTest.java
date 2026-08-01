package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureHistoryBackupManagerTest {
    private static final int ACCOUNT = 0;
    private static final long OWNER = 920000001L;

    @Test
    public void restoresHistoricalCopiesButPausesEveryRecoveredChat() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        long peer = positiveRandomLong();
        char[] password = "test-only-history-password".toCharArray();
        byte[] archive = null;
        String carrier = carrier();
        byte[] typed = SecureContentCodec.encodeText("historical typed content");
        try {
            clean(context, peer);
            SecureIdentityBackupManager.IdentityInfo original =
                    SecureIdentityBackupManager.getIdentityInfo(context);
            SecureLocalTextStore text =
                    new SecureLocalTextStore(context, ACCOUNT, peer);
            SecureLocalContentStore content =
                    new SecureLocalContentStore(context, ACCOUNT, peer);
            text.rememberOutgoing(carrier, "historical outgoing");
            text.rememberIncoming(carrier, "historical incoming");
            content.rememberOutgoing(carrier, typed);
            content.rememberIncoming(carrier, typed);
            SecureChatState state = new SecureChatState(context);
            state.markPaired(ACCOUNT, peer);
            state.recordPairingMessage(ACCOUNT, peer, 73);

            archive = SecureHistoryBackupManager.exportArchive(
                    context, ACCOUNT, OWNER, password);

            String replacement = SecureChatEngine.resetOwnIdentity(context);
            assertNotEquals(original.fingerprint, replacement);
            new SecureLocalMessageCache(context, ACCOUNT, peer).forgetPeer();
            assertNull(text.loadOutgoing(carrier));

            SecureHistoryBackupManager.RestoreResult restored =
                    SecureHistoryBackupManager.restoreArchive(
                            context, ACCOUNT, OWNER, archive, password);

            SecureIdentityBackupManager.IdentityInfo current =
                    SecureIdentityBackupManager.getIdentityInfo(context);
            assertEquals(original.fingerprint, current.fingerprint);
            assertEquals(original.fingerprint, restored.fingerprint);
            assertEquals(current.generation, restored.restoredGeneration);
            assertEquals(4, restored.restoredMessages);
            assertEquals(1, restored.pausedChats);

            SecureChatState recoveredState = new SecureChatState(context);
            assertTrue(recoveredState.isPaused(ACCOUNT, peer));
            assertFalse(recoveredState.isPaired(ACCOUNT, peer));
            assertEquals(73, recoveredState.getLastPairingMessageId(ACCOUNT, peer));
            assertEquals("historical outgoing", text.loadOutgoing(carrier));
            assertEquals("historical incoming", text.loadIncoming(carrier));
            assertArrayEquals(typed, content.loadOutgoing(carrier));
            assertArrayEquals(typed, content.loadIncoming(carrier));
            assertEquals(
                    SecureChatEngine.Mode.PAUSED,
                    new SecureChatEngine(context, ACCOUNT, peer).getMode());
        } finally {
            Arrays.fill(password, '\0');
            if (archive != null) {
                Arrays.fill(archive, (byte) 0);
            }
            clean(context, peer);
            Arrays.fill(typed, (byte) 0);
        }
    }

    @Test
    public void rejectedArchiveLeavesIdentityAndHistoryUntouched() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        long peer = positiveRandomLong();
        char[] password = "test-only-history-password".toCharArray();
        byte[] archive = null;
        String carrier = carrier();
        try {
            clean(context, peer);
            SecureLocalTextStore text =
                    new SecureLocalTextStore(context, ACCOUNT, peer);
            text.rememberIncoming(carrier, "source history");
            new SecureChatState(context).markPaired(ACCOUNT, peer);
            archive = SecureHistoryBackupManager.exportArchive(
                    context, ACCOUNT, OWNER, password);

            SecureChatEngine.resetOwnIdentity(context);
            new SecureLocalMessageCache(context, ACCOUNT, peer).forgetPeer();
            String current =
                    SecureIdentityBackupManager.getIdentityInfo(context).fingerprint;
            byte[] testedArchive = archive;

            expectFailure(() -> SecureHistoryBackupManager.restoreArchive(
                    context, ACCOUNT, OWNER + 1, testedArchive, password));
            assertEquals(
                    current,
                    SecureIdentityBackupManager.getIdentityInfo(context).fingerprint);
            assertFalse(new SecureChatState(context).hasAnySecureConversationState());
            assertNull(text.loadIncoming(carrier));

            testedArchive[testedArchive.length - 1] ^= 1;
            expectFailure(() -> SecureHistoryBackupManager.restoreArchive(
                    context, ACCOUNT, OWNER, testedArchive, password));
            assertEquals(
                    current,
                    SecureIdentityBackupManager.getIdentityInfo(context).fingerprint);
            assertFalse(new SecureChatState(context).hasAnySecureConversationState());
            assertNull(text.loadIncoming(carrier));
        } finally {
            Arrays.fill(password, '\0');
            if (archive != null) {
                Arrays.fill(archive, (byte) 0);
            }
            clean(context, peer);
        }
    }

    private static void clean(Context context, long peer) throws Exception {
        try {
            SecureChatEngine.resetOwnIdentity(context);
        } finally {
            new SecureLocalMessageCache(context, ACCOUNT, peer).forgetPeer();
        }
    }

    private static String carrier() {
        return SecureCarrierCodec.encode(
                SecureCarrierCodec.TYPE_WHISPER,
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
    }

    private static long positiveRandomLong() {
        long value = UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE;
        return value == 0 ? 1 : value;
    }

    private static void expectFailure(ThrowingRunnable runnable) {
        try {
            runnable.run();
            fail("expected secure history recovery failure");
        } catch (RuntimeException expected) {
            assertTrue(expected.getMessage() != null);
        } catch (Exception error) {
            throw new AssertionError(error);
        }
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
