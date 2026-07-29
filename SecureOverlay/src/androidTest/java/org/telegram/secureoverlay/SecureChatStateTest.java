package org.telegram.secureoverlay;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureChatStateTest {
    @Test
    public void transitionsFromWaitingToPairedToPaused() {
        SecureChatState state = new SecureChatState(ApplicationProvider.getApplicationContext());
        long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);

        assertFalse(state.isPaired(0, peer));
        assertFalse(state.isWaiting(0, peer));
        assertFalse(state.isPaused(0, peer));

        state.markWaiting(0, peer);
        assertTrue(state.isWaiting(0, peer));
        assertFalse(state.isPaired(0, peer));
        assertFalse(state.isPaused(0, peer));

        state.markPaired(0, peer);
        assertTrue(state.isPaired(0, peer));
        assertFalse(state.isWaiting(0, peer));
        assertFalse(state.isPaused(0, peer));

        state.pause(0, peer);
        assertFalse(state.isPaired(0, peer));
        assertFalse(state.isWaiting(0, peer));
        assertTrue(state.isPaused(0, peer));

        state.markPaired(0, peer);
        assertTrue(state.isPaired(0, peer));
        assertFalse(state.isWaiting(0, peer));
        assertFalse(state.isPaused(0, peer));

        state.markIdentityPending(0, peer, "TGS1:test-public-bundle", 101);
        assertFalse(state.isPaired(0, peer));
        assertFalse(state.isWaiting(0, peer));
        assertFalse(state.isPaused(0, peer));
        assertTrue(state.isIdentityPending(0, peer));
        assertTrue(state.getPendingKind(0, peer)
                == SecureChatState.PendingKind.IDENTITY_CHANGE);
        assertTrue(state.getPendingMessageId(0, peer) == 101);

        state.rejectPendingIdentity(0, peer);
        assertFalse(state.isIdentityPending(0, peer));
        assertTrue(state.isPaused(0, peer));

        state.markIdentityPending(0, peer, "TGS1:test-public-bundle-new", 102);
        state.approvePendingIdentity(0, peer);
        assertTrue(state.isPaired(0, peer));
        assertFalse(state.isIdentityPending(0, peer));
        assertTrue(state.getLastPairingMessageId(0, peer) == 102);

        state.markIdentityPending(
                0,
                peer,
                "TGS1:test-recovery-bundle",
                103,
                SecureChatState.PendingKind.RECOVERY_ADVANCE);
        assertTrue(state.getPendingKind(0, peer)
                == SecureChatState.PendingKind.RECOVERY_ADVANCE);
        state.rejectPendingIdentity(0, peer);
        assertTrue(state.getPendingKind(0, peer) == SecureChatState.PendingKind.NONE);
    }

    @Test
    public void summaryCountsOnlyPrimaryStatesForRequestedAccount() {
        SecureChatState state = new SecureChatState(ApplicationProvider.getApplicationContext());
        int account = ThreadLocalRandom.current().nextInt(20, 2000);
        long paired = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        long waiting = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        long paused = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        long pending = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        long otherAccount = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);

        state.markPaired(account, paired);
        state.recordPairingMessage(account, paired, 10);
        state.markWaiting(account, waiting);
        state.pause(account, paused);
        state.markIdentityPending(
                account,
                pending,
                "TGS1:test-summary",
                11,
                SecureChatState.PendingKind.RECOVERY_ADVANCE);
        state.markPaired(account + 1, otherAccount);

        SecureChatState.Summary summary = state.getSummary(account);
        assertEquals(1, summary.paired);
        assertEquals(1, summary.waiting);
        assertEquals(1, summary.paused);
        assertEquals(1, summary.identityPending);
        assertEquals(4, summary.total());
        assertEquals(1, state.getSummary(account + 1).total());
        assertEquals(0, state.getSummary(account + 2).total());
    }
}
