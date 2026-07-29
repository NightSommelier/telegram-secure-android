package org.telegram.secureoverlay;

import static org.junit.Assert.assertFalse;
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
        assertTrue(state.getPendingMessageId(0, peer) == 101);

        state.rejectPendingIdentity(0, peer);
        assertFalse(state.isIdentityPending(0, peer));
        assertTrue(state.isPaused(0, peer));

        state.markIdentityPending(0, peer, "TGS1:test-public-bundle-new", 102);
        state.approvePendingIdentity(0, peer);
        assertTrue(state.isPaired(0, peer));
        assertFalse(state.isIdentityPending(0, peer));
        assertTrue(state.getLastPairingMessageId(0, peer) == 102);
    }
}
