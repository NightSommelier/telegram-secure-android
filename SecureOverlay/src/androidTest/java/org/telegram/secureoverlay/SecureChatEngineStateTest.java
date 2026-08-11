package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.state.SessionRecord;

@RunWith(AndroidJUnit4.class)
public final class SecureChatEngineStateTest {
    @Test
    public void detectsOnlyTheTargetPeersPersistedSecureStateForPrewarm() {
        Context context = ApplicationProvider.getApplicationContext();
        long protectedPeer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        long otherPeer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        SecureChatState state = new SecureChatState(context);

        assertFalse(SecureChatEngine.hasLocalState(context, 0, protectedPeer));
        assertFalse(SecureChatEngine.hasLocalState(context, 0, otherPeer));

        state.markPaired(0, protectedPeer);

        assertTrue(SecureChatEngine.hasLocalState(context, 0, protectedPeer));
        assertFalse(SecureChatEngine.hasLocalState(context, 0, otherPeer));
    }

    @Test
    public void resumesPausedChatOnlyWhenExistingSessionStillExists() {
        Context context = ApplicationProvider.getApplicationContext();

        long missingPeer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        SecureChatEngine missingSession = new SecureChatEngine(context, 0, missingPeer);
        missingSession.disable();
        assertFalse(missingSession.resumeIfPaused());
        assertEquals(SecureChatEngine.Mode.PAUSED, missingSession.getMode());

        long existingPeer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        SignalProtocolAddress address =
                new SignalProtocolAddress("telegram-user-" + existingPeer, 1);
        KeystoreSignalProtocolStore store = new KeystoreSignalProtocolStore(context);
        store.storeSession(address, new SessionRecord());
        try {
            SecureChatEngine existingSession =
                    new SecureChatEngine(context, 0, existingPeer);
            existingSession.disable();
            assertTrue(existingSession.resumeIfPaused());
            assertEquals(SecureChatEngine.Mode.PROTECTED, existingSession.getMode());
        } finally {
            store.deleteSession(address);
        }
    }
}
