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

    @Test
    public void concurrentEncryptAndDecryptShareUnifiedSessionLockWithoutRatchetLoss() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        long peerId = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        SignalProtocolAddress localAddress = new SignalProtocolAddress("telegram-user-local", 1);
        SignalProtocolAddress peerAddress = new SignalProtocolAddress("telegram-user-" + peerId, 1);

        // Remote simulated peer in memory
        org.signal.libsignal.protocol.IdentityKeyPair remoteIdentity =
                org.signal.libsignal.protocol.IdentityKeyPair.generate();
        int remoteRegId = org.signal.libsignal.protocol.util.KeyHelper.generateRegistrationId(false);
        org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore remoteStore =
                new org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore(
                        remoteIdentity, remoteRegId);
        LibsignalSessionAdapter remoteSessions =
                new LibsignalSessionAdapter(remoteStore, peerAddress);

        SecureChatEngine localEngine = new SecureChatEngine(context, 0, peerId);
        String offerCarrier = localEngine.createPairingOffer();
        SecureCarrierCodec.Decoded decodedOffer = SecureCarrierCodec.decode(offerCarrier);
        org.signal.libsignal.protocol.state.PreKeyBundle localBundle =
                SecurePreKeyBundleCodec.decode(decodedOffer.payload);
        remoteSessions.establish(localAddress, localBundle);

        // First message from remote establishes responder session on localEngine
        LibsignalSessionAdapter.EncryptedMessage bootstrapMsg =
                remoteSessions.encrypt(localAddress, SecureContentCodec.encodeText("bootstrap"));
        String bootstrapCarrier = SecureCarrierCodec.encode(
                bootstrapMsg.type == LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                        ? SecureCarrierCodec.TYPE_PREKEY : SecureCarrierCodec.TYPE_WHISPER,
                bootstrapMsg.serialized);
        assertEquals("bootstrap", localEngine.decryptText(bootstrapCarrier));

        // Pre-generate 10 inbound carriers from remote
        final int count = 10;
        final String[] inboundCarriers = new String[count];
        for (int i = 0; i < count; i++) {
            LibsignalSessionAdapter.EncryptedMessage msg =
                    remoteSessions.encrypt(localAddress, SecureContentCodec.encodeText("in-" + i));
            inboundCarriers[i] = SecureCarrierCodec.encode(
                    msg.type == LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                            ? SecureCarrierCodec.TYPE_PREKEY : SecureCarrierCodec.TYPE_WHISPER,
                    msg.serialized);
        }

        final String[] outboundCarriers = new String[count];
        final Throwable[] failure = new Throwable[2];
        java.util.concurrent.CountDownLatch startGate = new java.util.concurrent.CountDownLatch(1);

        Thread encryptThread = new Thread(() -> {
            try {
                startGate.await();
                for (int i = 0; i < count; i++) {
                    outboundCarriers[i] = localEngine.encryptText("out-" + i);
                }
            } catch (Throwable t) {
                failure[0] = t;
            }
        });

        Thread decryptThread = new Thread(() -> {
            try {
                startGate.await();
                for (int i = 0; i < count; i++) {
                    assertEquals("in-" + i, localEngine.decryptText(inboundCarriers[i]));
                }
            } catch (Throwable t) {
                failure[1] = t;
            }
        });

        try {
            encryptThread.start();
            decryptThread.start();
            startGate.countDown();
            encryptThread.join(10_000);
            decryptThread.join(10_000);
            if (failure[0] != null) throw new AssertionError("Encrypt thread failed", failure[0]);
            if (failure[1] != null) throw new AssertionError("Decrypt thread failed", failure[1]);

            for (int i = 0; i < count; i++) {
                SecureCarrierCodec.Decoded outDecoded = SecureCarrierCodec.decode(outboundCarriers[i]);
                int type = outDecoded.type == SecureCarrierCodec.TYPE_PREKEY
                        ? LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                        : LibsignalSessionAdapter.MESSAGE_TYPE_WHISPER;
                byte[] plain = remoteSessions.decrypt(
                        localAddress,
                        new LibsignalSessionAdapter.EncryptedMessage(type, outDecoded.payload));
                assertEquals("out-" + i, SecureContentCodec.decode(plain).text);
            }
        } finally {
            localEngine.disable();
            new KeystoreSignalProtocolStore(context).deleteSession(peerAddress);
            new KeystoreSignalProtocolStore(context).deleteIdentity(peerAddress);
        }
    }

    @Test
    public void rejectsCrossPeerSenderBindingInOneToOneChat() {
        Context context = ApplicationProvider.getApplicationContext();
        long peerA = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE / 2);
        long peerB = peerA + 1;
        SecureChatEngine engineA = new SecureChatEngine(context, 0, peerA);
        String carrier = SecureCarrierCodec.encode(
                SecureCarrierCodec.TYPE_WHISPER,
                new byte[] {1, 2, 3, 4});
        try {
            engineA.decryptText(carrier, peerB);
            org.junit.Assert.fail("Expected cross-peer senderUserId to be rejected");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertEquals("1:1 message sender does not match peer dialog", expected.getMessage());
        }
    }
}
