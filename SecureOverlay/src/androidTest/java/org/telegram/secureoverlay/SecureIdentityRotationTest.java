package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyType;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.PreKeyBundle;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore;
import org.signal.libsignal.protocol.util.KeyHelper;

@RunWith(AndroidJUnit4.class)
public final class SecureIdentityRotationTest {
    @Test
    public void changedIdentityBlocksUntilExplicitApprovalAndOldOffersStayStale() {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        SecureChatEngine engine = new SecureChatEngine(context, 0, peer);

        String firstOffer = pairingOffer(IdentityKeyPair.generate());
        assertEquals(
                SecureChatEngine.PairingOfferResult.ACCEPTED_INITIAL,
                engine.receivePairingOffer(firstOffer, 100));
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());
        String firstFingerprint = engine.getTrustedFingerprint();
        String acknowledgement = engine.createPairingAcknowledgement();
        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PAIRING_ACK,
                engine.resolveDialogPreview(acknowledgement, true).kind);

        String changedOffer = pairingOffer(IdentityKeyPair.generate());
        assertEquals(
                SecureChatEngine.PairingOfferResult.IDENTITY_CHANGE_PENDING,
                engine.receivePairingOffer(changedOffer, 101));
        assertEquals(SecureChatEngine.Mode.IDENTITY_CHANGED, engine.getMode());
        assertFalse(engine.isPaired());
        assertNotEquals(firstFingerprint, engine.getPendingFingerprint());

        assertEquals(
                SecureChatEngine.PairingOfferResult.IDENTITY_CHANGE_PENDING,
                engine.receivePairingOffer(changedOffer, 101));
        assertEquals(
                SecureChatEngine.PairingOfferResult.STALE,
                engine.receivePairingOffer(firstOffer, 100));
        assertEquals(SecureChatEngine.Mode.IDENTITY_CHANGED, engine.getMode());

        engine.acceptPendingIdentity();
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());
        assertNotEquals(firstFingerprint, engine.getTrustedFingerprint());
        String acceptedFingerprint = engine.getTrustedFingerprint();

        assertEquals(
                SecureChatEngine.PairingOfferResult.STALE,
                engine.receivePairingOffer(firstOffer, 100));
        assertEquals(acceptedFingerprint, engine.getTrustedFingerprint());
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());
    }

    @Test
    public void ownIdentityResetInvalidatesEnginesAndDestroysSessions() {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        SecureRecoveryGenerationStore recovery =
                new SecureRecoveryGenerationStore(context);
        SecureRecoveryGenerationStore.Record oldRecovery = recovery.getLocalIdentity();
        long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        SecureChatEngine oldEngine = new SecureChatEngine(context, 0, peer);
        String oldFingerprint = oldEngine.getOwnFingerprint();
        oldEngine.receivePairingOffer(pairingOffer(IdentityKeyPair.generate()), 200);
        assertTrue(oldEngine.isPaired());

        String newFingerprint = SecureChatEngine.resetOwnIdentity(context);
        assertNotEquals(oldFingerprint, newFingerprint);
        assertTrue(oldEngine.isStale());
        SecureRecoveryGenerationStore.Record newRecovery = recovery.getLocalIdentity();
        assertTrue(newRecovery.generation > oldRecovery.generation);
        assertNotEquals(oldRecovery.recoveryId, newRecovery.recoveryId);

        SecureChatEngine newEngine = new SecureChatEngine(context, 0, peer);
        assertEquals(newFingerprint, newEngine.getOwnFingerprint());
        assertEquals(SecureChatEngine.Mode.OFF, newEngine.getMode());
        assertFalse(newEngine.resumeIfPaused());
    }

    @Test
    public void encryptedAcknowledgementCompletesWaitingStateFromDialogPreview()
            throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        SecureChatEngine waitingEngine = new SecureChatEngine(context, 0, peer);
        String offer = waitingEngine.createPairingOffer();
        assertEquals(SecureChatEngine.Mode.WAITING, waitingEngine.getMode());

        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(offer);
        PreKeyBundle localBundle = SecurePreKeyBundleCodec.decode(decoded.payload);
        IdentityKeyPair remoteIdentity = IdentityKeyPair.generate();
        InMemorySignalProtocolStore remoteStore = new InMemorySignalProtocolStore(
                remoteIdentity, KeyHelper.generateRegistrationId(false));
        SignalProtocolAddress localAddress =
                new SignalProtocolAddress("local-account-0", 1);
        LibsignalSessionAdapter remote = new LibsignalSessionAdapter(
                remoteStore, new SignalProtocolAddress("telegram-user-" + peer, 1));
        remote.establish(localAddress, localBundle);
        LibsignalSessionAdapter.EncryptedMessage encryptedAck = remote.encrypt(
                localAddress,
                "\u0000fork-secure-control:pairing-ack:v1"
                        .getBytes(StandardCharsets.UTF_8));
        int carrierType = encryptedAck.type == LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                ? SecureCarrierCodec.TYPE_PREKEY : SecureCarrierCodec.TYPE_WHISPER;
        String ackCarrier = SecureCarrierCodec.encode(carrierType, encryptedAck.serialized);

        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PAIRING_ACK,
                waitingEngine.resolveDialogPreview(ackCarrier, false).kind);
        assertEquals(SecureChatEngine.Mode.PROTECTED, waitingEngine.getMode());
        // A second list rebuild must use the cache rather than consuming ratchet state again.
        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PAIRING_ACK,
                waitingEngine.resolveDialogPreview(ackCarrier, false).kind);
        assertEquals(SecureChatEngine.Mode.PROTECTED, waitingEngine.getMode());
    }

    @Test
    public void matchingTrustedOfferCompletesWaitingAndRepairsAlreadyRecordedOffer() {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        IdentityKeyPair remoteIdentity = IdentityKeyPair.generate();
        String trustedOffer = pairingOffer(remoteIdentity);
        SecureChatEngine engine = new SecureChatEngine(context, 0, peer);

        assertEquals(
                SecureChatEngine.PairingOfferResult.ACCEPTED_INITIAL,
                engine.receivePairingOffer(trustedOffer, 250));
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());

        engine.createPairingOffer();
        assertEquals(SecureChatEngine.Mode.WAITING, engine.getMode());

        // Reproduce the old client: it recorded the matching offer but forgot to leave WAITING.
        new SecureChatState(context).recordPairingMessage(0, peer, 251);
        assertEquals(
                SecureChatEngine.PairingOfferResult.SAME_IDENTITY,
                engine.receivePairingOffer(trustedOffer, 251));
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());
        assertTrue(engine.isPaired());
        engine.createPairingAcknowledgement();
    }

    @Test
    public void rejectedChangedIdentityKeepsOldTrustButDiscardsDeadSession()
            throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        SecureChatEngine engine = new SecureChatEngine(context, 0, peer);
        engine.receivePairingOffer(pairingOffer(IdentityKeyPair.generate()), 300);
        String oldFingerprint = engine.getTrustedFingerprint();

        RemotePeer changedPeer = remotePeer();
        assertEquals(
                SecureChatEngine.PairingOfferResult.IDENTITY_CHANGE_PENDING,
                engine.receivePairingOffer(changedPeer.offer, 301));
        String rejection = engine.createPairingRejection();

        // Creating the reply alone neither accepts the changed key nor alters the old trust record.
        assertEquals(SecureChatEngine.Mode.IDENTITY_CHANGED, engine.getMode());
        assertEquals(oldFingerprint, engine.getTrustedFingerprint());
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(rejection);
        int messageType = decoded.type == SecureCarrierCodec.TYPE_PREKEY
                ? LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                : LibsignalSessionAdapter.MESSAGE_TYPE_WHISPER;
        byte[] plaintext = changedPeer.sessions.decrypt(
                new SignalProtocolAddress("local-account-0", 1),
                new LibsignalSessionAdapter.EncryptedMessage(messageType, decoded.payload));
        assertEquals(
                "\u0000fork-secure-control:pairing-rejected:v1",
                new String(plaintext, StandardCharsets.UTF_8));

        engine.rejectPendingIdentity();
        assertEquals(SecureChatEngine.Mode.PAUSED, engine.getMode());
        assertEquals(oldFingerprint, engine.getTrustedFingerprint());
        // The contact rotated their identity, so the old ratchet must never be resumed.
        assertFalse(engine.resumeIfPaused());
        assertEquals(SecureChatEngine.Mode.PAUSED, engine.getMode());
    }

    @Test
    public void encryptedRejectionCompletesWaitingStateFromDialogPreview()
            throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        SecureChatEngine waitingEngine = new SecureChatEngine(context, 0, peer);
        String offer = waitingEngine.createPairingOffer();

        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(offer);
        PreKeyBundle localBundle = SecurePreKeyBundleCodec.decode(decoded.payload);
        IdentityKeyPair remoteIdentity = IdentityKeyPair.generate();
        InMemorySignalProtocolStore remoteStore = new InMemorySignalProtocolStore(
                remoteIdentity, KeyHelper.generateRegistrationId(false));
        SignalProtocolAddress localAddress =
                new SignalProtocolAddress("local-account-0", 1);
        LibsignalSessionAdapter remote = new LibsignalSessionAdapter(
                remoteStore, new SignalProtocolAddress("telegram-user-" + peer, 1));
        remote.establish(localAddress, localBundle);
        LibsignalSessionAdapter.EncryptedMessage encryptedRejection = remote.encrypt(
                localAddress,
                "\u0000fork-secure-control:pairing-rejected:v1"
                        .getBytes(StandardCharsets.UTF_8));
        int carrierType =
                encryptedRejection.type == LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                        ? SecureCarrierCodec.TYPE_PREKEY
                        : SecureCarrierCodec.TYPE_WHISPER;
        String rejectionCarrier =
                SecureCarrierCodec.encode(carrierType, encryptedRejection.serialized);

        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PAIRING_REJECTED,
                waitingEngine.resolveDialogPreview(rejectionCarrier, false).kind);
        assertEquals(SecureChatEngine.Mode.PAUSED, waitingEngine.getMode());
        assertFalse(waitingEngine.resumeIfPaused());
        // A list rebuild uses the cache and must not accidentally promote the chat to protected.
        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PAIRING_REJECTED,
                waitingEngine.resolveDialogPreview(rejectionCarrier, false).kind);
        assertEquals(SecureChatEngine.Mode.PAUSED, waitingEngine.getMode());

        // A later successful pairing must not be undone by rebuilding the preview for the old
        // cached rejection.
        new SecureChatState(context).markPaired(0, peer);
        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PAIRING_REJECTED,
                waitingEngine.resolveDialogPreview(rejectionCarrier, false).kind);
        assertEquals(SecureChatEngine.Mode.PROTECTED, waitingEngine.getMode());
    }

    @Test
    public void attachmentManifestRoundTripsThroughSignalAndEncryptedLocalCache()
            throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        RemotePeer remotePeer = remotePeer();
        SecureChatEngine engine = new SecureChatEngine(context, 0, peer);
        engine.receivePairingOffer(remotePeer.offer, 400);
        SecureContentCodec.Attachment attachment =
                new SecureContentCodec.Attachment(
                        new byte[16],
                        new byte[32],
                        new byte[12],
                        new byte[32],
                        100,
                        100 + SecureMediaCrypto.GCM_TAG_BYTES,
                        "private.jpg",
                        "image/jpeg",
                        "caption",
                        800,
                        600,
                        true);

        String carrier = engine.encryptAttachmentManifest(attachment);

        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PHOTO,
                engine.resolveDialogPreview(carrier, true).kind);
        assertEquals(
                "private.jpg",
                engine.getOutgoingAttachment(carrier).fileName);
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
        int messageType = decoded.type == SecureCarrierCodec.TYPE_PREKEY
                ? LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                : LibsignalSessionAdapter.MESSAGE_TYPE_WHISPER;
        byte[] plaintext = remotePeer.sessions.decrypt(
                new SignalProtocolAddress("local-account-0", 1),
                new LibsignalSessionAdapter.EncryptedMessage(
                        messageType, decoded.payload));
        SecureContentCodec.Decoded content = SecureContentCodec.decode(plaintext);
        assertEquals(SecureContentCodec.TYPE_PHOTO, content.type);
        assertEquals("caption", content.attachment.caption);
    }

    private static RemotePeer remotePeer() {
        int registrationId = KeyHelper.generateRegistrationId(false);
        IdentityKeyPair identity = IdentityKeyPair.generate();
        InMemorySignalProtocolStore store =
                new InMemorySignalProtocolStore(identity, registrationId);
        ECKeyPair preKey = ECKeyPair.generate();
        ECKeyPair signedPreKey = ECKeyPair.generate();
        byte[] signedSignature = identity.getPrivateKey()
                .calculateSignature(signedPreKey.getPublicKey().serialize());
        KEMKeyPair kyberPreKey = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
        byte[] kyberSignature = identity.getPrivateKey()
                .calculateSignature(kyberPreKey.getPublicKey().serialize());
        store.storePreKey(1, new PreKeyRecord(1, preKey));
        store.storeSignedPreKey(
                2,
                new SignedPreKeyRecord(
                        2, System.currentTimeMillis(), signedPreKey, signedSignature));
        store.storeKyberPreKey(
                3,
                new KyberPreKeyRecord(
                        3, System.currentTimeMillis(), kyberPreKey, kyberSignature));
        String offer = SecureCarrierCodec.encode(
                SecureCarrierCodec.TYPE_PREKEY_BUNDLE,
                SecurePreKeyBundleCodec.encode(new SecurePreKeyBundleCodec.PublicBundle(
                        registrationId,
                        1,
                        preKey.getPublicKey().serialize(),
                        2,
                        signedPreKey.getPublicKey().serialize(),
                        signedSignature,
                        identity.getPublicKey().serialize(),
                        3,
                        kyberPreKey.getPublicKey().serialize(),
                        kyberSignature)));
        return new RemotePeer(
                offer,
                new LibsignalSessionAdapter(
                        store, new SignalProtocolAddress("remote-test", 1)));
    }

    private static final class RemotePeer {
        final String offer;
        final LibsignalSessionAdapter sessions;

        RemotePeer(String offer, LibsignalSessionAdapter sessions) {
            this.offer = offer;
            this.sessions = sessions;
        }
    }

    private static String pairingOffer(IdentityKeyPair identity) {
        ECKeyPair preKey = ECKeyPair.generate();
        ECKeyPair signedPreKey = ECKeyPair.generate();
        byte[] signedSignature = identity.getPrivateKey()
                .calculateSignature(signedPreKey.getPublicKey().serialize());
        KEMKeyPair kyberPreKey = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
        byte[] kyberSignature = identity.getPrivateKey()
                .calculateSignature(kyberPreKey.getPublicKey().serialize());
        SecurePreKeyBundleCodec.PublicBundle bundle =
                new SecurePreKeyBundleCodec.PublicBundle(
                        ThreadLocalRandom.current().nextInt(1, 16380),
                        1,
                        preKey.getPublicKey().serialize(),
                        2,
                        signedPreKey.getPublicKey().serialize(),
                        signedSignature,
                        identity.getPublicKey().serialize(),
                        3,
                        kyberPreKey.getPublicKey().serialize(),
                        kyberSignature);
        return SecureCarrierCodec.encode(
                SecureCarrierCodec.TYPE_PREKEY_BUNDLE,
                SecurePreKeyBundleCodec.encode(bundle));
    }
}
