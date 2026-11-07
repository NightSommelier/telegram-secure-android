package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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
    private static final long LOCAL_USER_ID = 900_000_001L;

    private static long randomPeerId() {
        long peer;
        do {
            peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        } while (peer == LOCAL_USER_ID);
        return peer;
    }

    @Test
    public void changedIdentityBlocksUntilExplicitApprovalAndOldOffersStayStale() {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = randomPeerId();
        SecureChatEngine engine = new SecureChatEngine(context, 0, peer);

        String firstOffer = pairingOffer(IdentityKeyPair.generate(), peer, LOCAL_USER_ID);
        assertEquals(
                SecureChatEngine.PairingOfferResult.INITIAL_OFFER_PENDING,
                engine.receivePairingOffer(firstOffer, 100, peer, LOCAL_USER_ID));
        assertEquals(SecureChatEngine.Mode.INITIAL_PAIRING_PENDING, engine.getMode());
        assertFalse(engine.isPaired());
        engine.acceptPendingIdentity();
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());
        String firstFingerprint = engine.getTrustedFingerprint();
        String acknowledgement = engine.createPairingAcknowledgement();
        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PAIRING_ACK,
                engine.resolveDialogPreview(acknowledgement, true, LOCAL_USER_ID).kind);

        String changedOffer = pairingOffer(IdentityKeyPair.generate(), peer, LOCAL_USER_ID);
        assertEquals(
                SecureChatEngine.PairingOfferResult.IDENTITY_CHANGE_PENDING,
                engine.receivePairingOffer(changedOffer, 101, peer, LOCAL_USER_ID));
        assertEquals(SecureChatEngine.Mode.IDENTITY_CHANGED, engine.getMode());
        assertFalse(engine.isPaired());
        assertNotEquals(firstFingerprint, engine.getPendingFingerprint());

        assertEquals(
                SecureChatEngine.PairingOfferResult.IDENTITY_CHANGE_PENDING,
                engine.receivePairingOffer(changedOffer, 101, peer, LOCAL_USER_ID));
        assertEquals(
                SecureChatEngine.PairingOfferResult.STALE,
                engine.receivePairingOffer(firstOffer, 100, peer, LOCAL_USER_ID));
        assertEquals(SecureChatEngine.Mode.IDENTITY_CHANGED, engine.getMode());

        engine.acceptPendingIdentity();
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());
        assertNotEquals(firstFingerprint, engine.getTrustedFingerprint());
        String acceptedFingerprint = engine.getTrustedFingerprint();

        assertEquals(
                SecureChatEngine.PairingOfferResult.STALE,
                engine.receivePairingOffer(firstOffer, 100, peer, LOCAL_USER_ID));
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
        long peer = randomPeerId();
        SecureChatEngine oldEngine = new SecureChatEngine(context, 0, peer);
        String oldFingerprint = oldEngine.getOwnFingerprint();
        oldEngine.receivePairingOffer(
                pairingOffer(IdentityKeyPair.generate(), peer, LOCAL_USER_ID),
                200,
                peer,
                LOCAL_USER_ID);
        oldEngine.acceptPendingIdentity();
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
    public void authenticatedRecoveryRequiresVerificationAndRejectsUnsafeOffers() {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = randomPeerId();
        SecureChatEngine engine = new SecureChatEngine(context, 0, peer);
        IdentityKeyPair remoteIdentity = IdentityKeyPair.generate();
        SecureRecoveryGenerationStore.Record generationFive =
                new SecureRecoveryGenerationStore.Record(5, java.util.UUID.randomUUID());

        assertEquals(
                SecureChatEngine.PairingOfferResult.INITIAL_OFFER_PENDING,
                engine.receivePairingOffer(
                        pairingOffer(remoteIdentity, generationFive, peer, LOCAL_USER_ID),
                        400,
                        peer,
                        LOCAL_USER_ID));
        assertEquals(SecureChatEngine.Mode.INITIAL_PAIRING_PENDING, engine.getMode());
        engine.acceptPendingIdentity();
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());
        assertEquals(5, engine.getTrustedRecoveryGeneration());

        SecureRecoveryGenerationStore.Record rollback =
                new SecureRecoveryGenerationStore.Record(4, java.util.UUID.randomUUID());
        assertEquals(
                SecureChatEngine.PairingOfferResult.RECOVERY_REJECTED,
                engine.receivePairingOffer(
                        pairingOffer(remoteIdentity, rollback, peer, LOCAL_USER_ID),
                        401,
                        peer,
                        LOCAL_USER_ID));
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());
        assertEquals(5, engine.getTrustedRecoveryGeneration());

        SecureRecoveryGenerationStore.Record clone =
                new SecureRecoveryGenerationStore.Record(5, java.util.UUID.randomUUID());
        assertEquals(
                SecureChatEngine.PairingOfferResult.RECOVERY_REJECTED,
                engine.receivePairingOffer(
                        pairingOffer(remoteIdentity, clone, peer, LOCAL_USER_ID),
                        402,
                        peer,
                        LOCAL_USER_ID));
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());
        assertEquals(5, engine.getTrustedRecoveryGeneration());

        try {
            engine.receivePairingOffer(
                    legacyPairingOffer(remoteIdentity), 403, peer, LOCAL_USER_ID);
            fail("legacy v1 offer must be rejected");
        } catch (IllegalArgumentException expected) {
            // Expected fail-closed rejection of unsigned legacy v1 format.
        }
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());
        assertEquals(5, engine.getTrustedRecoveryGeneration());

        SecureRecoveryGenerationStore.Record generationSix =
                new SecureRecoveryGenerationStore.Record(6, java.util.UUID.randomUUID());
        String recoveredOffer = pairingOffer(remoteIdentity, generationSix, peer, LOCAL_USER_ID);
        assertEquals(
                SecureChatEngine.PairingOfferResult.RECOVERY_CHANGE_PENDING,
                engine.receivePairingOffer(recoveredOffer, 404, peer, LOCAL_USER_ID));
        assertEquals(SecureChatEngine.Mode.RECOVERY_CHANGED, engine.getMode());
        assertEquals(5, engine.getTrustedRecoveryGeneration());
        assertEquals(6, engine.getPendingRecoveryGeneration());
        assertEquals(generationSix.recoveryId.toString(), engine.getPendingRecoveryId());
        assertEquals(
                SecureChatEngine.PairingOfferResult.RECOVERY_CHANGE_PENDING,
                engine.receivePairingOffer(recoveredOffer, 404, peer, LOCAL_USER_ID));

        engine.acceptPendingIdentity();
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());
        assertEquals(6, engine.getTrustedRecoveryGeneration());
    }

    @Test
    public void encryptedAcknowledgementCompletesWaitingStateFromDialogPreview()
            throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = randomPeerId();
        SecureChatEngine waitingEngine = new SecureChatEngine(context, 0, peer);
        String offer = waitingEngine.createPairingOffer(LOCAL_USER_ID);
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
                SecureContentCodec.encodePairingAckControl());
        int carrierType = encryptedAck.type == LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                ? SecureCarrierCodec.TYPE_PREKEY : SecureCarrierCodec.TYPE_WHISPER;
        String ackCarrier = SecureCarrierCodec.encode(carrierType, encryptedAck.serialized);

        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PAIRING_ACK,
                waitingEngine.resolveDialogPreview(ackCarrier, false, peer).kind);
        assertEquals(SecureChatEngine.Mode.PROTECTED, waitingEngine.getMode());
        // A second list rebuild must use the cache rather than consuming ratchet state again.
        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PAIRING_ACK,
                waitingEngine.resolveDialogPreview(ackCarrier, false, peer).kind);
        assertEquals(SecureChatEngine.Mode.PROTECTED, waitingEngine.getMode());
    }

    @Test
    public void matchingTrustedOfferCompletesWaitingAndRepairsAlreadyRecordedOffer() {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = randomPeerId();
        IdentityKeyPair remoteIdentity = IdentityKeyPair.generate();
        String trustedOffer = pairingOffer(remoteIdentity, peer, LOCAL_USER_ID);
        SecureChatEngine engine = new SecureChatEngine(context, 0, peer);

        assertEquals(
                SecureChatEngine.PairingOfferResult.INITIAL_OFFER_PENDING,
                engine.receivePairingOffer(trustedOffer, 250, peer, LOCAL_USER_ID));
        engine.acceptPendingIdentity();
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());

        engine.createPairingOffer(LOCAL_USER_ID);
        assertEquals(SecureChatEngine.Mode.WAITING, engine.getMode());

        // Reproduce the old client: it recorded the matching offer but forgot to leave WAITING.
        new SecureChatState(context).recordPairingMessage(0, peer, 251);
        assertEquals(
                SecureChatEngine.PairingOfferResult.SAME_IDENTITY,
                engine.receivePairingOffer(trustedOffer, 251, peer, LOCAL_USER_ID));
        assertEquals(SecureChatEngine.Mode.PROTECTED, engine.getMode());
        assertTrue(engine.isPaired());
        engine.createPairingAcknowledgement();
    }

    @Test
    public void rejectedChangedIdentityKeepsOldTrustButDiscardsDeadSession()
            throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = randomPeerId();
        SecureChatEngine engine = new SecureChatEngine(context, 0, peer);
        engine.receivePairingOffer(
                pairingOffer(IdentityKeyPair.generate(), peer, LOCAL_USER_ID),
                300,
                peer,
                LOCAL_USER_ID);
        engine.acceptPendingIdentity();
        String oldFingerprint = engine.getTrustedFingerprint();

        RemotePeer changedPeer = remotePeer(peer, LOCAL_USER_ID);
        assertEquals(
                SecureChatEngine.PairingOfferResult.IDENTITY_CHANGE_PENDING,
                engine.receivePairingOffer(changedPeer.offer, 301, peer, LOCAL_USER_ID));
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
        SecureContentCodec.Decoded control = SecureContentCodec.decode(plaintext);
        assertEquals(SecureContentCodec.TYPE_CONTROL, control.type);
        assertEquals(SecureContentCodec.CONTROL_ACTION_PAIRING_REJECT, control.control.action);

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
        long peer = randomPeerId();
        SecureChatEngine waitingEngine = new SecureChatEngine(context, 0, peer);
        String offer = waitingEngine.createPairingOffer(LOCAL_USER_ID);

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
                SecureContentCodec.encodePairingRejectControl());
        int carrierType =
                encryptedRejection.type == LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                        ? SecureCarrierCodec.TYPE_PREKEY
                        : SecureCarrierCodec.TYPE_WHISPER;
        String rejectionCarrier =
                SecureCarrierCodec.encode(carrierType, encryptedRejection.serialized);

        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PAIRING_REJECTED,
                waitingEngine.resolveDialogPreview(rejectionCarrier, false, peer).kind);
        assertEquals(SecureChatEngine.Mode.PAUSED, waitingEngine.getMode());
        assertFalse(waitingEngine.resumeIfPaused());
        // A list rebuild uses the cache and must not accidentally promote the chat to protected.
        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PAIRING_REJECTED,
                waitingEngine.resolveDialogPreview(rejectionCarrier, false, peer).kind);
        assertEquals(SecureChatEngine.Mode.PAUSED, waitingEngine.getMode());

        // A later successful pairing must not be undone by rebuilding the preview for the old
        // cached rejection.
        new SecureChatState(context).markPaired(0, peer);
        assertEquals(
                SecureChatEngine.DialogPreview.Kind.PAIRING_REJECTED,
                waitingEngine.resolveDialogPreview(rejectionCarrier, false, peer).kind);
        assertEquals(SecureChatEngine.Mode.PROTECTED, waitingEngine.getMode());
    }

    @Test
    public void attachmentManifestRoundTripsThroughSignalAndEncryptedLocalCache()
            throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = randomPeerId();
        RemotePeer remotePeer = remotePeer(peer, LOCAL_USER_ID);
        SecureChatEngine engine = new SecureChatEngine(context, 0, peer);
        engine.receivePairingOffer(remotePeer.offer, 400, peer, LOCAL_USER_ID);
        engine.acceptPendingIdentity();
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
                engine.resolveDialogPreview(carrier, true, LOCAL_USER_ID).kind);
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

    @Test
    public void mediaWaitsForTwoWayPairingConfirmationThenFitsCaption()
            throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = randomPeerId();
        RemotePeer remotePeer = remotePeer(peer, LOCAL_USER_ID);
        SecureChatEngine engine = new SecureChatEngine(context, 0, peer);
        engine.receivePairingOffer(remotePeer.offer, 401, peer, LOCAL_USER_ID);
        engine.acceptPendingIdentity();
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
                        "",
                        800,
                        600,
                        true);

        try {
            engine.encryptAttachmentForTransport(attachment, 1024, 4096);
            fail("one-way PQ pre-key session must not emit an oversized caption");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertTrue(expected.getCause() instanceof IllegalArgumentException);
        }

        String firstConfirmation = engine.createPairingAcknowledgement();
        SecureContentCodec.Decoded ackDecoded =
                SecureContentCodec.decode(decryptFromEngine(remotePeer, firstConfirmation));
        assertEquals(SecureContentCodec.TYPE_CONTROL, ackDecoded.type);
        assertEquals(SecureContentCodec.CONTROL_ACTION_PAIRING_ACK, ackDecoded.control.action);
        String ready = encryptFromRemote(
                remotePeer, SecureContentCodec.encodePairingReadyControl());
        assertTrue(SecureChatEngine.isPairingReadyDisplay(
                engine.decryptText(ready, peer)));

        SecureChatEngine.AttachmentTransport transport =
                engine.encryptAttachmentForTransport(attachment, 1024, 4096);
        assertTrue(transport.attachmentCarrier.length() <= 1024);
        SecureContentCodec.Decoded content = SecureContentCodec.decode(
                decryptFromEngine(remotePeer, transport.attachmentCarrier));
        assertEquals(SecureContentCodec.TYPE_PHOTO, content.type);
        assertEquals("private.jpg", content.attachment.fileName);
    }

    private static byte[] decryptFromEngine(
            RemotePeer remotePeer, String carrier) throws Exception {
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
        int messageType = decoded.type == SecureCarrierCodec.TYPE_PREKEY
                ? LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                : LibsignalSessionAdapter.MESSAGE_TYPE_WHISPER;
        return remotePeer.sessions.decrypt(
                new SignalProtocolAddress("local-account-0", 1),
                new LibsignalSessionAdapter.EncryptedMessage(
                        messageType, decoded.payload));
    }

    private static String encryptFromRemote(
            RemotePeer remotePeer, byte[] plaintext) throws Exception {
        LibsignalSessionAdapter.EncryptedMessage encrypted =
                remotePeer.sessions.encrypt(
                        new SignalProtocolAddress("local-account-0", 1),
                        plaintext);
        int carrierType =
                encrypted.type == LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                        ? SecureCarrierCodec.TYPE_PREKEY
                        : SecureCarrierCodec.TYPE_WHISPER;
        return SecureCarrierCodec.encode(
                carrierType, encrypted.serialized);
    }

    private static RemotePeer remotePeer(long ownerUserId, long recipientUserId) {
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
                SecurePreKeyBundleCodec.encodeRecoveryOffer(
                        new SecurePreKeyBundleCodec.PublicBundle(
                                registrationId,
                                1,
                                preKey.getPublicKey().serialize(),
                                2,
                                signedPreKey.getPublicKey().serialize(),
                                signedSignature,
                                identity.getPublicKey().serialize(),
                                3,
                                kyberPreKey.getPublicKey().serialize(),
                                kyberSignature),
                        new SecureRecoveryGenerationStore.Record(1, java.util.UUID.randomUUID()),
                        identity,
                        ownerUserId,
                        recipientUserId,
                        1700000000L,
                        ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE)));
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

    private static String pairingOffer(
            IdentityKeyPair identity, long ownerUserId, long recipientUserId) {
        return pairingOffer(
                identity,
                new SecureRecoveryGenerationStore.Record(1, java.util.UUID.randomUUID()),
                ownerUserId,
                recipientUserId);
    }

    private static String legacyPairingOffer(IdentityKeyPair identity) {
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

    @Test
    public void textEditAdvancesRatchetAndCanRollBack() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        SecureChatEngine.resetOwnIdentity(context);
        long peer = randomPeerId();
        RemotePeer remotePeer = remotePeer(peer, LOCAL_USER_ID);
        SecureChatEngine engine = new SecureChatEngine(context, 0, peer);
        engine.receivePairingOffer(remotePeer.offer, 401, peer, LOCAL_USER_ID);
        engine.acceptPendingIdentity();
        String confirmation = engine.createPairingAcknowledgement();
        decryptFromEngine(remotePeer, confirmation);
        String ready = encryptFromRemote(
                remotePeer, SecureContentCodec.encodePairingReadyControl());
        engine.decryptText(ready, peer);

        SecureChatEngine.TextEditTransport transport =
                engine.encryptTextForEdit("edited message text", 4096);
        assertTrue(transport.textCarrier != null && transport.textCarrier.length() <= 4096);

        byte[] decrypted = decryptFromEngine(remotePeer, transport.textCarrier);
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(decrypted);
        assertEquals(SecureContentCodec.TYPE_TEXT, decoded.type);
        assertEquals("edited message text", decoded.text);

        SecureChatEngine.TextEditTransport failedTransport =
                engine.encryptTextForEdit("failed text", 4096);
        engine.rollbackTextEdit(failedTransport);

        SecureChatEngine.TextEditTransport nextTransport =
                engine.encryptTextForEdit("recovered text", 4096);
        byte[] failedDecrypted = decryptFromEngine(remotePeer, failedTransport.textCarrier);
        assertEquals("failed text", SecureContentCodec.decode(failedDecrypted).text);
        byte[] nextDecrypted = decryptFromEngine(remotePeer, nextTransport.textCarrier);
        SecureContentCodec.Decoded nextDecoded = SecureContentCodec.decode(nextDecrypted);
        assertEquals("recovered text", nextDecoded.text);
    }

    private static String pairingOffer(
            IdentityKeyPair identity,
            SecureRecoveryGenerationStore.Record recovery,
            long ownerUserId,
            long recipientUserId) {
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
                SecurePreKeyBundleCodec.encodeRecoveryOffer(
                        bundle,
                        recovery,
                        identity,
                        ownerUserId,
                        recipientUserId,
                        1700000000L,
                        ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE)));
    }
}
