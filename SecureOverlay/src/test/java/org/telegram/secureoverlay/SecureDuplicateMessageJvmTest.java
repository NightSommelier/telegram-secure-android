package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import org.junit.Test;
import org.signal.libsignal.protocol.DuplicateMessageException;
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

public final class SecureDuplicateMessageJvmTest {

    @Test
    public void duplicateMessageDisplayIsDisjointFromControlDelete() {
        String duplicateDisplay = SecureChatEngine.DUPLICATE_MESSAGE_DISPLAY;
        String deleteDisplay = SecureChatEngine.CONTROL_DELETE_DISPLAY;

        assertTrue(SecureChatEngine.isDuplicateMessageDisplay(duplicateDisplay));
        assertFalse(SecureChatEngine.isDuplicateMessageDisplay(deleteDisplay));
        assertFalse(SecureChatEngine.isControlDeleteDisplay(duplicateDisplay));
        assertTrue(SecureChatEngine.isControlDeleteDisplay(deleteDisplay));

        assertTrue(SecureChatEngine.isControlDisplay(duplicateDisplay));
        assertEquals(
                SecureChatEngine.DialogPreview.Kind.DUPLICATE_MESSAGE,
                SecureChatEngine.controlPreviewKind(duplicateDisplay));
        assertEquals(
                SecureChatEngine.DialogPreview.Kind.CONTROL_DELETE,
                SecureChatEngine.controlPreviewKind(deleteDisplay));
    }

    @Test
    public void replayedCiphertextThrowsDuplicateMessageExceptionWithoutMutatingSubsequentSession()
            throws Exception {
        IdentityKeyPair aliceIdentity = IdentityKeyPair.generate();
        IdentityKeyPair bobIdentity = IdentityKeyPair.generate();
        InMemorySignalProtocolStore aliceStore = new InMemorySignalProtocolStore(aliceIdentity, 101);
        InMemorySignalProtocolStore bobStore = new InMemorySignalProtocolStore(bobIdentity, 202);

        ECKeyPair bobPreKey = ECKeyPair.generate();
        ECKeyPair bobSignedPreKey = ECKeyPair.generate();
        byte[] bobSignedSig = bobIdentity.getPrivateKey()
                .calculateSignature(bobSignedPreKey.getPublicKey().serialize());
        KEMKeyPair bobKyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
        byte[] bobKyberSig = bobIdentity.getPrivateKey()
                .calculateSignature(bobKyber.getPublicKey().serialize());

        bobStore.storePreKey(1, new PreKeyRecord(1, bobPreKey));
        bobStore.storeSignedPreKey(
                2, new SignedPreKeyRecord(2, 1_700_000_000L, bobSignedPreKey, bobSignedSig));
        bobStore.storeKyberPreKey(
                3, new KyberPreKeyRecord(3, 1_700_000_000L, bobKyber, bobKyberSig));

        SignalProtocolAddress aliceAddr = new SignalProtocolAddress("telegram-user-1001", 1);
        SignalProtocolAddress bobAddr = new SignalProtocolAddress("telegram-user-2002", 1);
        LibsignalSessionAdapter alice = new LibsignalSessionAdapter(aliceStore, aliceAddr);
        LibsignalSessionAdapter bob = new LibsignalSessionAdapter(bobStore, bobAddr);

        PreKeyBundle bobBundle = new PreKeyBundle(
                202,
                1,
                1,
                bobPreKey.getPublicKey(),
                2,
                bobSignedPreKey.getPublicKey(),
                bobSignedSig,
                bobIdentity.getPublicKey(),
                3,
                bobKyber.getPublicKey(),
                bobKyberSig);
        alice.establish(bobAddr, bobBundle);

        byte[] firstPayload = SecureContentCodec.encodeText("first message");
        LibsignalSessionAdapter.EncryptedMessage firstCipher = alice.encrypt(bobAddr, firstPayload);
        assertArrayEquals(firstPayload, bob.decrypt(aliceAddr, firstCipher));

        // Replaying the exact same ciphertext without a local text cache hit raises DuplicateMessageException.
        try {
            bob.decrypt(aliceAddr, firstCipher);
            fail("Expected DuplicateMessageException on replayed ciphertext");
        } catch (DuplicateMessageException expected) {
            // SecureChatEngine maps this exception to DUPLICATE_MESSAGE_DISPLAY rather than CONTROL_DELETE_DISPLAY.
        }

        // Subsequent legitimate messages continue to decrypt normally.
        byte[] secondPayload = "second message".getBytes(StandardCharsets.UTF_8);
        LibsignalSessionAdapter.EncryptedMessage secondCipher = alice.encrypt(bobAddr, secondPayload);
        assertArrayEquals(secondPayload, bob.decrypt(aliceAddr, secondCipher));
    }
}
