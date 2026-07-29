package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.nio.charset.StandardCharsets;
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

/**
 * On-device proof that the pinned libsignal artifact can establish and use a
 * 1:1 pre-key session. This test deliberately uses in-memory state only; the
 * production persistent store is a separate implementation step.
 */
@RunWith(AndroidJUnit4.class)
public final class LibsignalSessionSmokeTest {
    private static final int DEVICE_ID = 1;
    private static final int PRE_KEY_ID = 1;
    private static final int SIGNED_PRE_KEY_ID = 2;
    private static final int KYBER_PRE_KEY_ID = 3;

    @Test
    public void establishesAndUsesBidirectionalPreKeySession() throws Exception {
        IdentityKeyPair aliceIdentity = IdentityKeyPair.generate();
        IdentityKeyPair bobIdentity = IdentityKeyPair.generate();
        InMemorySignalProtocolStore aliceStore = new InMemorySignalProtocolStore(
                aliceIdentity, KeyHelper.generateRegistrationId(false));
        InMemorySignalProtocolStore bobStore = new InMemorySignalProtocolStore(
                bobIdentity, KeyHelper.generateRegistrationId(false));

        ECKeyPair bobPreKeyPair = ECKeyPair.generate();
        PreKeyRecord bobPreKey = new PreKeyRecord(PRE_KEY_ID, bobPreKeyPair);
        bobStore.storePreKey(PRE_KEY_ID, bobPreKey);

        ECKeyPair bobSignedPreKeyPair = ECKeyPair.generate();
        byte[] signedPreKeySignature = bobIdentity.getPrivateKey().calculateSignature(
                bobSignedPreKeyPair.getPublicKey().serialize());
        SignedPreKeyRecord bobSignedPreKey = new SignedPreKeyRecord(
                SIGNED_PRE_KEY_ID,
                System.currentTimeMillis(),
                bobSignedPreKeyPair,
                signedPreKeySignature);
        bobStore.storeSignedPreKey(SIGNED_PRE_KEY_ID, bobSignedPreKey);

        KEMKeyPair bobKyberPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
        byte[] kyberSignature = bobIdentity.getPrivateKey().calculateSignature(
                bobKyberPair.getPublicKey().serialize());
        KyberPreKeyRecord bobKyberPreKey = new KyberPreKeyRecord(
                KYBER_PRE_KEY_ID,
                System.currentTimeMillis(),
                bobKyberPair,
                kyberSignature);
        bobStore.storeKyberPreKey(KYBER_PRE_KEY_ID, bobKyberPreKey);

        SignalProtocolAddress aliceAddress = new SignalProtocolAddress("telegram-user-1001", DEVICE_ID);
        SignalProtocolAddress bobAddress = new SignalProtocolAddress("telegram-user-2002", DEVICE_ID);
        PreKeyBundle bobBundle = new PreKeyBundle(
                bobStore.getLocalRegistrationId(),
                DEVICE_ID,
                PRE_KEY_ID,
                bobPreKeyPair.getPublicKey(),
                SIGNED_PRE_KEY_ID,
                bobSignedPreKeyPair.getPublicKey(),
                signedPreKeySignature,
                bobIdentity.getPublicKey(),
                KYBER_PRE_KEY_ID,
                bobKyberPair.getPublicKey(),
                kyberSignature);

        LibsignalSessionAdapter alice = new LibsignalSessionAdapter(aliceStore, aliceAddress);
        LibsignalSessionAdapter bob = new LibsignalSessionAdapter(bobStore, bobAddress);
        alice.establish(bobAddress, bobBundle);

        byte[] firstPlaintext = "secure hello".getBytes(StandardCharsets.UTF_8);
        LibsignalSessionAdapter.EncryptedMessage firstCiphertext = alice.encrypt(bobAddress, firstPlaintext);
        assertEquals(LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY, firstCiphertext.type);
        assertArrayEquals(firstPlaintext, bob.decrypt(aliceAddress, firstCiphertext));

        byte[] replyPlaintext = "secure reply".getBytes(StandardCharsets.UTF_8);
        LibsignalSessionAdapter.EncryptedMessage replyCiphertext = bob.encrypt(aliceAddress, replyPlaintext);
        assertEquals(LibsignalSessionAdapter.MESSAGE_TYPE_WHISPER, replyCiphertext.type);
        assertArrayEquals(replyPlaintext, alice.decrypt(bobAddress, replyCiphertext));
    }
}
