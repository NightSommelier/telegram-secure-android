package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.groups.GroupCipher;
import org.signal.libsignal.protocol.groups.GroupSessionBuilder;
import org.signal.libsignal.protocol.groups.state.InMemorySenderKeyStore;
import org.signal.libsignal.protocol.message.CiphertextMessage;
import org.signal.libsignal.protocol.message.SenderKeyDistributionMessage;

/**
 * On-device proof and verification of libsignal GroupCipher and SenderKeyDistributionMessage flows.
 */
@RunWith(AndroidJUnit4.class)
public final class LibsignalGroupSmokeTest {
    private static final int DEVICE_ID = 1;

    @Test
    public void distributesSenderKeyAndEncryptsGroupMessage() throws Exception {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore charlieStore = new InMemorySenderKeyStore();

        SignalProtocolAddress aliceAddress = new SignalProtocolAddress("telegram-user-1001", DEVICE_ID);
        UUID groupDistributionId = UUID.nameUUIDFromBytes("group-chat-5005".getBytes(StandardCharsets.UTF_8));

        // 1. Alice creates SenderKeyDistributionMessage for this group
        GroupSessionBuilder aliceGroupBuilder = new GroupSessionBuilder(aliceStore);
        SenderKeyDistributionMessage aliceDistributionMessage = aliceGroupBuilder.create(aliceAddress, groupDistributionId);
        assertNotNull(aliceDistributionMessage);

        byte[] serializedDistribution = aliceDistributionMessage.serialize();

        // 2. Bob and Charlie receive Alice's distribution message
        GroupSessionBuilder bobGroupBuilder = new GroupSessionBuilder(bobStore);
        bobGroupBuilder.process(aliceAddress, new SenderKeyDistributionMessage(serializedDistribution));

        GroupSessionBuilder charlieGroupBuilder = new GroupSessionBuilder(charlieStore);
        charlieGroupBuilder.process(aliceAddress, new SenderKeyDistributionMessage(serializedDistribution));

        // 3. Alice encrypts group message
        GroupCipher aliceCipher = new GroupCipher(aliceStore, aliceAddress);
        byte[] plaintext = "Hello secure group members!".getBytes(StandardCharsets.UTF_8);
        CiphertextMessage groupCiphertext = aliceCipher.encrypt(groupDistributionId, plaintext);
        assertEquals(CiphertextMessage.SENDERKEY_TYPE, groupCiphertext.getType());

        byte[] serializedCiphertext = groupCiphertext.serialize();

        // 4. Bob decrypts group message
        GroupCipher bobCipher = new GroupCipher(bobStore, aliceAddress);
        byte[] bobDecrypted = bobCipher.decrypt(serializedCiphertext);
        assertArrayEquals(plaintext, bobDecrypted);

        // 5. Charlie decrypts group message
        GroupCipher charlieCipher = new GroupCipher(charlieStore, aliceAddress);
        byte[] charlieDecrypted = charlieCipher.decrypt(serializedCiphertext);
        assertArrayEquals(plaintext, charlieDecrypted);
    }

    @Test
    public void encodesAndDecodesGroupCarriers() throws Exception {
        byte[] dummyDistribution = "dummy-distribution-bytes".getBytes(StandardCharsets.UTF_8);
        String distCarrier = SecureCarrierCodec.encode(
                SecureCarrierCodec.TYPE_SENDERKEY_DISTRIBUTION, dummyDistribution);
        SecureCarrierCodec.Decoded decodedDist = SecureCarrierCodec.decode(distCarrier);
        assertNotNull(decodedDist);
        assertEquals(SecureCarrierCodec.TYPE_SENDERKEY_DISTRIBUTION, decodedDist.type);
        assertArrayEquals(dummyDistribution, decodedDist.payload);

        byte[] dummySenderKeyCiphertext = "dummy-ciphertext-bytes".getBytes(StandardCharsets.UTF_8);
        String msgCarrier = SecureCarrierCodec.encode(
                SecureCarrierCodec.TYPE_SENDERKEY, dummySenderKeyCiphertext);
        SecureCarrierCodec.Decoded decodedMsg = SecureCarrierCodec.decode(msgCarrier);
        assertNotNull(decodedMsg);
        assertEquals(SecureCarrierCodec.TYPE_SENDERKEY, decodedMsg.type);
        assertArrayEquals(dummySenderKeyCiphertext, decodedMsg.payload);
    }
}
