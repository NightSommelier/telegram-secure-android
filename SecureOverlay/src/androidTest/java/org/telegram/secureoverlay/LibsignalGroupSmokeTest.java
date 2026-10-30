package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
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

    @org.junit.Before
    public void setUp() {
        SecureSessionManager.GROUPS_ENABLED = true;
    }

    @org.junit.After
    public void tearDown() {
        SecureSessionManager.GROUPS_ENABLED = false;
    }

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

    @Test
    public void rotatesSenderKeyAndEnsuresForwardSecrecy() throws Exception {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore charlieStore = new InMemorySenderKeyStore();

        SignalProtocolAddress aliceAddress = new SignalProtocolAddress("telegram-user-1001", DEVICE_ID);
        UUID groupDistributionId = UUID.nameUUIDFromBytes("group-chat-5005".getBytes(StandardCharsets.UTF_8));

        // 1. Initial key exchange
        GroupSessionBuilder aliceBuilder = new GroupSessionBuilder(aliceStore);
        byte[] dist1 = aliceBuilder.create(aliceAddress, groupDistributionId).serialize();

        new GroupSessionBuilder(bobStore).process(aliceAddress, new SenderKeyDistributionMessage(dist1));
        new GroupSessionBuilder(charlieStore).process(aliceAddress, new SenderKeyDistributionMessage(dist1));

        // 2. Alice sends message 1 - both Bob and Charlie can decrypt
        byte[] msg1 = "Message before member leave".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext1 = new GroupCipher(aliceStore, aliceAddress).encrypt(groupDistributionId, msg1).serialize();
        assertArrayEquals(msg1, new GroupCipher(bobStore, aliceAddress).decrypt(ciphertext1));
        assertArrayEquals(msg1, new GroupCipher(charlieStore, aliceAddress).decrypt(ciphertext1));

        // 3. Charlie leaves group -> Alice rotates SenderKey (re-creates a new store/key)
        InMemorySenderKeyStore aliceNewStore = new InMemorySenderKeyStore();
        GroupSessionBuilder aliceNewBuilder = new GroupSessionBuilder(aliceNewStore);
        byte[] dist2 = aliceNewBuilder.create(aliceAddress, groupDistributionId).serialize();

        // 4. Alice distributes key ONLY to Bob (Charlie does NOT receive dist2)
        new GroupSessionBuilder(bobStore).process(aliceAddress, new SenderKeyDistributionMessage(dist2));

        // 5. Alice sends message 2 under rotated key
        byte[] msg2 = "Secret message after Charlie left".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext2 = new GroupCipher(aliceNewStore, aliceAddress).encrypt(groupDistributionId, msg2).serialize();

        // Bob can decrypt message 2
        assertArrayEquals(msg2, new GroupCipher(bobStore, aliceAddress).decrypt(ciphertext2));

        // Charlie CANNOT decrypt message 2 with the old key
        try {
            new GroupCipher(charlieStore, aliceAddress).decrypt(ciphertext2);
            org.junit.Assert.fail("Charlie should not be able to decrypt message encrypted with rotated SenderKey");
        } catch (Exception expected) {
            assertNotNull(expected);
        }
    }

    @Test
    public void autoCreatesSenderKeyOnEncrypt() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        KeystoreSignalProtocolStore store = new KeystoreSignalProtocolStore(context);
        SignalProtocolAddress localAddress = new SignalProtocolAddress("local-account-0", DEVICE_ID);
        LibsignalSessionAdapter adapter = new LibsignalSessionAdapter(store, localAddress);

        UUID distributionId = UUID.randomUUID();
        // Ensure no prior sender key exists
        store.deleteSenderKey(localAddress, distributionId);

        // encryptGroup should auto-create the sender key without throwing NoSessionException
        byte[] payload = "Auto created sender key test".getBytes(StandardCharsets.UTF_8);
        LibsignalSessionAdapter.EncryptedMessage encrypted = adapter.encryptGroup(distributionId, payload);
        assertNotNull(encrypted);
        assertEquals(LibsignalSessionAdapter.MESSAGE_TYPE_SENDERKEY, encrypted.type);
        assertNotNull(encrypted.serialized);

        // Distribution message reflects current ratchet state and allows members to decrypt subsequent messages
        byte[] distBytes = adapter.createGroupDistributionMessage(distributionId);
        assertNotNull(distBytes);
        InMemorySenderKeyStore receiverStore = new InMemorySenderKeyStore();
        new GroupSessionBuilder(receiverStore).process(localAddress, new SenderKeyDistributionMessage(distBytes));

        byte[] payload2 = "Subsequent message after distribution".getBytes(StandardCharsets.UTF_8);
        LibsignalSessionAdapter.EncryptedMessage encrypted2 = adapter.encryptGroup(distributionId, payload2);
        byte[] decrypted2 = new GroupCipher(receiverStore, localAddress).decrypt(encrypted2.serialized);
        assertArrayEquals(payload2, decrypted2);

        store.deleteSenderKey(localAddress, distributionId);
    }

    @Test
    public void rejectsUnencryptedSenderKeyDistributionAndEnforcesPairwise1To1Delivery() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        long testGroupId = -987654321L;
        long senderUserId = 12345678L;

        SecureChatEngine groupEngine = new SecureChatEngine(context, 0, testGroupId);
        groupEngine.disable();
        org.junit.Assert.assertFalse(groupEngine.isPaired());

        // 1. Unencrypted outer TYPE_SENDERKEY_DISTRIBUTION carrier must be rejected fail-closed
        InMemorySenderKeyStore senderStore = new InMemorySenderKeyStore();
        SignalProtocolAddress senderAddress = new SignalProtocolAddress("telegram-user-" + senderUserId, DEVICE_ID);
        UUID groupDistributionId = UUID.nameUUIDFromBytes(("telegram-group-" + testGroupId).getBytes(StandardCharsets.UTF_8));
        GroupSessionBuilder builder = new GroupSessionBuilder(senderStore);
        byte[] distBytes = builder.create(senderAddress, groupDistributionId).serialize();
        String unencryptedCarrier = SecureCarrierCodec.encode(
                SecureCarrierCodec.TYPE_SENDERKEY_DISTRIBUTION, distBytes);

        try {
            groupEngine.processGroupSenderKeyDistributionCarrier(senderUserId, unencryptedCarrier);
            org.junit.Assert.fail("Unencrypted SenderKey distribution carrier must be rejected");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertNotNull(expected);
        }
        try {
            groupEngine.decryptText(unencryptedCarrier, senderUserId);
            org.junit.Assert.fail("decryptText must reject TYPE_SENDERKEY_DISTRIBUTION");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertNotNull(expected);
        }
        org.junit.Assert.assertFalse(groupEngine.isPaired());

        // 2. Pairwise inner FSC1 TYPE_SENDER_KEY_DISTRIBUTION round-trip
        byte[] encodedInner = SecureContentCodec.encodeSenderKeyDistribution(testGroupId, distBytes);
        SecureContentCodec.Decoded decodedInner = SecureContentCodec.decode(encodedInner);
        assertEquals(SecureContentCodec.TYPE_SENDER_KEY_DISTRIBUTION, decodedInner.type);
        assertNotNull(decodedInner.senderKeyDistribution);
        assertEquals(testGroupId, decodedInner.senderKeyDistribution.groupChatId);
        assertArrayEquals(distBytes, decodedInner.senderKeyDistribution.distributionBytes);
    }

    @Test
    public void senderKeyRotationSetsNeedsDistributionFlagAndBlocksGroupSelfDistribution() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        long testGroupId = -888777666L;
        SecureChatEngine engine = new SecureChatEngine(context, 0, testGroupId);
        try {
            engine.clearGroupKeyNeedsDistribution();
            org.junit.Assert.assertFalse(engine.isGroupKeyNeedsDistribution());

            // Rotating sender key must mark distribution as needed
            engine.rotateGroupSenderKey();
            assertTrue(engine.isGroupKeyNeedsDistribution());

            // Calling createGroupSenderKeyDistributionCarrier on a group engine (peerUserId < 0) must fail closed
            try {
                engine.createGroupSenderKeyDistributionCarrier(testGroupId);
                org.junit.Assert.fail("Group engine must not create unencrypted self-distribution carrier");
            } catch (SecureChatEngine.SecureChatException expected) {
                assertNotNull(expected);
            }

            engine.clearGroupKeyNeedsDistribution();
            org.junit.Assert.assertFalse(engine.isGroupKeyNeedsDistribution());
        } finally {
            engine.disable();
        }
    }
}
