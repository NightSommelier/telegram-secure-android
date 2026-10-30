package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.UUID;
import org.junit.Test;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyType;

public final class SecurePairingOfferBindingJvmTest {
    @Test
    public void rejectsLegacyUnsignedV1Offer() {
        Fixture fixture = fixture();
        byte[] legacy = SecurePreKeyBundleCodec.encode(fixture.bundle);
        try {
            SecurePreKeyBundleCodec.decodeOffer(legacy);
            fail("Expected legacy v1 unsigned offer to be rejected");
        } catch (IllegalArgumentException expected) {
            assertEquals("unsupported pre-key bundle version", expected.getMessage());
        }
    }

    @Test
    public void v3ParticipantBoundOfferRoundTripsAndValidatesParticipants() {
        Fixture fixture = fixture();
        SecureRecoveryGenerationStore.Record recovery =
                new SecureRecoveryGenerationStore.Record(2, UUID.randomUUID());
        byte[] encoded = SecurePreKeyBundleCodec.encodeRecoveryOffer(
                fixture.bundle,
                recovery,
                fixture.identity,
                1001L,
                2002L,
                1700000000L,
                123456789L);

        SecurePreKeyBundleCodec.DecodedOffer decoded =
                SecurePreKeyBundleCodec.decodeOffer(encoded);
        assertEquals(1001L, decoded.ownerUserId);
        assertEquals(2002L, decoded.recipientUserId);
        assertEquals(1700000000L, decoded.issuedAtEpochSeconds);
        assertEquals(123456789L, decoded.offerNonce);

        // Matching peerUserId, senderUserId, and localUserId succeeds
        SecureChatEngine.requireValidOfferBinding(1001L, 1001L, 2002L, decoded);

        // UKS attack: offer from 1001L replayed in dialog with 3003L
        try {
            SecureChatEngine.requireValidOfferBinding(3003L, 3003L, 2002L, decoded);
            fail("Expected UKS offer owner mismatch to be rejected");
        } catch (IllegalArgumentException expected) {
            assertEquals("pairing offer owner does not match peer", expected.getMessage());
        }

        // Recipient mismatch: offer intended for 2002L replayed to user 4004L
        try {
            SecureChatEngine.requireValidOfferBinding(1001L, 1001L, 4004L, decoded);
            fail("Expected offer recipient mismatch to be rejected");
        } catch (IllegalArgumentException expected) {
            assertEquals(
                    "pairing offer recipient does not match local user",
                    expected.getMessage());
        }

        // Reflection attack: offer replayed back to sender 1001L
        try {
            SecureChatEngine.requireValidOfferBinding(2002L, 2002L, 1001L, decoded);
            fail("Expected reflected offer to be rejected");
        } catch (IllegalArgumentException expected) {
            assertEquals("pairing offer owner does not match peer", expected.getMessage());
        }
    }

    @Test
    public void v3SignatureDetectsTamperedOwnerOrRecipientOrNonce() {
        Fixture fixture = fixture();
        SecureRecoveryGenerationStore.Record recovery =
                new SecureRecoveryGenerationStore.Record(1, UUID.randomUUID());
        byte[] encoded = SecurePreKeyBundleCodec.encodeRecoveryOffer(
                fixture.bundle,
                recovery,
                fixture.identity,
                5555L,
                6666L,
                1700000000L,
                777777L);

        // Signature is 2 bytes length + 64 bytes signature at end (66 bytes total).
        // Preceding 32 bytes are: ownerUserId (8), recipientUserId (8), timestamp (8), nonce (8).
        int signatureBlockLen = 66;
        int metadataStart = encoded.length - signatureBlockLen - 32;

        // Tamper ownerUserId
        assertTamperedRejected(encoded, metadataStart + 7);
        // Tamper recipientUserId
        assertTamperedRejected(encoded, metadataStart + 15);
        // Tamper timestamp
        assertTamperedRejected(encoded, metadataStart + 23);
        // Tamper nonce
        assertTamperedRejected(encoded, metadataStart + 31);
    }

    private static void assertTamperedRejected(byte[] encoded, int index) {
        byte[] tampered = encoded.clone();
        tampered[index] ^= 1;
        try {
            SecurePreKeyBundleCodec.decodeOffer(tampered);
            fail("Expected tampered v3 offer to be rejected");
        } catch (IllegalArgumentException expected) {
            // Expected fail-closed rejection
        }
    }

    private static Fixture fixture() {
        IdentityKeyPair identity = IdentityKeyPair.generate();
        ECKeyPair preKey = ECKeyPair.generate();
        ECKeyPair signedPreKey = ECKeyPair.generate();
        byte[] signedSignature = identity.getPrivateKey()
                .calculateSignature(signedPreKey.getPublicKey().serialize());
        KEMKeyPair kyberPreKey = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
        byte[] kyberSignature = identity.getPrivateKey()
                .calculateSignature(kyberPreKey.getPublicKey().serialize());
        SecurePreKeyBundleCodec.PublicBundle bundle =
                new SecurePreKeyBundleCodec.PublicBundle(
                        1234,
                        1,
                        preKey.getPublicKey().serialize(),
                        2,
                        signedPreKey.getPublicKey().serialize(),
                        signedSignature,
                        identity.getPublicKey().serialize(),
                        3,
                        kyberPreKey.getPublicKey().serialize(),
                        kyberSignature);
        return new Fixture(identity, bundle);
    }

    private static final class Fixture {
        final IdentityKeyPair identity;
        final SecurePreKeyBundleCodec.PublicBundle bundle;

        Fixture(IdentityKeyPair identity, SecurePreKeyBundleCodec.PublicBundle bundle) {
            this.identity = identity;
            this.bundle = bundle;
        }
    }
}
