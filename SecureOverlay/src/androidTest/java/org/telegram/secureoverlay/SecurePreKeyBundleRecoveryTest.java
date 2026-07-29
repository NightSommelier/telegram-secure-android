package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.util.UUID;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyType;

@RunWith(AndroidJUnit4.class)
public final class SecurePreKeyBundleRecoveryTest {
    @Test
    public void recoveryOfferRoundTripsAndLegacyBundleRemainsReadable() {
        Fixture fixture = fixture();
        SecureRecoveryGenerationStore.Record recovery =
                new SecureRecoveryGenerationStore.Record(7, UUID.randomUUID());
        byte[] encoded = SecurePreKeyBundleCodec.encodeRecoveryOffer(
                fixture.bundle, recovery, fixture.identity);

        SecurePreKeyBundleCodec.DecodedOffer decoded =
                SecurePreKeyBundleCodec.decodeOffer(encoded);
        assertEquals(recovery, decoded.recovery);
        assertArrayEquals(
                fixture.identity.getPublicKey().serialize(),
                decoded.preKeyBundle.getIdentityKey().serialize());

        SecurePreKeyBundleCodec.DecodedOffer legacy =
                SecurePreKeyBundleCodec.decodeOffer(
                        SecurePreKeyBundleCodec.encode(fixture.bundle));
        assertNull(legacy.recovery);
        assertNotNull(legacy.preKeyBundle);
    }

    @Test
    public void recoverySignatureCoversGenerationRecoveryIdAndBundle() {
        Fixture fixture = fixture();
        byte[] encoded = SecurePreKeyBundleCodec.encodeRecoveryOffer(
                fixture.bundle,
                new SecureRecoveryGenerationStore.Record(9, UUID.randomUUID()),
                fixture.identity);

        assertTampered(encoded, encoded.length - 68);
        assertTampered(encoded, encoded.length - 60);
        assertTampered(encoded, 6);
        assertTampered(encoded, encoded.length - 1);

        byte[] trailing = new byte[encoded.length + 1];
        System.arraycopy(encoded, 0, trailing, 0, encoded.length);
        assertMalformed(trailing);
    }

    @Test
    public void recoveryOfferRejectsMismatchedIdentitySigner() {
        Fixture fixture = fixture();
        try {
            SecurePreKeyBundleCodec.encodeRecoveryOffer(
                    fixture.bundle,
                    new SecureRecoveryGenerationStore.Record(2, UUID.randomUUID()),
                    IdentityKeyPair.generate());
            throw new AssertionError("mismatched recovery signer was accepted");
        } catch (IllegalArgumentException expected) {
            // Expected fail-closed signer binding.
        }
    }

    private static void assertTampered(byte[] encoded, int index) {
        byte[] tampered = encoded.clone();
        tampered[index] ^= 1;
        assertMalformed(tampered);
    }

    private static void assertMalformed(byte[] encoded) {
        try {
            SecurePreKeyBundleCodec.decodeOffer(encoded);
            throw new AssertionError("malformed recovery offer was accepted");
        } catch (IllegalArgumentException expected) {
            // Expected fail-closed parse or signature validation.
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

        Fixture(
                IdentityKeyPair identity,
                SecurePreKeyBundleCodec.PublicBundle bundle) {
            this.identity = identity;
            this.bundle = bundle;
        }
    }
}
