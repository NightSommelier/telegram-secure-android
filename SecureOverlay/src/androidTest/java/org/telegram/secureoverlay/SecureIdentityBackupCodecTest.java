package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.signal.libsignal.protocol.IdentityKeyPair;

@RunWith(AndroidJUnit4.class)
public final class SecureIdentityBackupCodecTest {
    @Test
    public void deterministicContainerRoundTripsIdentityOnlyPayload() {
        IdentityKeyPair identity = IdentityKeyPair.generate();
        SecureIdentityBackupCodec.Payload payload = new SecureIdentityBackupCodec.Payload(
                UUID.fromString("00112233-4455-6677-8899-aabbccddeeff"),
                123456789L,
                7,
                1_700_000_000L,
                8192,
                identity.serialize());
        char[] password = "correct horse battery staple".toCharArray();
        byte[] salt = sequence(16, 0);
        byte[] nonce = sequence(12, 32);

        byte[] first = SecureIdentityBackupCodec.encrypt(payload, password, salt, nonce);
        byte[] second = SecureIdentityBackupCodec.encrypt(payload, password, salt, nonce);
        assertArrayEquals(first, second);

        SecureIdentityBackupCodec.Payload decoded =
                SecureIdentityBackupCodec.decrypt(first, password);
        assertEquals(payload.archiveId, decoded.archiveId);
        assertEquals(payload.ownerUserId, decoded.ownerUserId);
        assertEquals(payload.generation, decoded.generation);
        assertEquals(payload.exportedAtUnixSeconds, decoded.exportedAtUnixSeconds);
        assertEquals(payload.registrationId, decoded.registrationId);
        assertArrayEquals(payload.serializedIdentity, decoded.serializedIdentity);
        Arrays.fill(password, '\0');
    }

    @Test
    public void kdfMatchesIndependentKnownAnswer() {
        byte[] derived = SecureIdentityBackupCodec.pbkdf2HmacSha256(
                "backup-test".getBytes(StandardCharsets.UTF_8),
                sequence(16, 0),
                600_000);
        assertEquals(
                "6eab1fff298eb6258b0cfb70eb9dc38e019e5867b514edc600a3f323092e55d5",
                hex(derived));
    }

    @Test
    public void wrongPasswordTamperAndResourceChangesFailClosed() {
        SecureIdentityBackupCodec.Payload payload = new SecureIdentityBackupCodec.Payload(
                UUID.randomUUID(),
                42,
                3,
                1_700_000_001L,
                4000,
                IdentityKeyPair.generate().serialize());
        byte[] archive = SecureIdentityBackupCodec.encrypt(
                payload,
                "right-password".toCharArray(),
                sequence(16, 1),
                sequence(12, 21));

        assertSecurityFailure(archive, "wrong-password".toCharArray());

        byte[] tampered = archive.clone();
        tampered[tampered.length - 1] ^= 1;
        assertSecurityFailure(tampered, "right-password".toCharArray());

        byte[] changedKdf = archive.clone();
        changedKdf[13] ^= 1;
        assertMalformed(changedKdf);

        byte[] trailing = Arrays.copyOf(archive, archive.length + 1);
        assertMalformed(trailing);

        byte[] truncated = Arrays.copyOf(archive, archive.length - 1);
        assertMalformed(truncated);
    }

    @Test
    public void plaintextRejectsMissingDuplicateOutOfOrderAndChangedFingerprint() {
        SecureIdentityBackupCodec.Payload payload = new SecureIdentityBackupCodec.Payload(
                UUID.randomUUID(),
                84,
                9,
                1_700_000_002L,
                5000,
                IdentityKeyPair.generate().serialize());
        byte[] plaintext = SecureIdentityBackupCodec.encodePlaintext(payload);
        SecureIdentityBackupCodec.Payload decoded =
                SecureIdentityBackupCodec.decodePlaintext(plaintext);
        assertArrayEquals(payload.serializedIdentity, decoded.serializedIdentity);

        assertPlaintextMalformed(Arrays.copyOf(plaintext, plaintext.length - 1));

        byte[] duplicateFirstTag = plaintext.clone();
        int secondTagOffset = 6 + 1 + 2 + 16;
        duplicateFirstTag[secondTagOffset] = 1;
        assertPlaintextMalformed(duplicateFirstTag);

        byte[] changedFingerprint = plaintext.clone();
        int digestOffset = findFieldValue(changedFingerprint, 7);
        changedFingerprint[digestOffset] ^= 1;
        assertPlaintextMalformed(changedFingerprint);

        byte[] trailingField = Arrays.copyOf(plaintext, plaintext.length + 4);
        trailingField[plaintext.length] = 9;
        trailingField[plaintext.length + 1] = 0;
        trailingField[plaintext.length + 2] = 1;
        trailingField[plaintext.length + 3] = 0;
        assertPlaintextMalformed(trailingField);
    }

    private static int findFieldValue(byte[] plaintext, int wantedTag) {
        int offset = 6;
        while (offset < plaintext.length) {
            int tag = plaintext[offset] & 0xff;
            int length = ((plaintext[offset + 1] & 0xff) << 8)
                    | (plaintext[offset + 2] & 0xff);
            if (tag == wantedTag) {
                return offset + 3;
            }
            offset += 3 + length;
        }
        throw new AssertionError("missing field " + wantedTag);
    }

    private static void assertSecurityFailure(byte[] archive, char[] password) {
        try {
            SecureIdentityBackupCodec.decrypt(archive, password);
            throw new AssertionError("unauthenticated identity backup was accepted");
        } catch (SecurityException expected) {
            // Expected fail-closed authentication.
        }
    }

    private static void assertMalformed(byte[] archive) {
        try {
            SecureIdentityBackupCodec.decrypt(archive, "right-password".toCharArray());
            throw new AssertionError("malformed identity backup was accepted");
        } catch (IllegalArgumentException expected) {
            // Expected pre-KDF structural rejection.
        }
    }

    private static void assertPlaintextMalformed(byte[] plaintext) {
        try {
            SecureIdentityBackupCodec.decodePlaintext(plaintext);
            throw new AssertionError("malformed identity backup plaintext was accepted");
        } catch (IllegalArgumentException expected) {
            // Expected canonical parser rejection.
        }
    }

    private static byte[] sequence(int length, int start) {
        byte[] value = new byte[length];
        for (int i = 0; i < value.length; i++) {
            value[i] = (byte) (start + i);
        }
        return value;
    }

    private static String hex(byte[] value) {
        StringBuilder output = new StringBuilder(value.length * 2);
        for (byte item : value) {
            output.append(String.format("%02x", item));
        }
        return output.toString();
    }
}
