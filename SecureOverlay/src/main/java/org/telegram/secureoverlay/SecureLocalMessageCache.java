package org.telegram.secureoverlay;

import android.content.Context;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Deletes device-local decrypted display and authenticated content copies for a Telegram carrier.
 *
 * <p>The four direction/type records are removed in one SharedPreferences commit. Protocol
 * identity, trust, and ratchet state are intentionally outside this boundary.</p>
 */
public final class SecureLocalMessageCache {
    private final Context context;
    private final int account;
    private final long peerUserId;
    private final KeystoreEncryptedBlobStore blobs;

    public SecureLocalMessageCache(Context context, int account, long peerUserId) {
        if (context == null || account < 0 || peerUserId == 0) {
            throw new IllegalArgumentException(
                    "local secure cache requires an account and user peer");
        }
        this.context = context.getApplicationContext();
        this.account = account;
        this.peerUserId = peerUserId;
        blobs = new KeystoreEncryptedBlobStore(this.context);
    }

    /**
     * Removes all local copies for an encrypted carrier.
     *
     * @return {@code true} when the value was an encrypted carrier and cleanup was applied
     */
    public boolean forget(String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
        if (decoded == null || decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE) {
            return false;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(carrier.getBytes(StandardCharsets.UTF_8));
            return forgetByDigest(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    /**
     * Removes all local copies for a carrier digest (used for remote cryptographic delete).
     *
     * @return {@code true} when cleanup was applied
     */
    public boolean forgetByDigest(byte[] carrierDigest)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        if (carrierDigest == null || carrierDigest.length != 32) {
            return false;
        }
        String hex = hex(carrierDigest);
        String outgoingText = SecureLocalTextStore.OUTGOING_PREFIX + account + '.' + peerUserId + '.' + hex;
        String incomingText = SecureLocalTextStore.INCOMING_PREFIX + account + '.' + peerUserId + '.' + hex;
        String outgoingContent = SecureLocalContentStore.OUTGOING_PREFIX + account + '.' + peerUserId + '.' + hex;
        String incomingContent = SecureLocalContentStore.INCOMING_PREFIX + account + '.' + peerUserId + '.' + hex;
        blobs.deleteAll(
                outgoingText,
                incomingText,
                outgoingContent,
                incomingContent);
        new SecureMediaIndex(context, account, peerUserId)
                .forgetByDigest(carrierDigest);
        SecureLocalTextStore.evictDisplayCopies(outgoingText, incomingText);
        return true;
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(Character.forDigit((item >>> 4) & 0x0f, 16));
            result.append(Character.forDigit(item & 0x0f, 16));
        }
        return result.toString();
    }

    /** Removes all local message copies for this account and peer, but preserves protocol state. */
    public void forgetPeer()
            throws KeystoreEncryptedBlobStore.StateStoreException {
        String outgoingText = scopedPrefix(SecureLocalTextStore.OUTGOING_PREFIX);
        String incomingText = scopedPrefix(SecureLocalTextStore.INCOMING_PREFIX);
        blobs.deletePrefixes(
                outgoingText,
                incomingText,
                scopedPrefix(SecureLocalContentStore.OUTGOING_PREFIX),
                scopedPrefix(SecureLocalContentStore.INCOMING_PREFIX));
        new SecureMediaIndex(context, account, peerUserId)
                .forgetPeer();
        SecureLocalTextStore.evictDisplayPrefixes(outgoingText, incomingText);
    }

    private String scopedPrefix(String recordPrefix) {
        return recordPrefix + account + '.' + peerUserId + '.';
    }
}
